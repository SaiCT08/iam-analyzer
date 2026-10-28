from pathlib import Path

import pytest

from iam_analyzer.account import load_account_file, parse_account
from iam_analyzer.compliance import Result, run, run_check
from iam_analyzer.errors import AccountError, FrameworkError, OrganizationError
from iam_analyzer.framework import parse_framework
from iam_analyzer.models import Decision, PolicyType, Principal, PrincipalType
from iam_analyzer.organization import load_organization_file, parse_organization

EXAMPLES = Path(__file__).parent.parent / "examples"
BUCKET = "arn:aws:s3:::district-student-records"
OBJECT = f"{BUCKET}/campus-02/transcript.pdf"
MFA = "aws:MultiFactorAuthPresent"


def statement(effect, action, resource=f"{BUCKET}/*", **elements):
    return {"Effect": effect, "Action": action, "Resource": resource, **elements}


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


READ = policy(statement("Allow", "s3:GetObject", Sid="Read"))
WRITE_WITH_MFA = policy(
    statement("Allow", "s3:PutObject", Sid="Write"),
    statement("Deny", "s3:PutObject", Sid="NeedsMfa",
              Condition={"BoolIfExists": {MFA: "false"}}),
)


def account(policies, users=None, roles=None, groups=None, bucket_policy=None):
    bucket = {} if bucket_policy is None else {"Policy": bucket_policy}
    return parse_account({
        "AccountId": "111122223333", "Policies": policies, "Users": users or {},
        "Roles": roles or {}, "Groups": groups or {}, "Resources": {BUCKET: bucket},
    }, name="acct.json")


def check(check_type, **fields):
    names = {"requires": {"Key": MFA, "Value": "true"}}.get(check_type, {"Principals": []})
    raw = {"Id": "c", "Title": "A check", "Severity": "high", "Type": check_type,
           "Actions": ["s3:GetObject"], "Resources": [OBJECT], "Fix": "Fix it.",
           **names, **fields}
    framework = parse_framework({"Framework": {"Id": "f", "Title": "F"}, "Checks": [raw]},
                                name="fw.json")
    return framework.checks[0]


def ask(acct, check_type, organization=None, **fields):
    return run_check(check(check_type, **fields), acct, organization=organization)


def by_principal(result):
    return {item.principal: item for item in result.items}


# --- "only" ----------------------------------------------------------------------------


def test_only_passes_when_everyone_else_is_denied():
    acct = account({"Read": READ}, users={"reader": {"Policies": ["Read"]}, "other": {}})
    result = ask(acct, "only", Principals=["user/reader"])
    assert result.result is Result.PASS
    assert result.not_asked == ("user/reader",)
    assert [item.principal for item in result.items] == ["user/other"]


def test_only_fails_and_keeps_the_statements_that_grant_access():
    acct = account({"Read": READ}, groups={"Teachers": {"Policies": ["Read"]}},
                   users={"teacher": {"Groups": ["Teachers"]}, "other": {}})
    result = ask(acct, "only")
    assert result.result is Result.FAIL
    teacher = by_principal(result)["user/teacher"]
    assert teacher.result is Result.FAIL
    [grant] = teacher.answers[0].result.reasons
    assert (grant.policy_name, grant.statement.sid, grant.via_group, grant.index) == (
        "Read", "Read", "Teachers", 0)
    assert by_principal(result)["user/other"].result is Result.PASS


def test_an_empty_only_asks_every_user_and_role():
    acct = account({}, users={"a": {}}, roles={"r": {}})
    assert [item.principal for item in ask(acct, "only").items] == ["user/a", "role/r"]


def test_a_group_stands_for_its_members():
    acct = account({"Read": READ}, groups={"Teachers": {"Policies": ["Read"]}},
                   users={"teacher": {"Groups": ["Teachers"]}})
    result = ask(acct, "only", Principals=["group/Teachers"])
    assert result.result is Result.PASS
    assert result.not_asked == ("user/teacher",)


@pytest.mark.parametrize("name, message", [
    ("user/ghost", "no user 'ghost' in acct.json"),
    ("role/ghost", "no role 'ghost' in acct.json"),
    ("group/Ghosts", "no group 'Ghosts' in acct.json"),
])
def test_principals_the_account_file_doesnt_define(name, message):
    with pytest.raises(FrameworkError, match=message):
        ask(account({}), "only", Principals=[name])


# --- Trying the values AWS documents ---------------------------------------------------


def test_a_can_check_depends_on_a_key_aws_documents():
    acct = account({"Write": WRITE_WITH_MFA}, users={"registrar": {"Policies": ["Write"]}})
    result = ask(acct, "can", Principals=["user/registrar"], Actions=["s3:PutObject"])
    assert result.result is Result.DEPENDS
    [item] = result.items
    assert item.turns_on == (MFA,)
    assert [(a.values, a.allowed) for a in item.answers] == [
        (((MFA, "true"),), True), (((MFA, "false"),), False), (((MFA, None),), False)]


def test_a_prohibition_fails_when_any_value_allows_it():
    # A plain Bool Deny skips requests made with access keys, which carry no MFA key at all.
    skips_access_keys = policy(
        statement("Allow", "s3:PutObject"),
        statement("Deny", "s3:PutObject", Condition={"Bool": {MFA: "false"}}),
    )
    acct = account({"Write": skips_access_keys}, users={"registrar": {"Policies": ["Write"]}})
    result = ask(acct, "requires", Actions=["s3:PutObject"])
    [item] = result.items
    assert result.result is item.result is Result.FAIL
    assert [(a.values, a.allowed) for a in item.answers] == [
        (((MFA, "false"),), False), (((MFA, None),), True)]
    assert item.turns_on == (MFA,)


def test_requires_passes_when_every_other_value_is_denied():
    acct = account({"Write": WRITE_WITH_MFA}, users={"registrar": {"Policies": ["Write"]}})
    result = ask(acct, "requires", Actions=["s3:PutObject"])
    assert result.result is Result.PASS
    assert [a.values for a in result.items[0].answers] == [((MFA, "false"),), ((MFA, None),)]


def test_keys_are_tried_together():
    both = policy(statement("Allow", "s3:GetObject", Condition={
        "Bool": {MFA: "true", "aws:SecureTransport": "true"}}))
    acct = account({"Both": both}, users={"u": {"Policies": ["Both"]}})
    [item] = ask(acct, "can", Principals=["user/u"]).items
    assert item.result is Result.DEPENDS
    assert len(item.answers) == 6  # MFA's 3 values times TLS's 2
    assert set(item.turns_on) == {MFA, "aws:SecureTransport"}


def test_a_key_aws_doesnt_list_every_value_of_is_cant_tell():
    from_office = policy(statement("Allow", "s3:GetObject",
                                   Condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}))
    acct = account({"Office": from_office}, users={"u": {"Policies": ["Office"]}})
    result = ask(acct, "only")
    [item] = result.items
    assert result.result is item.result is Result.CANT_TELL
    refusal = item.answers[0].refusal
    assert (refusal.kind, refusal.keys) == ("MissingContextError", ("aws:SourceIp",))
    assert "aws:SourceIp, used by Office statement 0" in refusal.message
    # Once the check gives the key, the engine answers.
    answered = ask(acct, "only", Context={"aws:SourceIp": "203.0.113.5"})
    assert answered.result is Result.FAIL


def test_a_key_the_account_file_fills_in_cant_be_given():
    acct = account({}, users={"u": {}})
    with pytest.raises(FrameworkError, match="'aws:username' comes from acct.json user/u"):
        ask(acct, "only", Context={"aws:username": "someone"})


# --- Refusals --------------------------------------------------------------------------

LESSONS = "arn:aws:s3:::district-lesson-plans/week1.pdf"  # not described in the account


def test_an_undescribed_resource_is_cant_tell():
    acct = account({"Read": READ}, users={"u": {"Policies": ["Read"]}})
    result = ask(acct, "only", Resources=[LESSONS])
    refusal = result.items[0].answers[0].refusal
    assert result.result is Result.CANT_TELL
    assert (refusal.kind, refusal.resource) == (
        "MissingResourceError", "arn:aws:s3:::district-lesson-plans")


def test_a_request_the_analyzer_cant_evaluate_is_cant_tell():
    key = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    result = ask(account({}, users={"u": {}}), "only", Actions=["kms:Decrypt"], Resources=[key])
    assert result.result is Result.CANT_TELL
    assert result.items[0].answers[0].refusal.kind == "UnsupportedPolicyFeature"


def test_a_prohibition_with_refusals_and_no_allow_is_cant_tell_not_pass():
    acct = account({}, users={"u": {}})
    result = ask(acct, "only", Resources=[OBJECT, LESSONS])
    assert [item.result for item in result.items] == [Result.PASS, Result.CANT_TELL]
    assert result.result is Result.CANT_TELL


def test_a_fail_outranks_a_cant_tell():
    acct = account({"Read": READ}, users={"reader": {"Policies": ["Read"]}})
    result = ask(acct, "only", Resources=[OBJECT, LESSONS])
    assert [item.result for item in result.items] == [Result.FAIL, Result.CANT_TELL]
    assert result.result is Result.FAIL


def test_a_depends_outranks_a_cant_tell():
    acct = account({"Write": WRITE_WITH_MFA}, users={"registrar": {"Policies": ["Write"]}})
    result = ask(acct, "can", Principals=["user/registrar"], Actions=["s3:PutObject"],
                 Resources=[OBJECT, LESSONS])
    assert [item.result for item in result.items] == [Result.DEPENDS, Result.CANT_TELL]
    assert result.result is Result.DEPENDS


def test_a_check_with_no_one_to_ask_passes():
    acct = account({"Read": READ}, users={"reader": {"Policies": ["Read"]}})
    result = ask(acct, "only", Principals=["user/reader"])
    assert (result.items, result.result) == ((), Result.PASS)


def test_can_fails_with_why_it_was_denied():
    result = ask(account({}, users={"u": {}}), "can", Principals=["user/u"])
    assert result.result is Result.FAIL
    assert result.items[0].answers[0].result.decision is Decision.IMPLICIT_DENY


# --- Principals outside the account file -----------------------------------------------


def test_a_grant_to_everyone_fails_and_is_cited_for_outsiders():
    public = {"Statement": [{"Sid": "Public", "Effect": "Allow", "Principal": "*",
                             "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"}]}
    result = ask(account({}, users={"u": {}}, bucket_policy=public), "only")
    assert result.result is Result.FAIL  # the file's own principals can read it too
    [outside] = result.outside
    assert outside.policy.statements[outside.index].sid == "Public"
    assert outside.layer.policy_type is PolicyType.RESOURCE_BASED
    assert outside.principals == (Principal(PrincipalType.AWS, "*"),)


def test_a_grant_to_another_account_is_cant_tell():
    vendor = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "444455556666"},
                             "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"}]}
    result = ask(account({}, users={"u": {}}, bucket_policy=vendor), "only")
    assert [item.result for item in result.items] == [Result.PASS]
    assert result.result is Result.CANT_TELL
    assert result.outside[0].principals == (Principal(PrincipalType.AWS, "444455556666"),)


def test_grants_to_the_files_own_principals_are_asked_not_cited():
    own = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{BUCKET}/*",
                          "Principal": {"AWS": ["arn:aws:iam::111122223333:user/u",
                                                "arn:aws:iam::111122223333:root"]}}]}
    result = ask(account({}, users={"u": {}}, bucket_policy=own), "only")
    assert result.outside == ()
    assert result.result is Result.FAIL


def test_outsiders_only_count_for_the_checks_requests():
    public = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:ListBucket",
                             "Resource": BUCKET}]}
    result = ask(account({}, users={"u": {}}, bucket_policy=public), "only")
    assert result.outside == ()
    assert result.result is Result.PASS


# --- Roles in a check that requires MFA ------------------------------------------------

ADMIN_TRUST = {"Statement": [{"Sid": "AccountWithMfa", "Effect": "Allow",
                              "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                              "Action": "sts:AssumeRole",
                              "Condition": {"Bool": {MFA: "true"}}}]}


SAML_TRUST = {"Statement": [
    {"Effect": "Deny", "Principal": "*", "Action": "sts:TagSession"},
    {"Sid": "SignIn", "Effect": "Allow", "Action": "sts:AssumeRoleWithSAML",
     "Principal": {"Federated": "arn:aws:iam::111122223333:saml-provider/DistrictIdP"}},
]}


def test_a_roles_item_points_to_its_trust_policy():
    acct = account({"Write": policy(statement("Allow", "s3:PutObject"))},
                   roles={"Admin": {"Policies": ["Write"], "AssumeRolePolicyDocument": ADMIN_TRUST},
                          "SignIn": {"AssumeRolePolicyDocument": SAML_TRUST},
                          "Bare": {"Policies": ["Write"]}})
    result = ask(acct, "requires", Actions=["s3:PutObject"])
    admin, sign_in, bare = result.items
    assert admin.result is Result.FAIL  # the note explains it, and doesn't change it
    assert admin.note.trust_policy.name == "arn:aws:iam::111122223333:role/Admin"
    assert admin.note.statements == (0,)
    assert sign_in.note.statements == (1,)  # a SAML sign-in assumes the role too
    assert bare.note.trust_policy is None


def test_only_mfa_checks_have_the_note():
    acct = account({}, roles={"Admin": {"AssumeRolePolicyDocument": ADMIN_TRUST}})
    assert ask(acct, "only").items[0].note is None
    tls = ask(acct, "requires", Key="aws:SecureTransport", Value="true")
    assert tls.items[0].note is None


# --- The organization ------------------------------------------------------------------


def test_scps_apply_when_the_organization_is_given():
    acct = load_account_file(EXAMPLES / "accounts" / "district.json")
    org = load_organization_file(EXAMPLES / "organizations" / "district.json")
    fields = {"Actions": ["ec2:DescribeInstances"], "Resources": ["*"]}
    assert ask(acct, "only", **fields).result is Result.FAIL  # IT staff may describe instances
    assert ask(acct, "only", organization=org, **fields).result is Result.PASS  # no SCP allows it


def framework(*checks):
    return parse_framework({"Framework": {"Id": "f", "Title": "F"},
                            "Checks": [{"Id": f"c{i}", "Title": "A check", "Severity": "low",
                                        "Type": "only", "Principals": [],
                                        "Actions": ["s3:GetObject"], "Resources": [OBJECT],
                                        "Fix": "Fix it."} for i in range(checks[0])]},
                           name="fw.json")


def test_run_checks_the_account_is_in_the_organization():
    org = parse_organization({
        "ManagementAccountId": "999988887777",
        "ServiceControlPolicies": {"All": {"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
        "Root": {"ServiceControlPolicies": ["All"], "Accounts": {
            "999988887777": {"ServiceControlPolicies": ["All"]}}},
    }, name="org.json")
    with pytest.raises(OrganizationError, match="no account '111122223333'"):
        run(framework(1), account({}), organization=org)
    no_id = parse_account({"Policies": {}}, name="acct.json")
    with pytest.raises(AccountError, match="needs an 'AccountId'"):
        run(framework(1), no_id, organization=org)


def test_run_runs_every_check():
    assert len(run(framework(2), account({}), organization=None)) == 2
