import json
from pathlib import Path

import pytest

from iam_analyzer.account import load_account_file, parse_account
from iam_analyzer.compliance import Result, run, run_check
from iam_analyzer.errors import AccountError, FrameworkError, OrganizationError
from iam_analyzer.findings import scan
from iam_analyzer.framework import load_framework_file, parse_framework
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
    assert admin.note.trust_policy.name == "arn:aws:iam::111122223333:role/Admin"
    assert admin.note.statements == (0,)
    assert sign_in.note.statements == (1,)  # a SAML sign-in assumes the role too
    assert bare.note.trust_policy is None


# --- The second question: can anyone assume the role without MFA? ---------------------

ADMIN = "arn:aws:iam::111122223333:role/Admin"
WRITE = policy(statement("Allow", "s3:PutObject"))
ASSUME_ADMIN = policy(statement("Allow", "sts:AssumeRole", ADMIN))
NO_MFA_TRUST = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "111122223333"},
                               "Action": "sts:AssumeRole"}]}


def admin_item(trust, users=None, roles=None, **fields):
    roles = {"Admin": {"Policies": ["Write"], "AssumeRolePolicyDocument": trust}, **(roles or {})}
    acct = account({"Write": WRITE, "AssumeAdmin": ASSUME_ADMIN}, users=users, roles=roles)
    result = ask(acct, "requires", **{"Actions": ["s3:PutObject"], **fields})
    return result, by_principal(result)["role/Admin"]


def test_a_role_only_mfa_can_assume_passes():
    result, admin = admin_item(ADMIN_TRUST, users={"it": {"Policies": ["AssumeAdmin"]}})
    # The role's own requests never show MFA, so it can write without it...
    assert any(answer.allowed for answer in admin.answers)
    # ...but no one can assume it without MFA, which is where AWS checks MFA for a role.
    assert admin.result is Result.PASS
    question = admin.note.assume
    assert question.check.actions == ("sts:AssumeRole",) and question.check.resources == (ADMIN,)
    assert [(i.principal, i.result) for i in question.items] == [
        ("user/it", Result.PASS), ("role/Admin", Result.PASS)]
    assert [a.values for a in question.items[0].answers] == [((MFA, "false"),), ((MFA, None),)]
    assert result.result is Result.PASS


def test_a_role_someone_can_assume_without_mfa_fails_and_names_them():
    _, admin = admin_item(NO_MFA_TRUST, users={"it": {"Policies": ["AssumeAdmin"]}, "other": {}})
    assert admin.result is Result.FAIL
    failing = [i.principal for i in admin.note.assume.items if i.result is Result.FAIL]
    assert failing == ["user/it"]


def test_someone_outside_who_can_assume_the_role_makes_it_cant_tell():
    vendor = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "444455556666"},
                             "Action": "sts:AssumeRole"}]}
    _, admin = admin_item(vendor)
    assert admin.result is Result.CANT_TELL
    [outside] = admin.note.assume.outside
    assert outside.principals == (Principal(PrincipalType.AWS, "444455556666"),)


def test_a_role_that_saml_users_assume_is_cant_tell():
    # No one can sts:AssumeRole it, but SAML users can, and AWS "cannot determine whether that
    # provider required MFA".
    _, admin = admin_item(SAML_TRUST)
    assert [i.result for i in admin.note.assume.items] == [Result.PASS]
    [outside] = admin.note.assume.outside
    assert outside.action == "sts:AssumeRoleWithSAML"
    assert admin.result is Result.CANT_TELL


def test_a_role_without_a_trust_policy_is_cant_tell():
    acct = account({"Write": WRITE}, roles={"Bare": {"Policies": ["Write"]}})
    [bare] = ask(acct, "requires", Actions=["s3:PutObject"]).items
    assert bare.result is Result.CANT_TELL
    assert bare.note.assume.items[0].answers[0].refusal.kind == "MissingResourceError"


def test_a_role_denied_without_mfa_isnt_asked_again():
    _, admin = admin_item(ADMIN_TRUST, Actions=["s3:DeleteObject"])
    assert admin.result is Result.PASS
    assert not admin.note.asked


def test_the_second_question_goes_one_level_deep():
    # Hop can assume Admin, whose trust policy doesn't check MFA. Hop needs MFA to be assumed
    # itself, but the second question about Admin doesn't ask about Hop's own trust policy.
    hop = {"Policies": ["AssumeAdmin"], "AssumeRolePolicyDocument": ADMIN_TRUST}
    _, admin = admin_item(NO_MFA_TRUST, roles={"Hop": hop})
    hop_item = next(i for i in admin.note.assume.items if i.principal == "role/Hop")
    assert hop_item.result is Result.FAIL and hop_item.note is None
    assert admin.result is Result.FAIL


def test_the_second_question_is_asked_once_per_role():
    acct = account({"Write": WRITE}, roles={"Admin": {"Policies": ["Write"],
                                                     "AssumeRolePolicyDocument": ADMIN_TRUST}})
    first, second = ask(acct, "requires", Actions=["s3:PutObject"],
                        Resources=[OBJECT, f"{BUCKET}/campus-01/x.pdf"]).items
    assert first.note.assume is second.note.assume


def test_following_the_district_fix_passes_the_mfa_check():
    document = json.loads((EXAMPLES / "accounts" / "district.json").read_text())
    acct = parse_account(document, name="district.json")
    org = load_organization_file(EXAMPLES / "organizations" / "district.json")
    framework = load_framework_file(EXAMPLES / "frameworks" / "district.json")
    mfa = next(c for c in framework.checks if c.id == "record-changes-need-mfa")
    assert run_check(mfa, acct, organization=org).result is Result.FAIL  # alee, directly
    document["Users"]["alee"]["Policies"] = []  # the check's Fix
    fixed = run_check(mfa, parse_account(document, name="district.json"), organization=org)
    assert fixed.result is Result.PASS
    admin = by_principal(fixed)["role/ITAdmin"]
    assert admin.result is Result.PASS and admin.note.assume.result is Result.PASS


def test_following_the_anycompany_fixes_passes_every_check_that_forbids_access():
    document = json.loads((EXAMPLES / "accounts" / "anycompany-production.json").read_text())
    org = load_organization_file(EXAMPLES / "organizations" / "anycompany.json")
    framework = load_framework_file(EXAMPLES / "frameworks" / "anycompany.json")
    policies, roles = document["Policies"], document["Roles"]
    logs = ["arn:aws:s3:::anycompany-prod-app-logs", "arn:aws:s3:::anycompany-prod-app-logs/*"]
    uploads = ["arn:aws:s3:::anycompany-prod-support-uploads",
               "arn:aws:s3:::anycompany-prod-support-uploads/*"]
    # Each check's Fix: narrow the wildcards that reach the backups...
    policies["SupportAccess"]["Statement"][0]["Resource"] = logs + uploads
    policies["VendorReadOnly"]["Statement"] = [
        statement("Allow", ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"], "*"),
        statement("Allow", ["s3:GetObject", "s3:ListBucket"], logs)]
    # ...make the MFA Deny apply to requests made with access keys...
    policies["RequireMfaForCustomerData"]["Statement"][0]["Condition"] = {
        "BoolIfExists": {MFA: "false"}}
    # ...and stop the deploy role from assuming the admin role.
    trust = roles["OnCallAdmin"]["AssumeRolePolicyDocument"]
    trust["Statement"] = [s for s in trust["Statement"] if s["Sid"] != "DeployMigrations"]
    # The external-ID finding's fix.
    roles["VendorMonitoring"]["AssumeRolePolicyDocument"]["Statement"][0]["Condition"] = {
        "StringEquals": {"sts:ExternalId": "anycompany-monitoring"}}
    acct = parse_account(document, name="anycompany-production.json")
    results = {r.check.id: r.result for r in run(framework, acct, organization=org)}
    assert results.pop("on-call-can-assume-admin") is Result.DEPENDS  # MFA, by design
    assert set(results.values()) == {Result.PASS}
    assert scan(acct, organization=org) == ()


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
