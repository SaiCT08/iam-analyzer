import json
from pathlib import Path

import pytest

from iam_analyzer.account import load_account_file, parse_account
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import (
    AccountError,
    PolicyParseError,
    RequestError,
    UnsupportedPolicyFeature,
)
from iam_analyzer.models import Decision, PolicyType, Principal, PrincipalType, Resource
from iam_analyzer.organization import load_organization_file

EXAMPLE = Path(__file__).parent.parent / "examples" / "accounts" / "district.json"


def policy_doc(sid):
    statement = {"Sid": sid, "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    return {"Statement": [statement]}


def account(**sections):
    document = {"Policies": {"Read": policy_doc("R"), "Write": policy_doc("W")}, **sections}
    return parse_account(document, name="acct.json")


def summary(policies):
    return [(p.name, p.via_group) for p in policies]


def test_direct_policies_have_no_via_group():
    acct = account(Users={"jsmith": {"Policies": ["Read"]}})
    assert summary(acct.policies_for("user/jsmith")) == [("Read", None)]


def test_group_policies_are_inherited_with_via_group_and_original_name():
    acct = account(
        Groups={"Teachers": {"Policies": ["Read"]}}, Users={"jsmith": {"Groups": ["Teachers"]}}
    )
    [policy] = acct.policies_for("user/jsmith")
    assert policy.name == "Read"
    assert policy.via_group == "Teachers"
    # The shared definition is not modified.
    assert acct.policies["Read"].via_group is None


def test_direct_and_group_policies_are_combined():
    acct = account(
        Groups={"A": {"Policies": ["Read"]}, "B": {"Policies": ["Read", "Write"]}},
        Users={"jsmith": {"Policies": ["Write"], "Groups": ["A", "B"]}},
    )
    assert summary(acct.policies_for("user/jsmith")) == [
        ("Write", None),
        ("Read", "A"),
        ("Read", "B"),
        ("Write", "B"),
    ]


def test_role_lookup():
    acct = account(Roles={"ITAdmin": {"Policies": ["Read", "Write"]}})
    assert summary(acct.policies_for("role/ITAdmin")) == [("Read", None), ("Write", None)]


def test_users_and_roles_are_separate_namespaces():
    acct = account(
        Users={"admin": {"Policies": ["Read"]}}, Roles={"admin": {"Policies": ["Write"]}}
    )
    assert summary(acct.policies_for("user/admin")) == [("Read", None)]
    assert summary(acct.policies_for("role/admin")) == [("Write", None)]


def test_role_path_defaults_to_root():
    acct = account(Roles={"ITAdmin": {}})
    assert acct.roles["ITAdmin"].path == "/"
    assert not acct.is_service_linked("role/ITAdmin")


def test_service_linked_roles_are_marked_by_their_path():
    acct = account(
        Roles={
            "AWSServiceRoleForSupport": {"Path": "/aws-service-role/support.amazonaws.com/"},
            "CampusApp": {"Path": "/district/"},
            # The name alone doesn't make a role service-linked.
            "AWSServiceRoleForLookalike": {},
        },
        Users={"jsmith": {}},
    )
    assert acct.roles["AWSServiceRoleForSupport"].path == "/aws-service-role/support.amazonaws.com/"
    assert acct.is_service_linked("role/AWSServiceRoleForSupport")
    assert not acct.is_service_linked("role/CampusApp")
    assert not acct.is_service_linked("role/AWSServiceRoleForLookalike")
    assert not acct.is_service_linked("user/jsmith")


def test_principal_with_no_policies():
    acct = account(Users={"newhire": {}})
    assert acct.policies_for("user/newhire") == []


@pytest.mark.parametrize(
    "principal, message",
    [
        ("user/nobody", "no user named 'nobody'"),
        ("role/jsmith", "no role named 'jsmith'"),
        ("jsmith", "must be 'user/NAME' or 'role/NAME'"),
        ("group/Teachers", "must be 'user/NAME' or 'role/NAME'"),
        ("user/", "must be 'user/NAME' or 'role/NAME'"),
    ],
)
def test_unknown_principal(principal, message):
    acct = account(Users={"jsmith": {}})
    with pytest.raises(AccountError, match=message):
        acct.policies_for(principal)


@pytest.mark.parametrize(
    "document, message",
    [
        ([], "must be a JSON object"),
        ({}, "no 'Policies'"),
        ({"Policies": {}, "Accounts": {}}, "unknown key"),
        ({"Policies": []}, "'Policies' must be a JSON object"),
        ({"Policies": {}, "Users": {"u": []}}, "user 'u': must be a JSON object"),
        ({"Policies": {}, "Users": {"u": {"Roles": []}}}, "user 'u': unknown key"),
        ({"Policies": {}, "Roles": {"r": {"Groups": []}}}, "role 'r': unknown key"),
        ({"Policies": {}, "Users": {"u": {"Policies": "Read"}}}, "must be a list of names"),
        ({"Policies": {}, "Users": {"u": {"Policies": ["Missing"]}}}, "unknown policy 'Missing'"),
        ({"Policies": {}, "Users": {"u": {"Groups": ["Missing"]}}}, "unknown group 'Missing'"),
        ({"Policies": {}, "Groups": {"g": {"Policies": ["Missing"]}}}, "unknown policy 'Missing'"),
        (
            {"Policies": {}, "Users": {"u": {"PermissionsBoundary": ["B"]}}},
            "'PermissionsBoundary' must be a policy name",
        ),
        (
            {"Policies": {}, "Roles": {"r": {"PermissionsBoundary": "Missing"}}},
            "role 'r': unknown policy 'Missing'",
        ),
        ({"Policies": {}, "Groups": {"g": {"PermissionsBoundary": "B"}}}, "group 'g': unknown key"),
        ({"Policies": {}, "AccountId": 111122223333}, "111122223333 is not an AWS account ID"),
        ({"Policies": {}, "AccountId": "1111-2222-3333"}, "is not an AWS account ID"),
        ({"Policies": {}, "Roles": {"r": {"Path": 1}}}, "role 'r': 'Path' must be a string"),
        (
            {"Policies": {}, "Roles": {"r": {"Path": "aws-service-role/"}}},
            "'Path' must be a string that starts and ends with '/'",
        ),
        (
            {"Policies": {}, "Roles": {"r": {"Path": "/district"}}},
            "'Path' must be a string that starts and ends with '/'",
        ),
        (
            {"Policies": {}, "Users": {"u": {"Path": "teachers/"}}},
            "user 'u': 'Path' must be a string that starts and ends with '/'",
        ),
        # Tags, with IAM's rules for users and roles.
        ({"Policies": {}, "Users": {"u": {"Tags": {"campus": "x"}}}}, "'Tags' must be a list"),
        ({"Policies": {}, "Users": {"u": {"Tags": ["campus"]}}}, "user 'u' tag 0: must be a JSON"),
        (
            {"Policies": {}, "Users": {"u": {"Tags": [{"Key": "k", "Value": "v", "Note": 1}]}}},
            "user 'u' tag 0: unknown key",
        ),
        ({"Policies": {}, "Users": {"u": {"Tags": [{"Key": "campus"}]}}}, "'Value' must be"),
        ({"Policies": {}, "Users": {"u": {"Tags": [{"Key": "", "Value": "x"}]}}}, "'Key' must be"),
        (
            {"Policies": {}, "Users": {"u": {"Tags": [{"Key": "campus*", "Value": "x"}]}}},
            "'Key' must be a string of 1 to 128 letters, numbers, spaces",
        ),
        ({"Policies": {}, "Users": {"u": {"Tags": [{"Key": "k", "Value": "x?"}]}}}, "'Value' must"),
        (
            {"Policies": {}, "Users": {"u": {"Tags": [{"Key": "k", "Value": "x" * 257}]}}},
            "'Value' must be a string of 0 to 256",
        ),
        (
            {"Policies": {}, "Users": {"u": {"Tags": [{"Key": "AWS:campus", "Value": "x"}]}}},
            "'Key' can't start with 'aws:'",
        ),
        (
            {"Policies": {}, "Roles": {"r": {"Tags": [
                {"Key": "Campus", "Value": "a"}, {"Key": "campus", "Value": "b"}]}}},
            "role 'r' tag 1: tag key 'campus' is used more than once",
        ),
        ({"Policies": {}, "Groups": {"g": {"Tags": []}}}, "group 'g': unknown key"),
    ],
)
def test_invalid_accounts(document, message):
    with pytest.raises(AccountError, match=message):
        parse_account(document, name="acct.json")


def test_invalid_policy_inside_account_uses_policy_name():
    with pytest.raises(PolicyParseError, match="Broken statement 0"):
        parse_account({"Policies": {"Broken": {"Statement": [{"Effect": "Allow"}]}}}, name="a")


def test_load_account_file(tmp_path):
    path = tmp_path / "acct.json"
    document = {"Policies": {"Read": policy_doc("R")}, "Roles": {"r": {"Policies": ["Read"]}}}
    path.write_text(json.dumps(document))
    acct = load_account_file(path)
    assert acct.name == "acct.json"
    assert summary(acct.policies_for("role/r")) == [("Read", None)]


def test_load_account_file_errors(tmp_path):
    with pytest.raises(AccountError, match="cannot read file"):
        load_account_file(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(AccountError, match="invalid JSON"):
        load_account_file(bad)


def test_user_listed_twice_is_rejected(tmp_path):
    # json.loads would keep only the second "jsmith" and silently drop their boundary.
    path = tmp_path / "acct.json"
    path.write_text(
        '{"Policies": {"Read": %s},'
        ' "Users": {"jsmith": {"PermissionsBoundary": "Read"}, "jsmith": {}}}'
        % json.dumps(policy_doc("R"))
    )
    with pytest.raises(AccountError, match="acct.json: duplicate key 'jsmith'"):
        load_account_file(path)


def test_example_account_loads():
    acct = load_account_file(EXAMPLE)
    assert summary(acct.policies_for("user/jsmith")) == [
        ("TeacherReadGrades", "Teachers"),
        ("DenyStudentRecordsDelete", "Teachers"),
    ]


# --- Permissions boundaries ------------------------------------------------------------


def test_boundary_for_user_and_role():
    acct = account(
        Users={"jsmith": {"Policies": ["Read"], "PermissionsBoundary": "Write"}},
        Roles={"Vendor": {"PermissionsBoundary": "Read"}},
    )
    assert acct.boundary_for("user/jsmith").name == "Write"
    assert acct.boundary_for("role/Vendor").name == "Read"


def test_boundary_is_not_an_identity_policy():
    acct = account(Users={"jsmith": {"Policies": ["Read"], "PermissionsBoundary": "Write"}})
    assert summary(acct.policies_for("user/jsmith")) == [("Read", None)]


def test_principal_without_boundary():
    acct = account(Users={"jsmith": {"Policies": ["Read"]}}, Roles={"r": {}})
    assert acct.boundary_for("user/jsmith") is None
    assert acct.boundary_for("role/r") is None


def test_boundary_for_unknown_principal():
    acct = account(Users={"jsmith": {}})
    with pytest.raises(AccountError, match="no user named 'nobody'"):
        acct.boundary_for("user/nobody")
    with pytest.raises(AccountError, match="must be 'user/NAME' or 'role/NAME'"):
        acct.boundary_for("group/Teachers")


def test_example_account_boundaries():
    acct = load_account_file(EXAMPLE)
    assert acct.boundary_for("user/dpatel").name == "StudentTeacherBoundary"
    assert acct.boundary_for("role/GradebookVendor").name == "GradebookVendorBoundary"
    assert acct.boundary_for("user/jsmith") is None


# --- Account ID ------------------------------------------------------------------------


def test_account_id_is_optional():
    assert account().account_id is None
    # A string keeps the leading zero that some account IDs have.
    assert account(AccountId="012345678901").account_id == "012345678901"


def test_example_account_has_an_id():
    assert load_account_file(EXAMPLE).account_id == "111122223333"


# --- Tags, user paths and the principal's request context ------------------------------


def test_tags_are_read_in_aws_shape():
    acct = account(
        Users={"jsmith": {"Tags": [{"Key": "campus", "Value": "campus-01"},
                                   {"Key": "phone", "Value": ""}]}},
        Roles={"Vendor": {"Tags": [{"Key": "vendor", "Value": "gradebook"}]}},
    )
    assert acct.users["jsmith"].tags == (("campus", "campus-01"), ("phone", ""))
    assert acct.roles["Vendor"].tags == (("vendor", "gradebook"),)


def test_user_path_defaults_to_root():
    acct = account(Users={"jsmith": {}, "dpatel": {"Path": "/student-teachers/"}})
    assert acct.users["jsmith"].path == "/"
    assert acct.users["dpatel"].path == "/student-teachers/"


def test_principal_context_for_a_user():
    acct = account(
        AccountId="111122223333",
        Users={"jsmith": {"Path": "/teachers/", "Tags": [{"Key": "campus", "Value": "campus-01"}]}},
    )
    context = acct.principal_context("user/jsmith")
    assert context.get("aws:username") == ("jsmith",)
    assert context.get("aws:PrincipalType") == ("User",)
    assert context.get("aws:PrincipalArn") == ("arn:aws:iam::111122223333:user/teachers/jsmith",)
    assert context.get("aws:PrincipalAccount") == ("111122223333",)
    assert context.get("aws:PrincipalTag/Campus") == ("campus-01",)
    # The file lists all of a user's tags, so any other tag is absent.
    assert context.get("aws:PrincipalTag/grade") is None
    # The file has no unique IDs, and AWS doesn't document aws:PrincipalIsAWSService for users.
    assert not context.knows("aws:userid")
    assert not context.knows("aws:PrincipalIsAWSService")


def test_principal_context_for_a_role():
    acct = account(
        AccountId="111122223333",
        Roles={"Vendor": {"Path": "/vendors/", "Tags": [{"Key": "vendor", "Value": "gradebook"}]}},
    )
    context = acct.principal_context("role/Vendor")
    assert context.get("aws:username") is None  # roles have no user name
    assert context.get("aws:PrincipalType") == ("AssumedRole",)
    # The role's own ARN, not the session's.
    assert context.get("aws:PrincipalArn") == ("arn:aws:iam::111122223333:role/vendors/Vendor",)
    # Session tags can override the role's tags and add new ones, so no tag is known.
    assert not context.knows("aws:PrincipalTag/vendor")
    assert not context.knows("aws:PrincipalTag/grade")


def test_a_role_without_session_tags_has_only_its_own_tags():
    acct = account(Roles={"Vendor": {"Tags": [{"Key": "vendor", "Value": "gradebook"}]}})
    context = acct.principal_context("role/Vendor", session_tags=False)
    assert context.get("aws:PrincipalTag/vendor") == ("gradebook",)
    assert context.get("aws:PrincipalTag/grade") is None


def test_a_session_tag_cannot_remove_a_roles_tag():
    acct = account(Roles={"Vendor": {"Tags": [{"Key": "campus", "Value": "campus-01"}]}})
    context = acct.principal_context("role/Vendor")
    message = "session tags can override a role's tags but not remove them"
    with pytest.raises(RequestError, match=message):
        context.merged(RequestContext.of(absent=["aws:principaltag/CAMPUS"]))
    # A tag the role doesn't have can be missing from the session.
    merged = context.merged(RequestContext.of(absent=["aws:PrincipalTag/grade"]))
    assert merged.get("aws:PrincipalTag/grade") is None


def test_principal_arn_needs_an_account_id():
    context = account(Users={"jsmith": {}}).principal_context("user/jsmith")
    assert not context.knows("aws:PrincipalArn")
    assert not context.knows("aws:PrincipalAccount")


def test_principal_context_for_an_unknown_principal():
    with pytest.raises(AccountError, match="no user named 'nobody'"):
        account(Users={"jsmith": {}}).principal_context("user/nobody")


# --- Resources -------------------------------------------------------------------------

RECORDS = "arn:aws:s3:::district-student-records"
ALERTS = "arn:aws:sqs:us-east-1:111122223333:district-alerts"
READ_STATEMENT = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{RECORDS}/*"}
BUCKET_POLICY = {"Statement": [{**READ_STATEMENT, "Principal": "*"}]}


def test_resources_describe_buckets_and_other_resources():
    acct = account(AccountId="111122223333", Resources={RECORDS: {}, ALERTS: {}})
    assert acct.resources == {RECORDS: Resource(RECORDS), ALERTS: Resource(ALERTS)}
    # A bucket is described for its objects.
    assert acct.resource_for(f"{RECORDS}/2026/roster.csv", "s3:GetObject") == Resource(RECORDS)
    assert acct.resource_for(ALERTS, "sqs:SendMessage") == Resource(ALERTS)


def test_resource_for_is_none_when_nothing_is_described_or_needed():
    acct = account(Resources={RECORDS: {}})
    assert acct.resource_for("arn:aws:s3:::district-lesson-plans/week1.pdf", "s3:GetObject") is None
    assert acct.resource_for("arn:aws:iam::111122223333:user/jsmith", "iam:GetUser") is None
    assert acct.resource_for("*", "s3:ListAllMyBuckets") is None


def test_example_account_describes_its_buckets():
    assert set(load_account_file(EXAMPLE).resources) == {
        RECORDS,
        "arn:aws:s3:::district-staff-files",
        "arn:aws:s3:::district-gradebook-app",
    }


@pytest.mark.parametrize(
    "described, error, message",
    [
        ([], AccountError, "'Resources' must be a JSON object"),
        ({RECORDS: []}, AccountError, f"resource '{RECORDS}': must be a JSON object"),
        ({RECORDS: {"Tags": []}}, AccountError, "unknown key"),
        ({"district-student-records": {}}, AccountError, "must be the full ARN of one resource"),
        ({"arn:aws:s3:::district-*": {}}, AccountError, "must be the full ARN of one resource"),
        ({"arn:aws:iam::111122223333:role/ITAdmin": {}}, AccountError, "IAM and STS resources"),
        ({"arn:aws:sts::111122223333:federated-user/bob": {}}, AccountError, "IAM and STS"),
        ({f"{RECORDS}/2026/roster.csv": {}}, AccountError, "describe the bucket, not an object"),
        (
            {"arn:aws:kms:us-east-1:111122223333:key/1234abcd": {}},
            UnsupportedPolicyFeature,
            "KMS isn't supported yet",
        ),
        (
            {"arn:aws:s3:us-east-1:111122223333:accesspoint/records": {}},
            UnsupportedPolicyFeature,
            "such as access points",
        ),
        (
            {"arn:aws:sqs:us-east-1:444455556666:alerts": {}},
            AccountError,
            "is in account 444455556666, not this file's account 111122223333; cross-account",
        ),
        ({"arn:aws:sqs:us-east-1:aws:alerts": {}}, AccountError, "empty or a 12-digit account ID"),
        (
            {ALERTS: {"Policy": BUCKET_POLICY}},
            UnsupportedPolicyFeature,
            f"resource '{ALERTS}': only S3 bucket policies and role trust policies",
        ),
        (
            {RECORDS: {"Policy": {"Statement": [{**READ_STATEMENT}]}}},
            PolicyParseError,
            f"{RECORDS} statement 0: a resource-based policy's statement needs a 'Principal'",
        ),
        (
            {RECORDS: {"Policy": {"Statement": [
                {**READ_STATEMENT, "Principal": "*", "Resource": "arn:aws:s3"}]}}},
            UnsupportedPolicyFeature,
            f"{RECORDS} statement 0: 'Resource' entry 'arn:aws:s3' has fewer than six fields",
        ),
    ],
)
def test_invalid_resources(described, error, message):
    with pytest.raises(error, match=message):
        account(AccountId="111122223333", Resources=described)


def test_a_resource_that_names_an_account_needs_the_files_account_id():
    with pytest.raises(AccountError, match="names account 111122223333, so the account file needs"):
        account(Resources={ALERTS: {}})


def test_a_bucket_policy_is_read_as_a_resource_based_policy():
    acct = account(AccountId="111122223333", Resources={RECORDS: {"Policy": BUCKET_POLICY}})
    bucket_policy = acct.resources[RECORDS].policy
    assert bucket_policy.name == RECORDS
    assert bucket_policy.statements[0].principals == (Principal(PrincipalType.AWS, "*"),)


def test_a_bucket_policy_needs_the_files_account_id():
    with pytest.raises(AccountError, match="needs an 'AccountId' to know which ARNs"):
        account(Resources={RECORDS: {"Policy": BUCKET_POLICY}})


def test_example_account_has_a_bucket_policy_on_student_records():
    bucket_policy = load_account_file(EXAMPLE).resources[RECORDS].policy
    assert [s.sid for s in bucket_policy.statements] == [
        "OnlyITAdminChangesThePolicy",
        "CounselorsReadCounselingNotes",
    ]


# --- Trust policies --------------------------------------------------------------------

ADMIN_ARN = "arn:aws:iam::111122223333:role/district/ITAdmin"
TRUST_ACCOUNT = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "111122223333"},
                                "Action": "sts:AssumeRole"}]}
TRUST_SAML = {"Statement": [{
    "Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::111122223333:saml-provider/IdP"},
    "Action": "sts:AssumeRoleWithSAML"}]}


def with_role(trust=TRUST_ACCOUNT, **role):
    return account(AccountId="111122223333", Roles={"ITAdmin": {
        "Path": "/district/", "AssumeRolePolicyDocument": trust, **role}})


def test_a_roles_trust_policy_is_named_after_the_role():
    trust_policy = with_role().roles["ITAdmin"].trust_policy
    assert trust_policy.name == ADMIN_ARN
    assert trust_policy.statements[0].resources == ()


def test_a_trust_policy_needs_the_files_account_id():
    message = "role 'ITAdmin': a trust policy names principals by ARN"
    with pytest.raises(AccountError, match=message):
        account(Roles={"ITAdmin": {"AssumeRolePolicyDocument": TRUST_ACCOUNT}})


def test_resource_for_finds_a_role_and_its_trust_policy():
    acct = with_role()
    found = acct.resource_for(ADMIN_ARN, "sts:AssumeRole")
    assert found == Resource(ADMIN_ARN, acct.roles["ITAdmin"].trust_policy)
    # The trust policy only covers the STS actions on the role.
    assert acct.resource_for(ADMIN_ARN, "iam:GetRole") is None


def test_resource_for_a_role_the_file_cant_describe():
    acct = account(AccountId="111122223333", Roles={"Helper": {}})
    # No trust policy in the file: the evaluator says it needs one.
    assert acct.resource_for("arn:aws:iam::111122223333:role/Helper", "sts:AssumeRole") is None
    # Another account's role: the evaluator refuses it as cross-account.
    assert acct.resource_for("arn:aws:iam::444455556666:role/Helper", "sts:AssumeRole") is None


@pytest.mark.parametrize(
    "arn, error, message",
    [
        ("arn:aws:iam::111122223333:role/district/Nobody", AccountError, "no role named 'Nobody'"),
        (
            "arn:aws:iam::111122223333:role/ITAdmin",
            AccountError,
            "role 'ITAdmin' has the path '/district/', not '/'",
        ),
        (
            "arn:aws:iam::111122223333:role/district/itadmin",
            UnsupportedPolicyFeature,
            "IAM role names ignore case, and AWS doesn't say whether a role ARN does too",
        ),
    ],
)
def test_role_arns_that_dont_name_a_role_in_the_file(arn, error, message):
    with pytest.raises(error, match=message):
        with_role().resource_for(arn, "sts:AssumeRole")


@pytest.mark.parametrize(
    "trust, complete",
    [
        # Only identity providers can assume the role, and sts:TagSession isn't allowed.
        (TRUST_SAML, True),
        # A role session in the account could chain in with transitive session tags.
        (TRUST_ACCOUNT, False),
    ],
)
def test_a_trust_policy_can_rule_out_session_tags(trust, complete):
    acct = with_role(trust, Tags=[{"Key": "campus", "Value": "campus-01"}])
    context = acct.principal_context("role/ITAdmin")
    assert context.knows("aws:PrincipalTag/campus") is complete
    assert context.knows("aws:PrincipalTag/grade") is complete
    # Saying the session has no session tags still works either way.
    assert acct.principal_context("role/ITAdmin", session_tags=False).get(
        "aws:PrincipalTag/campus"
    ) == ("campus-01",)


def test_example_teacher_sign_in_role_has_only_its_own_tags():
    context = load_account_file(EXAMPLE).principal_context("role/TeacherSignIn")
    assert context.get("aws:PrincipalTag/campus") == ("campus-01",)
    assert context.get("aws:PrincipalTag/grade") is None


# --- Asking about one of the file's principals -----------------------------------------

ORG = Path(__file__).parent.parent / "examples" / "organizations" / "district.json"
ROSTER = "arn:aws:s3:::district-student-records/2026/roster.csv"


def test_a_request_adds_the_callers_keys_to_the_principals():
    request = load_account_file(EXAMPLE).request(
        "user/jsmith", "s3:GetObject", ROSTER,
        context=RequestContext.of([("aws:SourceIp", "203.0.113.5")]),
    )
    assert request.context.get("aws:username") == ("jsmith",)
    assert request.context.get("aws:SourceIp") == ("203.0.113.5",)


def test_a_request_cannot_change_what_the_file_says():
    with pytest.raises(RequestError, match="'aws:username' comes from district.json user/jsmith"):
        load_account_file(EXAMPLE).request(
            "user/jsmith", "s3:GetObject", ROSTER,
            context=RequestContext.of([("aws:username", "alee")]),
        )


def test_a_request_can_rule_out_session_tags():
    acct = with_role(Tags=[{"Key": "campus", "Value": "campus-01"}])
    request = acct.request("role/ITAdmin", "s3:GetObject", "*", session_tags=False)
    assert request.context.get("aws:PrincipalTag/campus") == ("campus-01",)


def test_evaluate_uses_the_identity_policies_boundary_and_described_resource():
    acct = load_account_file(EXAMPLE)
    notes = "arn:aws:s3:::district-student-records/counseling/2026/notes.pdf"
    # A bucket policy grant, with no identity policy at all.
    kwong = acct.evaluate("user/kwong", acct.request("user/kwong", "s3:GetObject", notes),
                          organization=None)
    assert kwong.allowed
    # A group's Allow that the user's boundary doesn't allow.
    campus_02 = "arn:aws:s3:::district-student-records/campus-02/transcript.pdf"
    dpatel = acct.evaluate("user/dpatel", acct.request("user/dpatel", "s3:GetObject", campus_02),
                           organization=None)
    assert dpatel.decision is Decision.IMPLICIT_DENY
    assert [layer.policy_type for layer in dpatel.not_allowed_by] == [
        PolicyType.PERMISSIONS_BOUNDARY, PolicyType.RESOURCE_BASED
    ]


def test_evaluate_applies_the_organizations_scps():
    acct = load_account_file(EXAMPLE)
    request = acct.request("user/alee", "ec2:DescribeInstances", "*")
    assert acct.evaluate("user/alee", request, organization=None).allowed
    denied = acct.evaluate("user/alee", request, organization=load_organization_file(ORG))
    assert denied.decision is Decision.IMPLICIT_DENY
    assert [layer.org_target.name for layer in denied.not_allowed_by] == ["Schools"]


def test_evaluate_needs_the_organization_stated():
    acct = load_account_file(EXAMPLE)
    with pytest.raises(TypeError, match="organization"):
        acct.evaluate("user/alee", acct.request("user/alee", "ec2:DescribeInstances", "*"))


def test_evaluate_with_an_organization_needs_an_account_id():
    acct = account(Users={"jsmith": {"Policies": ["Read"]}})
    with pytest.raises(AccountError, match="acct.json: needs an 'AccountId' to look up its SCPs"):
        acct.evaluate("user/jsmith", acct.request("user/jsmith", "s3:GetObject", "*"),
                      organization=load_organization_file(ORG))


def test_evaluate_skips_scps_for_a_service_linked_role():
    acct = account(AccountId="111122223333", Policies={"Describe": {"Statement": [
        {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}},
        Roles={"AWSServiceRoleForSupport": {
            "Policies": ["Describe"], "Path": "/aws-service-role/support.amazonaws.com/"}})
    request = acct.request("role/AWSServiceRoleForSupport", "ec2:DescribeInstances", "*")
    result = acct.evaluate("role/AWSServiceRoleForSupport", request,
                           organization=load_organization_file(ORG))
    assert result.allowed
