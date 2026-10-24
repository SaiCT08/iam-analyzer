import json
from pathlib import Path

import pytest

from iam_analyzer.account import load_account_file, parse_account
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import AccountError, PolicyParseError, RequestError

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
