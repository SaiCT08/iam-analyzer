import json
from pathlib import Path

import pytest

from iam_analyzer.account import load_account_file, parse_account
from iam_analyzer.errors import AccountError, PolicyParseError

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
