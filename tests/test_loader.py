import json
import re

import pytest

from iam_analyzer.errors import PolicyParseError, UnsupportedPolicyFeature
from iam_analyzer.loader import load_policy, load_policy_file, parse_policy
from iam_analyzer.models import Effect

READ = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}


def test_single_values_are_normalized_to_tuples():
    policy = parse_policy(
        {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}},
        name="p",
    )
    assert len(policy.statements) == 1
    statement = policy.statements[0]
    assert statement.effect is Effect.ALLOW
    assert statement.actions == ("s3:GetObject",)
    assert statement.resources == ("*",)
    assert statement.sid is None


def test_lists_are_kept_and_sid_is_read():
    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Read",
                    "Effect": "Deny",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::a", "arn:aws:s3:::a/*"],
                }
            ],
        },
        name="p",
    )
    statement = policy.statements[0]
    assert statement.effect is Effect.DENY
    assert statement.actions == ("s3:GetObject", "s3:ListBucket")
    assert statement.resources == ("arn:aws:s3:::a", "arn:aws:s3:::a/*")
    assert statement.sid == "Read"


def test_plain_action_and_resource_are_not_negated():
    policy = parse_policy(
        {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}, name="p"
    )
    statement = policy.statements[0]
    assert not statement.not_action
    assert not statement.not_resource


def test_not_action_and_not_resource_are_read():
    policy = parse_policy(
        {
            "Statement": {
                "Effect": "Deny",
                "NotAction": ["s3:Get*", "s3:List*"],
                "NotResource": "arn:aws:s3:::public/*",
            }
        },
        name="p",
    )
    statement = policy.statements[0]
    assert statement.actions == ("s3:Get*", "s3:List*")
    assert statement.not_action
    assert statement.resources == ("arn:aws:s3:::public/*",)
    assert statement.not_resource


def test_load_policy_file_uses_file_name(tmp_path):
    path = tmp_path / "teacher.json"
    path.write_text(json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    assert load_policy_file(path).name == "teacher.json"


def test_missing_file(tmp_path):
    with pytest.raises(PolicyParseError, match="cannot read file"):
        load_policy_file(tmp_path / "nope.json")


@pytest.mark.parametrize(
    "document, message",
    [
        ([], "must be a JSON object"),
        ({}, "no 'Statement'"),
        ({"Statement": ["x"]}, "statement must be a JSON object"),
        ({"Statement": [{"Action": "*", "Resource": "*"}]}, "'Effect'"),
        ({"Statement": [{"Effect": "allow", "Action": "*", "Resource": "*"}]}, "'Effect'"),
        ({"Statement": [{"Effect": "Allow", "Resource": "*"}]}, "missing 'Action'"),
        ({"Statement": [{"Effect": "Allow", "Action": "*"}]}, "missing 'Resource'"),
        ({"Statement": [{"Effect": "Allow", "Action": [], "Resource": "*"}]}, "'Action' must be"),
        ({"Statement": [{"Effect": "Allow", "Action": [1], "Resource": "*"}]}, "'Action' must be"),
        (
            {"Statement": [{"Effect": "Allow", "Action": "*", "NotAction": "s3:*", "Resource": "*"}]},
            "both 'Action' and 'NotAction'",
        ),
        (
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "NotResource": "*"}]},
            "both 'Resource' and 'NotResource'",
        ),
        ({"Statement": [{"Effect": "Allow", "Resource": "*"}]}, "missing 'Action' or 'NotAction'"),
        (
            {"Statement": [{"Effect": "Allow", "NotAction": [], "Resource": "*"}]},
            "'NotAction' must be",
        ),
        (
            {"Statement": [{"Effect": "Allow", "Action": "*", "NotResource": ""}]},
            "'NotResource' must be",
        ),
        (
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "Bogus": 1}]},
            "unknown element",
        ),
        # Rules AWS checks when a policy is saved.
        ({"Version": "2012-10-18", "Statement": [READ]}, "'Version'"),
        ({"Version": 2012, "Statement": [READ]}, "'Version'"),
        ({"Version": "2012-10-17", "Statement": []}, "'Statement'"),
        ({"Statment": [READ]}, "unknown top-level key.*Statment"),
        ({"Version": "2012-10-17", "Statement": [{**READ, "Action": "s3*"}]}, "'Action'"),
        ({"Statement": [{**READ, "Action": ["s3:GetObject", "*Object"]}]}, "needs a service prefix"),
        (
            {"Statement": [{"Effect": "Allow", "NotAction": "s3*", "Resource": "*"}]},
            "'NotAction' entry 's3.' needs a service prefix",
        ),
        ({"Statement": [{**READ, "Sid": "Read records"}]}, "'Sid' must be a string of ASCII"),
        ({"Statement": [{**READ, "Sid": 7}]}, "'Sid' must be a string of ASCII"),
        (
            {"Statement": [{**READ, "Sid": "Read"}, {**READ, "Sid": "Read"}]},
            "Sid 'Read' is used more than once",
        ),
    ],
)
def test_invalid_policies(document, message):
    with pytest.raises(PolicyParseError, match=message):
        parse_policy(document, name="p")


def test_invalid_json():
    with pytest.raises(PolicyParseError, match="invalid JSON"):
        load_policy("{not json", name="p")


def test_duplicate_key_in_a_statement_is_rejected():
    # json.loads would keep only the last "Effect" and load this Deny as an Allow.
    text = '{"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Effect": "Allow"}]}'
    with pytest.raises(PolicyParseError, match="p: duplicate key 'Effect'"):
        load_policy(text, name="p")


def test_empty_sid_counts_as_no_sid():
    # Tools such as Terraform write "Sid": "" for statements without one, and IAM accepts it.
    policy = parse_policy({"Statement": [{**READ, "Sid": ""}, {**READ, "Sid": ""}]}, name="p")
    assert [statement.sid for statement in policy.statements] == [None, None]


def test_both_policy_language_versions_are_accepted():
    for version in ("2012-10-17", "2008-10-17"):
        assert parse_policy({"Version": version, "Statement": [READ]}, name="p").statements


@pytest.mark.parametrize("key", ["Resource", "NotResource"])
@pytest.mark.parametrize(
    "variable", ["${aws:username}", "${*}", "${aws:PrincipalTag/team, 'staff'}"]
)
def test_policy_variables_are_refused_with_version_2012_10_17(key, variable):
    statement = {"Effect": "Allow", "Action": "s3:GetObject", key: f"arn:aws:s3:::home/{variable}/*"}
    document = {"Version": "2012-10-17", "Statement": [statement]}
    message = f"p statement 0: policy variable {variable!r} in '{key}' is not supported yet"
    with pytest.raises(UnsupportedPolicyFeature, match=re.escape(message)):
        parse_policy(document, name="p")


@pytest.mark.parametrize("version", [None, "2008-10-17"])
def test_policy_variables_are_plain_text_without_version_2012_10_17(version):
    resource = "arn:aws:s3:::home/${aws:username}/*"
    document = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": resource}]}
    if version is not None:
        document["Version"] = version
    assert parse_policy(document, name="p").statements[0].resources == (resource,)


def test_id_is_only_for_resource_based_policies():
    with pytest.raises(UnsupportedPolicyFeature, match="'Id' is only allowed in resource-based"):
        parse_policy({"Id": "cd3ad3d9-2776-4ef1-a904-4c229d1642ee", "Statement": [READ]}, name="p")


@pytest.mark.parametrize("element", ["Principal", "NotPrincipal"])
def test_principal_is_only_for_resource_based_policies(element):
    with pytest.raises(UnsupportedPolicyFeature, match=f"'{element}' is only allowed in resource-based"):
        parse_policy({"Statement": [{**READ, element: "*"}]}, name="p")


@pytest.mark.parametrize(
    "element, value",
    [
        ("Condition", {"Bool": {"aws:SecureTransport": "true"}}),
        ("Principal", "*"),
        ("NotPrincipal", "*"),
    ],
)
def test_unsupported_elements_are_rejected(element, value):
    statement = {"Sid": "S1", "Effect": "Deny", "Action": "*", "Resource": "*", element: value}
    with pytest.raises(UnsupportedPolicyFeature, match=f"Sid=S1.*'{element}'"):
        parse_policy({"Statement": [statement]}, name="p")
