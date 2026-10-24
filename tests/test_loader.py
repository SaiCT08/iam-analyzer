import json

import pytest

from iam_analyzer.errors import PolicyParseError, UnsupportedPolicyFeature
from iam_analyzer.loader import load_policy, load_policy_file, parse_policy
from iam_analyzer.models import Effect, PolicyType, Principal, PrincipalType

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
        # The shape of a Condition block: {operator: {key: value or [values]}}.
        ({"Statement": [{**READ, "Condition": []}]}, "'Condition' must be a non-empty JSON"),
        ({"Statement": [{**READ, "Condition": {}}]}, "'Condition' must be a non-empty JSON"),
        (
            {"Statement": [{**READ, "Condition": {"StringEquals": []}}]},
            "condition 'StringEquals' must be a non-empty JSON object of condition keys",
        ),
        ({"Statement": [{**READ, "Condition": {"StringEquals": {}}}]}, "non-empty JSON object"),
        (
            {"Statement": [{**READ, "Condition": {"StringEquals": {"SourceIp": "x"}}}]},
            "'SourceIp' is not a condition key",
        ),
        (
            {"Statement": [{**READ, "Condition": {"StringEquals": {"aws:${x}": "a"}}}]},
            "is not a condition key",
        ),
        (
            {"Statement": [{**READ, "Condition": {"StringEquals": {"aws:x": "a", "AWS:X": "b"}}}]},
            "names 'AWS:X' twice",
        ),
        (
            {"Statement": [{**READ, "Condition": {"StringEquals": {"aws:x": []}}}]},
            "on 'aws:x': needs at least one value",
        ),
        (
            {"Statement": [{**READ, "Condition": {"StringEquals": {"aws:x": None}}}]},
            "values must be strings, numbers or booleans",
        ),
        (
            {"Statement": [{**READ, "Condition": {"StringEquals": {"aws:x": [{"a": 1}]}}}]},
            "values must be strings, numbers or booleans",
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
def test_policy_variables_are_read_with_version_2012_10_17(key, variable):
    resource = f"arn:aws:s3:::home/{variable}/*"
    statement = {"Effect": "Allow", "Action": "s3:GetObject", key: resource}
    document = {"Version": "2012-10-17", "Statement": [statement]}
    [parsed] = parse_policy(document, name="p").statements
    assert parsed.policy_variables
    assert parsed.resources == (resource,)  # filled in when a request is evaluated


@pytest.mark.parametrize("version", [None, "2008-10-17"])
def test_policy_variables_are_plain_text_without_version_2012_10_17(version):
    resource = "arn:aws:s3:::home/${aws:username}/*"
    document = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": resource}]}
    if version is not None:
        document["Version"] = version
    [statement] = parse_policy(document, name="p").statements
    assert statement.resources == (resource,)
    assert not statement.policy_variables


@pytest.mark.parametrize(
    "statement, error, message",
    [
        (
            {**READ, "Resource": "arn:aws:s3:::home/${username}/*"},
            PolicyParseError,
            "p statement 0: 'Resource': malformed policy variable",
        ),
        # AWS only allows variables in the resource part of an ARN, after the fifth colon.
        (
            {**READ, "Resource": "arn:aws:iam::${aws:PrincipalAccount}:user/x"},
            PolicyParseError,
            "after the fifth colon",
        ),
        ({**READ, "Resource": "${aws:username}"}, PolicyParseError, "after the fifth colon"),
        (
            {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:${*}::b"},
            PolicyParseError,
            "'NotResource' entry 'arn:aws:s3:\\$\\{\\*\\}::b': policy variables can only be used",
        ),
        ({**READ, "Action": "s3:${aws:username}"}, PolicyParseError, "can't be used in actions"),
        (
            {**READ, "Resource": "arn:aws:s3:::b/${aws:PrincipalTag/team, 'team-*'}"},
            UnsupportedPolicyFeature,
            "contains \\* or \\?",
        ),
    ],
)
def test_invalid_policy_variables_are_refused(statement, error, message):
    with pytest.raises(error, match=message):
        parse_policy({"Version": "2012-10-17", "Statement": [statement]}, name="p")


def test_id_is_only_for_resource_based_policies():
    with pytest.raises(PolicyParseError, match="^p: 'Id' is only allowed in resource-based"):
        parse_policy({"Id": "cd3ad3d9-2776-4ef1-a904-4c229d1642ee", "Statement": [READ]}, name="p")


@pytest.mark.parametrize("element", ["Principal", "NotPrincipal"])
def test_principal_is_only_for_resource_based_policies(element):
    statement = {"Sid": "S1", **READ, element: "*"}
    message = f"^p statement 0 \\(Sid=S1\\): '{element}' is only allowed in resource-based"
    with pytest.raises(PolicyParseError, match=message):
        parse_policy({"Statement": [statement]}, name="p")


# --- Resource-based policies -----------------------------------------------------------

BUCKET_READ = {
    "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
}
KWONG = "arn:aws:iam::111122223333:user/kwong"


def resource_policy(*statements, **top):
    document = {"Statement": list(statements), **top}
    return parse_policy(document, name="bucket", kind=PolicyType.RESOURCE_BASED)


def test_principals_are_read():
    principal = {"AWS": ["111122223333", KWONG], "Service": "cloudtrail.amazonaws.com"}
    [statement] = resource_policy({**BUCKET_READ, "Principal": principal}).statements
    assert statement.principals == (
        Principal(PrincipalType.AWS, "111122223333"),
        Principal(PrincipalType.AWS, KWONG),
        Principal(PrincipalType.SERVICE, "cloudtrail.amazonaws.com"),
    )


def test_star_is_the_same_as_aws_star():
    # AWS documents "Principal": "*" and {"AWS": "*"} as the same thing.
    for principal in ("*", {"AWS": "*"}):
        [statement] = resource_policy({**BUCKET_READ, "Principal": principal}).statements
        assert statement.principals == (Principal(PrincipalType.AWS, "*"),)


def test_identity_policies_have_no_principals():
    assert parse_policy({"Statement": [READ]}, name="p").statements[0].principals is None


def test_id_is_allowed_in_resource_based_policies():
    resource_policy(BUCKET_READ, Id="cd3ad3d9-2776-4ef1-a904-4c229d1642ee")
    with pytest.raises(PolicyParseError, match="'Id' must be a string"):
        resource_policy(BUCKET_READ, Id=7)


@pytest.mark.parametrize(
    "changes, error, message",
    [
        ({"Principal": None}, PolicyParseError, "statement needs a 'Principal'"),
        ({"NotPrincipal": "*"}, PolicyParseError, "cannot have both 'Principal' and"),
        (
            {"Principal": None, "NotPrincipal": {"AWS": KWONG}},
            PolicyParseError,
            "AWS only allows 'NotPrincipal' with \"Effect\": \"Deny\"",
        ),
        (
            {"Principal": None, "NotPrincipal": {"AWS": KWONG}, "Effect": "Deny"},
            UnsupportedPolicyFeature,
            "'NotPrincipal' isn't supported yet",
        ),
        ({"Principal": "111122223333"}, PolicyParseError, "must be \"\\*\" or a non-empty JSON"),
        ({"Principal": {}}, PolicyParseError, "must be \"\\*\" or a non-empty JSON"),
        ({"Principal": {"Group": "Teachers"}}, PolicyParseError, "unknown principal type 'Group'"),
        ({"Principal": {"AWS": []}}, PolicyParseError, "needs a string or a non-empty list"),
        ({"Principal": {"AWS": ""}}, PolicyParseError, "needs a string or a non-empty list"),
        (
            {"Principal": {"AWS": "arn:aws:iam::111122223333:user/*"}},
            PolicyParseError,
            "AWS doesn't allow a wildcard in part of a principal",
        ),
        ({"Principal": {"AWS": "arn:aws:iam::*:root"}}, PolicyParseError, "wildcard"),
        ({"Principal": {"Service": "*"}}, PolicyParseError, "'Service' can't be \"\\*\""),
        (
            {"Principal": {"AWS": "arn:aws:iam::111122223333:group/Teachers"}},
            PolicyParseError,
            "isn't an AWS principal",
        ),
        ({"Principal": {"AWS": "jsmith"}}, PolicyParseError, "isn't an AWS principal"),
        ({"Principal": {"AWS": "1111-2222-3333"}}, PolicyParseError, "isn't an AWS principal"),
    ],
)
def test_invalid_resource_based_statements(changes, error, message):
    statement = {**BUCKET_READ, **changes}
    statement = {key: value for key, value in statement.items() if value is not None}
    with pytest.raises(error, match=message):
        resource_policy(statement)


def test_principal_forms_aws_documents_are_accepted():
    principals = {"AWS": [
        "*", "111122223333", "arn:aws:iam::111122223333:root", KWONG,
        "arn:aws:iam::111122223333:role/district/CampusApp",
        "arn:aws:sts::111122223333:assumed-role/CampusApp/session-1",
        "arn:aws:sts::111122223333:federated-user/bob",
        "AIDAJQABLZS4A3QDU576Q",  # what AWS shows for a principal that was deleted
    ], "Federated": "cognito-identity.amazonaws.com", "CanonicalUser": "79a59df900b949e5"}
    [statement] = resource_policy({**BUCKET_READ, "Principal": principals}).statements
    assert len(statement.principals) == 10
