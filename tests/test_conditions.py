import pytest

from iam_analyzer.context import RequestContext
from iam_analyzer.errors import PolicyParseError, RequestError, UnsupportedPolicyFeature
from iam_analyzer.evaluator import statement_matches
from iam_analyzer.loader import parse_policy
from iam_analyzer.models import Request, SetOperator


def context(entries):
    """{"key": "value" or ["value", ...], or None when the key is absent}."""
    values = []
    for key, value in entries.items():
        if value is not None:
            values += [(key, v) for v in (value if isinstance(value, list) else [value])]
    return RequestContext.of(values, [key for key, value in entries.items() if value is None])


def statement_with(condition, version="2012-10-17"):
    statement = {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": condition}
    document = {"Statement": [statement]}
    if version is not None:
        document["Version"] = version
    [parsed] = parse_policy(document, name="p").statements
    return parsed


def applies(condition, entries, version="2012-10-17"):
    """Whether a statement with this Condition block applies to a request with this context."""
    request = Request(action="s3:GetObject", resource="arn:aws:s3:::b/k", context=context(entries))
    return statement_matches(statement_with(condition, version), request)


# --- AWS's evaluation tables -----------------------------------------------------------
# Each row is a row of a table on one of these pages of the IAM User Guide:
#   "Operators":  reference_policies_elements_condition_operators.html
#   "Multiple":   reference_policies_condition-logic-multiple-context-keys-or-values.html
#   "Set ops":    reference_policies_condition-single-vs-multi-valued-context-keys.html
#   "Variables":  reference_policies_variables.html

JOB_CATEGORY = {"StringEquals": {"aws:PrincipalTag/job-category": "iamuser-admin"}}
HOME_PREFIX = {"StringLike": {"s3:prefix": ["", "home/", "home/${aws:username}/"]}}
TAGGING = {
    "StringEqualsIgnoreCase": {"aws:RequestTag/environment": ["preprod", "storage"]},
    "ForAnyValue:StringEquals": {"aws:TagKeys": "environment"},
}
MAX_KEYS = {"NumericLessThanEquals": {"s3:max-keys": "10"}}
FRESH_TOKEN = {"DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}}
HTTP = {"Bool": {"aws:SecureTransport": "false"}}
BINARY = {"BinaryEquals": {"key:binary": "QmluYXJ5VmFsdWVJbkJhc2U2NA=="}}
OFFICE_IP = {"IpAddress": {"aws:SourceIp": ["203.0.113.0/24", "2001:DB8:1234:5678::/64"]}}
SNS_TOPIC = {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:us-west-2:123456789012:TOPIC-ID"}}
# The page's table writes these ARNs with the service and region swapped; the policy above it
# has them the right way round, as here.
DISTRIBUTIONS = {"ForAllValues:ArnLike": {"logs:LogGeneratingResourceArns": [
    "arn:aws:cloudfront::123456789012:distribution/*",
    "arn:aws:cloudfront::123456789012:distribution/support*",
]}}
DISTRIBUTION = "arn:aws:cloudfront::{}:distribution/{}"
INSTANCE_TYPE = {"StringLikeIfExists": {"ec2:InstanceType": ["t1.*", "t2.*", "m3.*"]}}
TEMPORARY_CREDENTIALS = {"Null": {"aws:TokenIssueTime": "false"}}
ONLY_LISTED_TAGS = {
    "ForAllValues:StringEquals": {"aws:TagKeys": ["environment", "cost-center"]},
    "Null": {"aws:TagKeys": "false"},
}
ANY_LISTED_TAG = {"ForAnyValue:StringEquals": {"aws:TagKeys": ["environment", "cost-center"]}}
TAGS_AND_ARN = {
    "StringEquals": {
        "aws:PrincipalTag/department": ["finance", "hr", "legal"],
        "aws:PrincipalTag/role": ["audit", "security"],
    },
    "ArnLike": {"aws:PrincipalArn": [
        "arn:aws:iam::222222222222:user/Ana", "arn:aws:iam::222222222222:user/Mary"]},
}
TAGS_AND_NOT_ARN = {
    "StringEquals": TAGS_AND_ARN["StringEquals"],
    "ArnNotLike": TAGS_AND_ARN["ArnLike"],
}
SAME_TEAM = {"StringNotEquals": {"s3:ExistingObjectTag/Team": "${aws:PrincipalTag/Team}"}}


def user(name):
    return f"arn:aws:iam::222222222222:user/{name}"


def tags(department=None, role=None, arn=None):
    return {"aws:PrincipalTag/department": department, "aws:PrincipalTag/role": role,
            "aws:PrincipalArn": arn}


@pytest.mark.parametrize(
    "condition, entries, expected",
    [
        # Operators, string example.
        (JOB_CATEGORY, {"aws:PrincipalTag/job-category": "iamuser-admin"}, True),
        (JOB_CATEGORY, {"aws:PrincipalTag/job-category": "dev-ops"}, False),
        (JOB_CATEGORY, {"aws:PrincipalTag/job-category": None}, False),
        # Operators, a policy variable in StringLike.
        (HOME_PREFIX, {"aws:username": "martha_rivera", "s3:prefix": "home/martha_rivera/"}, True),
        (HOME_PREFIX, {"aws:username": "nikki_wolf", "s3:prefix": "home/martha_rivera/"}, False),
        (HOME_PREFIX, {"aws:username": "nikki_wolf", "s3:prefix": ""}, True),
        # Operators, ForAnyValue with tags.
        (TAGGING, {"aws:TagKeys": "environment", "aws:RequestTag/environment": "preprod"}, True),
        (TAGGING, {"aws:TagKeys": ["environment", "costcenter"],
                   "aws:RequestTag/environment": "PreProd"}, True),
        (TAGGING, {"aws:TagKeys": "Environment", "aws:RequestTag/Environment": "preprod"}, False),
        (TAGGING, {"aws:TagKeys": "costcenter", "aws:RequestTag/environment": "preprod"}, False),
        (TAGGING, {"aws:TagKeys": None, "aws:RequestTag/environment": "storage"}, False),
        (TAGGING, {"aws:TagKeys": "environment", "aws:RequestTag/environment": None}, False),
        (TAGGING, {"aws:TagKeys": None, "aws:RequestTag/environment": None}, False),
        # Operators, numeric, date and Bool examples.
        (MAX_KEYS, {"s3:max-keys": "10"}, True),
        (MAX_KEYS, {"s3:max-keys": "11"}, False),
        (MAX_KEYS, {"s3:max-keys": None}, False),
        (FRESH_TOKEN, {"aws:TokenIssueTime": "2020-06-01T00:00:00Z"}, True),
        (FRESH_TOKEN, {"aws:TokenIssueTime": "2019-12-31T23:59:59Z"}, False),
        (FRESH_TOKEN, {"aws:TokenIssueTime": None}, False),  # access keys: the key is missing
        (HTTP, {"aws:SecureTransport": "false"}, True),
        (HTTP, {"aws:SecureTransport": "true"}, False),
        (HTTP, {"aws:SecureTransport": None}, False),
        # Operators, BinaryEquals.
        (BINARY, {"key:binary": "QmluYXJ5VmFsdWVJbkJhc2U2NA=="}, True),
        (BINARY, {"key:binary": "ASIAIOSFODNN7EXAMPLE"}, False),
        (BINARY, {"key:binary": None}, False),
        # Operators, IP addresses, including the mixed IPv4 and IPv6 example.
        (OFFICE_IP, {"aws:SourceIp": "203.0.113.1"}, True),
        (OFFICE_IP, {"aws:SourceIp": "198.51.100.1"}, False),
        (OFFICE_IP, {"aws:SourceIp": "2001:db8:1234:5678::1"}, True),
        # Operators, ArnEquals.
        (SNS_TOPIC, {"aws:SourceArn": "arn:aws:sns:us-west-2:123456789012:TOPIC-ID"}, True),
        (SNS_TOPIC, {"aws:SourceArn": "arn:aws:sns:us-west-2:777788889999:TOPIC-ID"}, False),
        (SNS_TOPIC, {"aws:SourceArn": None}, False),
        # Operators, ForAllValues:ArnLike.
        (DISTRIBUTIONS, {"logs:LogGeneratingResourceArns":
                         DISTRIBUTION.format("123456789012", "costcenter")}, True),
        (DISTRIBUTIONS, {"logs:LogGeneratingResourceArns": [
            DISTRIBUTION.format("123456789012", "costcenter"),
            DISTRIBUTION.format("123456789012", "support2025")]}, True),
        (DISTRIBUTIONS, {"logs:LogGeneratingResourceArns": [
            DISTRIBUTION.format("123456789012", "costcenter"),
            DISTRIBUTION.format("123456789012", "admin")]}, True),
        (DISTRIBUTIONS, {"logs:LogGeneratingResourceArns":
                         DISTRIBUTION.format("777788889999", "costcenter")}, False),
        (DISTRIBUTIONS, {"logs:LogGeneratingResourceArns": None}, True),
        # Operators, IfExists and Null.
        (INSTANCE_TYPE, {"ec2:InstanceType": "t1.micro"}, True),
        (INSTANCE_TYPE, {"ec2:InstanceType": "m2.micro"}, False),
        (INSTANCE_TYPE, {"ec2:InstanceType": None}, True),
        (TEMPORARY_CREDENTIALS, {"aws:TokenIssueTime": "2026-10-23T08:00:00Z"}, True),
        (TEMPORARY_CREDENTIALS, {"aws:TokenIssueTime": None}, False),
        # Set ops, ForAllValues with a Null check.
        (ONLY_LISTED_TAGS, {"aws:TagKeys": "environment"}, True),
        (ONLY_LISTED_TAGS, {"aws:TagKeys": "cost-center"}, True),
        (ONLY_LISTED_TAGS, {"aws:TagKeys": ["environment", "cost-center"]}, True),
        (ONLY_LISTED_TAGS, {"aws:TagKeys": ["environment", "dept"]}, False),
        (ONLY_LISTED_TAGS, {"aws:TagKeys": None}, False),
        # Set ops, ForAnyValue.
        (ANY_LISTED_TAG, {"aws:TagKeys": "environment"}, True),
        (ANY_LISTED_TAG, {"aws:TagKeys": "cost-center"}, True),
        (ANY_LISTED_TAG, {"aws:TagKeys": ["environment", "cost-center"]}, True),
        (ANY_LISTED_TAG, {"aws:TagKeys": ["environment", "dept"]}, True),
        (ANY_LISTED_TAG, {"aws:TagKeys": "dept"}, False),
        (ANY_LISTED_TAG, {"aws:TagKeys": None}, False),
        # Multiple, keys and values together.
        (TAGS_AND_ARN, tags("legal", "audit", user("Mary")), True),
        (TAGS_AND_ARN, tags("hr", "audit", user("Nikki")), False),
        (TAGS_AND_ARN, tags("hr", "payroll", user("Mary")), False),
        (TAGS_AND_ARN, tags("hr", None, user("Mary")), False),
        (TAGS_AND_ARN, tags(None, None, user("Mary")), False),
        # Multiple, with a negated operator.
        (TAGS_AND_NOT_ARN, tags("legal", "audit", user("Nikki")), True),
        (TAGS_AND_NOT_ARN, tags("hr", "audit", user("Mary")), False),
        (TAGS_AND_NOT_ARN, tags("hr", "payroll", user("Nikki")), False),
        (TAGS_AND_NOT_ARN, tags("hr", None, user("Nikki")), False),
        (TAGS_AND_NOT_ARN, tags(None, None, user("Nikki")), False),
        # Variables, StringNotEquals against a principal tag.
        (SAME_TEAM, {"aws:PrincipalTag/Team": "blue", "s3:ExistingObjectTag/Team": "blue"}, False),
        (SAME_TEAM, {"aws:PrincipalTag/Team": "blue", "s3:ExistingObjectTag/Team": "red"}, True),
    ],
)
def test_aws_documentation_tables(condition, entries, expected):
    assert applies(condition, entries) is expected


# The operators page's table for this example says the opposite in all three rows (Match, No
# match, No match). Each row contradicts the set-operator and negated-operator definitions
# beside it, and the example's own description ("denies access to Amazon S3 actions unless the
# resource being accessed is in a specific set of organizational units") only works with the
# definitions. So these tests expect the definitions' results.
OU_BOUNDARY = {"ForAllValues:StringNotLike": {"aws:ResourceOrgPaths": [
    "o-acorg/r-acroot/ou-acroot-mediaou/", "o-acorg/r-acroot/ou-acroot-sportsou/*"]}}


@pytest.mark.parametrize(
    "paths, expected",
    [
        ("o-acorg/r-acroot/ou-acroot-sportsou/costcenter/", False),  # the table says Match
        ("o-acorg/r-acroot/ou-acroot-mediaou/costcenter/", True),  # the table says No match
        (None, True),  # the table says No match
    ],
)
def test_for_all_values_string_not_like_follows_the_definitions(paths, expected):
    assert applies(OU_BOUNDARY, {"aws:ResourceOrgPaths": paths}) is expected


# --- Operators -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "operator, value, request_value, expected",
    [
        ("StringEquals", "campus-01", "Campus-01", False),
        ("StringEqualsIgnoreCase", "campus-01", "Campus-01", True),
        ("StringNotEqualsIgnoreCase", "campus-01", "Campus-01", False),
        # StringEquals has no wildcards, so * only matches itself.
        ("StringEquals", "campus-*", "campus-*", True),
        ("StringEquals", "campus-*", "campus-01", False),
        ("StringLike", "campus-*", "campus-01", True),
        ("StringNotLike", "campus-*", "campus-01", False),
    ],
)
def test_string_operators(operator, value, request_value, expected):
    condition = {operator: {"aws:PrincipalTag/campus": value}}
    assert applies(condition, {"aws:PrincipalTag/campus": request_value}) is expected


def test_a_negated_operator_needs_every_value_to_differ():
    condition = {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-east-2"]}}
    assert not applies(condition, {"aws:RequestedRegion": "us-east-1"})
    assert applies(condition, {"aws:RequestedRegion": "eu-west-1"})


@pytest.mark.parametrize(
    "operator", ["StringNotEquals", "StringNotLike", "ArnNotLike", "NotIpAddress", "DateNotEquals"]
)
def test_a_negated_operator_holds_when_the_key_is_missing(operator):
    value = {"ArnNotLike": "arn:aws:iam::*:role/Admin", "NotIpAddress": "203.0.113.0/24",
             "DateNotEquals": "2026-01-01T00:00:00Z"}.get(operator, "x")
    assert applies({operator: {"aws:SourceThing": value}}, {"aws:SourceThing": None})


@pytest.mark.parametrize(
    "operator, expected",
    [
        ("NumericEquals", True),
        ("NumericNotEquals", False),
        ("NumericLessThan", False),
        ("NumericLessThanEquals", True),
        ("NumericGreaterThan", False),
        ("NumericGreaterThanEquals", True),
    ],
)
def test_numeric_operators(operator, expected):
    # JSON numbers work as well as strings.
    assert applies({operator: {"s3:max-keys": 10}}, {"s3:max-keys": "10.0"}) is expected


def test_dates_can_be_iso_8601_or_epoch_seconds():
    # 1700000000 is 2023-11-14T22:13:20Z.
    condition = {"DateLessThan": {"aws:EpochTime": "2026-01-01T00:00:00Z"}}
    assert applies(condition, {"aws:EpochTime": "1700000000"})
    same_moment = {"DateEquals": {"aws:CurrentTime": "2026-08-15T02:30:00-05:00"}}
    assert applies(same_moment, {"aws:CurrentTime": "2026-08-15T07:30:00Z"})


def test_bool_takes_a_json_boolean():
    assert applies({"Bool": {"aws:SecureTransport": False}}, {"aws:SecureTransport": "false"})


def test_a_bare_ipv4_address_is_a_32():
    condition = {"IpAddress": {"aws:SourceIp": "203.0.113.5"}}
    assert applies(condition, {"aws:SourceIp": "203.0.113.5"})
    assert not applies(condition, {"aws:SourceIp": "203.0.113.6"})


def test_arn_wildcards_follow_the_resource_segment_rule():
    condition = {"ArnLike": {"aws:SourceArn": "arn:aws:lambda:*:*:function:*-prod"}}
    lambda_arn = "arn:aws:lambda:us-east-1:111122223333:function:{}"
    assert applies(condition, {"aws:SourceArn": lambda_arn.format("billing-prod")})
    assert not applies(condition, {"aws:SourceArn": lambda_arn.format("billing:canary-prod")})


def test_arn_fields_are_split_before_variables_are_filled_in():
    condition = {"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::${aws:PrincipalAccount}:role/x"}}
    assert applies(condition, {"aws:PrincipalAccount": "111122223333",
                               "aws:PrincipalArn": "arn:aws:iam::111122223333:role/x"})
    # A colon in the filled-in value can't move the fifth field's end.
    assert not applies(condition, {"aws:PrincipalAccount": "111122223333:role",
                                   "aws:PrincipalArn": "arn:aws:iam::111122223333:role:role/x"})


def test_a_literal_star_in_string_like():
    condition = {"StringLike": {"s3:prefix": "reports/${*}"}}
    assert applies(condition, {"s3:prefix": "reports/*"})
    assert not applies(condition, {"s3:prefix": "reports/2026"})


def test_without_version_2012_10_17_variables_are_plain_text():
    condition = {"StringEquals": {"aws:PrincipalTag/team": "${aws:username}"}}
    assert applies(condition, {"aws:PrincipalTag/team": "${aws:username}"}, version=None)


def test_for_all_values_treats_an_empty_value_as_no_values():
    # AWS: ForAllValues is true when the value "resolves to a null dataset, such as an empty
    # string".
    condition = {"ForAllValues:StringEquals": {"aws:TagKeys": "environment"}}
    assert applies(condition, {"aws:TagKeys": ""})


def test_a_refused_condition_does_not_matter_when_another_fails():
    # aws:TagKeys has two values but no set operator, which AWS doesn't define. The Bool
    # condition fails, though, so the statement can't apply either way, in either order.
    several = {"StringEquals": {"aws:TagKeys": "a"}}
    https = {"Bool": {"aws:SecureTransport": "true"}}
    entries = {"aws:TagKeys": ["a", "b"], "aws:SecureTransport": "false"}
    assert not applies({**several, **https}, entries)
    assert not applies({**https, **several}, entries)
    with pytest.raises(UnsupportedPolicyFeature, match="several values"):
        applies({**several, **https}, {**entries, "aws:SecureTransport": "true"})


# --- Refused ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "condition, entries, message",
    [
        ({"StringEquals": {"aws:TagKeys": "a"}}, {"aws:TagKeys": ["a", "b"]},
         "requires ForAllValues or ForAnyValue"),
        ({"ForAnyValue:StringEqualsIfExists": {"aws:TagKeys": "a"}}, {"aws:TagKeys": None},
         "doesn't say which wins"),
        ({"ForAnyValue:StringEquals": {"aws:TagKeys": "a"}}, {"aws:TagKeys": ""},
         "only value is empty"),
        ({"Null": {"aws:TagKeys": "true"}}, {"aws:TagKeys": ""}, "only value is empty"),
        # AWS's docs disagree on a variable with no value.
        (SAME_TEAM, {"aws:PrincipalTag/Team": None, "s3:ExistingObjectTag/Team": "red"},
         "has no value in this request"),
        (HOME_PREFIX, {"aws:username": None, "s3:prefix": "home/"}, "has no value in this request"),
    ],
)
def test_cases_aws_leaves_open_are_refused(condition, entries, message):
    with pytest.raises(UnsupportedPolicyFeature, match=message):
        applies(condition, entries)


@pytest.mark.parametrize(
    "condition, entries, message",
    [
        (OFFICE_IP, {"aws:SourceIp": "hello"}, "'aws:SourceIp': expected an IP address"),
        (HTTP, {"aws:SecureTransport": "True"}, "expected true or false, got 'True'"),
        (SNS_TOPIC, {"aws:SourceArn": "sns-topic"}, "expected an ARN with six fields"),
        (MAX_KEYS, {"s3:max-keys": "ten"}, "expected an integer or decimal"),
        (FRESH_TOKEN, {"aws:TokenIssueTime": "2026-08-15"}, "without a time and a time zone"),
    ],
)
def test_request_values_that_do_not_fit_the_operator(condition, entries, message):
    with pytest.raises(RequestError, match=message):
        applies(condition, entries)


@pytest.mark.parametrize(
    "condition, error, message",
    [
        ({"stringequals": {"aws:x": "a"}}, PolicyParseError, "unknown condition operator"),
        ({"ForSomeValues:StringLike": {"aws:x": "a"}}, PolicyParseError, "unknown condition"),
        ({"NullIfExists": {"aws:x": "true"}}, PolicyParseError, "doesn't allow IfExists on Null"),
        ({"ForAllValues:Null": {"aws:x": "true"}}, UnsupportedPolicyFeature, "set operator"),
        ({"NumericLessThan": {"s3:max-keys": "ten"}}, PolicyParseError, "integer or decimal"),
        ({"DateLessThan": {"aws:CurrentTime": "tomorrow"}}, PolicyParseError, "time zone"),
        ({"Bool": {"aws:SecureTransport": "yes"}}, PolicyParseError, "true or false"),
        ({"BinaryEquals": {"key:binary": "not base64!"}}, PolicyParseError, "base64"),
        ({"IpAddress": {"aws:SourceIp": "hello"}}, PolicyParseError, "expected an IP range"),
        ({"NumericLessThan": {"s3:max-keys": "${aws:x}"}}, PolicyParseError,
         "doesn't allow policy variables with Numeric"),
        ({"Null": {"aws:x": "${aws:y}"}}, PolicyParseError, "policy variables with Null"),
        # AWS's docs leave these open.
        ({"Bool": {"aws:SecureTransport": "${aws:x}"}}, UnsupportedPolicyFeature,
         "Bool takes policy variables, but its policy variables page"),
        ({"DateLessThan": {"aws:CurrentTime": "2026-08-15"}}, UnsupportedPolicyFeature,
         "which moment"),
        ({"DateLessThan": {"aws:CurrentTime": "2026-08-15T07:30:00"}}, UnsupportedPolicyFeature,
         "which moment"),
        ({"DateLessThan": {"aws:CurrentTime": "2026"}}, UnsupportedPolicyFeature, "which moment"),
        ({"IpAddress": {"aws:SourceIp": "2001:db8::1"}}, UnsupportedPolicyFeature, "fits IPv4"),
        ({"IpAddress": {"aws:SourceIp": "203.0.113.5/24"}}, UnsupportedPolicyFeature, "host bits"),
        ({"ArnLike": {"aws:SourceArn": "arn:aws:sns"}}, UnsupportedPolicyFeature, "six fields"),
        ({"StringLike": {"s3:prefix": "${aws:username, 'x*'}"}}, UnsupportedPolicyFeature,
         "contains \\* or \\?"),
    ],
)
def test_values_refused_when_the_policy_loads(condition, error, message):
    with pytest.raises(error, match=f"p statement 0: .*{message}"):
        statement_with(condition)


def test_conditions_are_read_into_typed_fields():
    statement = statement_with({
        "ForAnyValue:StringLikeIfExists": {"aws:TagKeys": ["campus-*", "grade"]},
        "NumericLessThan": {"s3:max-keys": 10},
    })
    first, second = statement.conditions
    assert (first.operator, first.key, first.values) == ("StringLike", "aws:TagKeys",
                                                         ("campus-*", "grade"))
    assert first.set_operator is SetOperator.FOR_ANY_VALUE and first.if_exists
    assert first.name == "ForAnyValue:StringLikeIfExists"
    assert (second.name, second.values) == ("NumericLessThan", ("10",))
