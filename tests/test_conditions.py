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
        "arn:aws:iam::111122223333:user/Ana", "arn:aws:iam::111122223333:user/Mary"]},
}
TAGS_AND_NOT_ARN = {
    "StringEquals": TAGS_AND_ARN["StringEquals"],
    "ArnNotLike": TAGS_AND_ARN["ArnLike"],
}
SAME_TEAM = {"StringNotEquals": {"s3:ExistingObjectTag/Team": "${aws:PrincipalTag/Team}"}}


def user(name):
    return f"arn:aws:iam::111122223333:user/{name}"


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
        (SNS_TOPIC, {"aws:SourceArn": "arn:aws:sns:us-west-2:444455556666:TOPIC-ID"}, False),
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
                         DISTRIBUTION.format("444455556666", "costcenter")}, False),
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


# --- Cases AWS's docs leave open, which the IAM policy simulator answered ---------------
# Each names its fixtures in tests/simulator_fixtures.


@pytest.mark.parametrize(
    "value, just_before, just_after",
    [
        # With no time zone, the simulator read each form as UTC (dates_without_a_time_zone/*).
        ("2026-08-15", "2026-08-14T23:59:59Z", "2026-08-15T00:00:01Z"),
        ("2026-08", "2026-07-31T23:59:59Z", "2026-08-01T00:00:01Z"),
        ("2026-08-15T07:30:00", "2026-08-15T07:29:59Z", "2026-08-15T07:30:01Z"),
        ("2026-08-15T07:30", "2026-08-15T07:29:59Z", "2026-08-15T07:30:01Z"),
        # Four digits are epoch seconds, not a year: 2026 is 1970-01-01T00:33:46Z.
        ("2026", "1970-01-01T00:33:45Z", "1970-01-01T00:33:47Z"),
    ],
)
def test_dates_without_a_time_zone_are_utc(value, just_before, just_after):
    condition = {"DateGreaterThan": {"aws:CurrentTime": value}}
    assert not applies(condition, {"aws:CurrentTime": just_before})
    assert applies(condition, {"aws:CurrentTime": just_after})


def test_request_dates_are_read_the_same_way():
    condition = {"DateLessThan": {"aws:CurrentTime": "2026-08-15T00:00:00Z"}}
    assert applies(condition, {"aws:CurrentTime": "2026-08-14T23:59"})
    assert not applies(condition, {"aws:CurrentTime": "2026-08-15"})


def test_a_bare_ipv6_address_is_a_128():
    # AWS's default of /32 only fits IPv4 (ip_ranges/bare_ipv6_address*).
    condition = {"IpAddress": {"aws:SourceIp": "2001:db8::1"}}
    assert applies(condition, {"aws:SourceIp": "2001:db8::1"})
    assert not applies(condition, {"aws:SourceIp": "2001:db8::2"})


def test_host_bits_in_a_range_are_masked():
    # 203.0.113.5/24 is 203.0.113.0/24 (ip_ranges/range_with_host_bits).
    condition = {"IpAddress": {"aws:SourceIp": "203.0.113.5/24"}}
    assert applies(condition, {"aws:SourceIp": "203.0.113.77"})
    assert not applies(condition, {"aws:SourceIp": "203.0.114.1"})


@pytest.mark.parametrize(
    "operator",
    ["StringEquals", "StringNotEquals", "StringEqualsIfExists", "StringNotEqualsIfExists"],
)
@pytest.mark.parametrize("tag_keys", [["campus", "grade"], ["grade", "other"]])
def test_several_values_with_no_set_operator_never_satisfy_string_equals(operator, tag_keys):
    # Not even StringNotEquals when no value is campus (several_values_without_a_set_operator/*).
    # IfExists changes nothing, since the key is in the request.
    assert not applies({operator: {"aws:TagKeys": "campus"}}, {"aws:TagKeys": tag_keys})


def test_an_empty_value_counts_under_for_any_value_and_null():
    # Only ForAllValues treats "" as a null dataset, as AWS documents (empty_values/*).
    assert applies({"ForAnyValue:StringNotEquals": {"aws:TagKeys": "campus"}}, {"aws:TagKeys": ""})
    assert not applies({"Null": {"aws:TagKeys": "true"}}, {"aws:TagKeys": ""})
    assert applies({"Null": {"aws:TagKeys": "false"}}, {"aws:TagKeys": ""})


def test_for_any_value_wins_over_if_exists_on_a_missing_key():
    # for_any_value_if_exists/key_absent
    assert not applies({"ForAnyValue:StringEqualsIfExists": {"aws:TagKeys": "campus"}},
                       {"aws:TagKeys": None})
    assert applies({"ForAllValues:StringEqualsIfExists": {"aws:TagKeys": "campus"}},
                   {"aws:TagKeys": None})


@pytest.mark.parametrize(
    "condition, tag_keys, expected",
    [
        # On a missing key the set operator decides, as with other operators
        # (set_operator_on_null/*_key_absent). Plain Null would give the opposite answers.
        ({"ForAllValues:Null": {"aws:TagKeys": "false"}}, None, True),
        ({"ForAnyValue:Null": {"aws:TagKeys": "true"}}, None, False),
        # With the key present, Null's own answer stands
        # (set_operator_on_null/for_all_values_null_false).
        ({"ForAllValues:Null": {"aws:TagKeys": "false"}}, ["campus"], True),
        ({"ForAnyValue:Null": {"aws:TagKeys": "true"}}, ["campus"], False),
    ],
)
def test_set_operators_on_null(condition, tag_keys, expected):
    assert applies(condition, {"aws:TagKeys": tag_keys}) is expected


def test_arn_like_checks_the_six_fields_separately():
    lambda_arn = "arn:aws:lambda:us-east-1:111122223333:function:{}"
    # In the resource part, a * matches colons, as in Resource (wildcards_and_colons/arn_like_*).
    condition = {"ArnLike": {"aws:SourceArn": "arn:aws:lambda:*:*:function:*-prod"}}
    assert applies(condition, {"aws:SourceArn": lambda_arn.format("billing-prod")})
    assert applies(condition, {"aws:SourceArn": lambda_arn.format("billing:canary-prod")})
    # But a * that ends the region field stays in that field, although the same pattern matches
    # in Resource (wildcards_and_colons/arn_like_star_ending_the_region_field).
    region_star = {"ArnLike": {"aws:SourceArn": "arn:aws:lambda:*:function:billing:canary"}}
    assert not applies(region_star, {"aws:SourceArn": lambda_arn.format("billing:canary")})
    lined_up = {"ArnLike": {"aws:SourceArn": "arn:aws:lambda:*:*:function:billing:canary"}}
    assert applies(lined_up, {"aws:SourceArn": lambda_arn.format("billing:canary")})


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


def test_a_variable_with_no_value_matches_nothing():
    # AWS's "Policy variables with no value": "StringEquals or StringLike do not match", and
    # "Inverted condition operators like StringNotEquals or StringNotLike do match against a null
    # value".
    no_team = {"aws:PrincipalTag/Team": None, "s3:ExistingObjectTag/Team": "red"}
    assert applies(SAME_TEAM, no_team)  # AWS's example Deny: "Access is explicitly denied"
    same = {"StringEquals": {"s3:ExistingObjectTag/Team": "${aws:PrincipalTag/Team}"}}
    assert not applies(same, no_team)
    # The other values still count.
    assert applies(HOME_PREFIX, {"aws:username": None, "s3:prefix": "home/"})
    assert not applies(HOME_PREFIX, {"aws:username": None, "s3:prefix": "home/jsmith/"})
    # In ARN operators too.
    other_teams = {"ArnNotLike": {"aws:SourceArn": "arn:aws:s3:::teams-${aws:PrincipalTag/Team}/*"}}
    source = "arn:aws:s3:::teams-red/x"
    assert applies(other_teams, {"aws:PrincipalTag/Team": None, "aws:SourceArn": source})


def test_a_variable_from_a_key_with_several_values_matches_nothing():
    # As AWS's IAM policy simulator showed (variables_with_several_values/condition_*).
    tags = {"aws:TagKeys": ["blue", "red"]}
    tagged = "${aws:TagKeys}"
    assert not applies({"StringEquals": {"s3:prefix": tagged}}, {**tags, "s3:prefix": "blue"})
    assert applies({"StringNotEquals": {"s3:prefix": tagged}}, {**tags, "s3:prefix": "red"})


def test_a_star_filled_in_from_a_variable_is_literal():
    # As AWS's IAM policy simulator showed (variables_with_wildcards/condition_*).
    from_value = {"StringLike": {"s3:prefix": "${aws:PrincipalTag/team}/"}}
    assert not applies(from_value, {"aws:PrincipalTag/team": "b*", "s3:prefix": "blue/"})
    assert applies(from_value, {"aws:PrincipalTag/team": "b*", "s3:prefix": "b*/"})
    from_default = {"StringLike": {"s3:prefix": "${aws:PrincipalTag/team, 'class-of-*'}/"}}
    assert not applies(from_default, {"aws:PrincipalTag/team": None, "s3:prefix": "class-of-2026/"})


def test_a_variable_in_a_bool_value_stays_as_written():
    # AWS accepts it but doesn't fill it in, so the value is neither true nor false and never
    # matches (bool_with_a_variable/*).
    condition = {"Bool": {"aws:SecureTransport": "${aws:MultiFactorAuthPresent}"}}
    assert not applies(condition, {"aws:SecureTransport": "true"})
    assert not applies(condition, {"aws:SecureTransport": "false"})
    # A missing key still passes BoolIfExists.
    assert applies({"BoolIfExists": condition["Bool"]}, {"aws:SecureTransport": None})


def test_without_version_2012_10_17_variables_are_plain_text():
    condition = {"StringEquals": {"aws:PrincipalTag/team": "${aws:username}"}}
    assert applies(condition, {"aws:PrincipalTag/team": "${aws:username}"}, version=None)


def test_for_all_values_treats_an_empty_value_as_no_values():
    # AWS: ForAllValues is true when the value "resolves to a null dataset, such as an empty
    # string".
    condition = {"ForAllValues:StringEquals": {"aws:TagKeys": "environment"}}
    assert applies(condition, {"aws:TagKeys": ""})


def test_a_refused_condition_does_not_matter_when_another_fails():
    # aws:TagKeys has two values but no set operator, which nothing settles for StringLike. The
    # Bool condition fails, though, so the statement can't apply either way, in either order.
    several = {"StringLike": {"aws:TagKeys": "a*"}}
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
        # The simulator only answered this for StringEquals and StringNotEquals.
        ({"StringLike": {"aws:TagKeys": "a*"}}, {"aws:TagKeys": ["a", "b"]},
         "requires ForAllValues or ForAnyValue"),
        # ForAllValues holds for a null dataset, but Null counts "" as present.
        ({"ForAllValues:Null": {"aws:TagKeys": "true"}}, {"aws:TagKeys": ""},
         "null dataset, but Null counts the key as present"),
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
        (FRESH_TOKEN, {"aws:TokenIssueTime": "yesterday"}, "expected a date and time"),
        (FRESH_TOKEN, {"aws:TokenIssueTime": "2026-08-15T07:30:00.5"}, "fractions of a second"),
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
        ({"NumericLessThan": {"s3:max-keys": "ten"}}, PolicyParseError, "integer or decimal"),
        ({"DateLessThan": {"aws:CurrentTime": "tomorrow"}}, PolicyParseError, "expected a date"),
        ({"DateLessThan": {"aws:CurrentTime": "2026-13"}}, PolicyParseError, "expected a date"),
        ({"Bool": {"aws:SecureTransport": "yes"}}, PolicyParseError, "true or false"),
        ({"BinaryEquals": {"key:binary": "not base64!"}}, PolicyParseError, "base64"),
        ({"IpAddress": {"aws:SourceIp": "hello"}}, PolicyParseError, "expected an IP range"),
        ({"NumericLessThan": {"s3:max-keys": "${aws:x}"}}, PolicyParseError,
         "doesn't allow policy variables with Numeric"),
        ({"Null": {"aws:x": "${aws:y}"}}, PolicyParseError, "policy variables with Null"),
        # Neither AWS's docs nor the simulator settle these.
        ({"DateLessThan": {"aws:CurrentTime": "2026-08-15T07:30:00.5"}}, UnsupportedPolicyFeature,
         "fractions of a second and no time zone"),
        ({"ArnLike": {"aws:SourceArn": "arn:aws:sns"}}, UnsupportedPolicyFeature, "six fields"),
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
