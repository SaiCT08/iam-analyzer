import pytest

from iam_analyzer.matching import match_action, match_resource, wildcard_match


@pytest.mark.parametrize(
    "pattern, value, expected",
    [
        # exact
        ("s3:GetObject", "s3:GetObject", True),
        ("s3:GetObject", "s3:PutObject", False),
        # * at the end, start, middle, and alone
        ("s3:Get*", "s3:GetObject", True),
        ("s3:Get*", "s3:Get", True),  # * matches zero characters
        ("s3:Get*", "s3:PutObject", False),
        ("*Object", "s3:GetObject", True),
        ("s3:*Object", "s3:GetObject", True),
        ("s3:*Object", "s3:GetObjectAcl", False),
        ("*", "anything:AtAll", True),
        ("s3:*", "ec2:DescribeInstances", False),
        # ? matches exactly one character
        ("campus-??", "campus-01", True),
        ("campus-??", "campus-1", False),
        ("campus-??", "campus-001", False),
        # must match the whole value, not a substring
        ("s3:Get", "s3:GetObject", False),
        ("Object", "s3:GetObject", False),
        # regex/glob metacharacters are literal
        ("a.b", "a.b", True),
        ("a.b", "axb", False),
        ("a+b", "a+b", True),
        ("a+b", "aab", False),
        ("[ab]", "[ab]", True),
        ("[ab]", "a", False),
        # empty edge cases
        ("", "", True),
        ("", "x", False),
        ("*", "", True),
    ],
)
def test_wildcard_match(pattern, value, expected):
    assert wildcard_match(pattern, value) is expected


@pytest.mark.parametrize(
    "pattern, action",
    [
        ("s3:GetObject", "S3:GETOBJECT"),
        ("S3:get*", "s3:GetObject"),
        ("IAM:*", "iam:CreateUser"),
    ],
)
def test_actions_are_case_insensitive(pattern, action):
    assert match_action(pattern, action)


def test_resources_are_case_sensitive():
    assert match_resource("arn:aws:s3:::grades/*", "arn:aws:s3:::grades/2026.csv")
    assert not match_resource("arn:aws:s3:::grades/*", "arn:aws:s3:::GRADES/2026.csv")


def test_resource_star_spans_slashes():
    # In IAM, * is not limited to one path segment.
    assert match_resource("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b/c.csv")


# --- ARN segments ------------------------------------------------------------------------

LAMBDA = "arn:aws:lambda:us-east-1:111122223333:function"
LOGS = "arn:aws:logs:us-east-1:111122223333:log-group"


def test_star_inside_a_segment_does_not_cross_colons():
    pattern = f"{LAMBDA}:*-prod"
    assert not match_resource(pattern, f"{LAMBDA}:billing:canary-prod")
    assert match_resource(pattern, f"{LAMBDA}:billing-prod")


def test_question_mark_does_not_match_a_colon():
    assert not match_resource("arn:aws:s3:::b?c", "arn:aws:s3:::b:c")
    assert match_resource("arn:aws:s3:::b?c", "arn:aws:s3:::bxc")


@pytest.mark.parametrize(
    "pattern, resource",
    [
        # A Lambda alias or version adds ":NAME" after the function name.
        (f"{LAMBDA}:*", f"{LAMBDA}:billing:canary"),
        (f"{LAMBDA}:billing*", f"{LAMBDA}:billing:canary"),
        # A log stream's ARN is its log group's ARN plus ":log-stream:NAME".
        (f"{LOGS}:/district/campus-01:*", f"{LOGS}:/district/campus-01:log-stream:web"),
        (f"{LOGS}:/district/campus-*", f"{LOGS}:/district/campus-01:log-stream:web"),
        # A * followed by a colon also ends a segment.
        ("arn:aws:logs:*:*:log-group:*:log-stream:web", f"{LOGS}:/district/campus-01:log-stream:web"),
        ("*", f"{LAMBDA}:billing:canary"),
    ],
)
def test_star_at_the_end_of_a_segment_crosses_colons(pattern, resource):
    assert match_resource(pattern, resource)


def test_action_wildcards_are_not_split_into_segments():
    assert match_action("*Object", "s3:GetObject")
    assert match_action("s3?GetObject", "s3:GetObject")


@pytest.mark.parametrize(
    "pattern, resource, expected",
    [
        ("arn:aws:s3", "arn:aws:s3:::district-student-records/2026/roster.csv", True),
        ("arn:aws:sqs", "arn:aws:sqs:us-east-1:111122223333:district-alerts", True),
        ("arn:aws:s3", "arn:aws:sqs:us-east-1:111122223333:district-alerts", False),
        # The fields that are given still have to match.
        ("arn:aws:s3:us-east-1", "arn:aws:s3:us-west-2:111122223333:accesspoint/x", False),
        ("arn:*", f"{LAMBDA}:billing:canary", True),
    ],
)
def test_incomplete_arns_are_completed_with_wildcards(pattern, resource, expected):
    assert match_resource(pattern, resource) is expected
