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
