import pytest

from iam_analyzer.errors import RequestError, UnsupportedPolicyFeature
from iam_analyzer.models import Resource
from iam_analyzer.resources import account_of, describe, governing_arn

BUCKET = "arn:aws:s3:::district-student-records"
ROLE = "arn:aws:iam::111122223333:role/ITAdmin"
QUEUE = "arn:aws:sqs:us-east-1:111122223333:district-alerts"


@pytest.mark.parametrize(
    "resource, action, expected",
    [
        # "*" names no resource.
        ("*", "s3:ListAllMyBuckets", None),
        # A bucket policy covers the bucket and its objects.
        (BUCKET, "s3:ListBucket", BUCKET),
        (f"{BUCKET}/2026/roster.csv", "s3:GetObject", BUCKET),
        (f"{BUCKET}/", "s3:PutObject", BUCKET),
        # The only IAM resource-based policy is a role's trust policy, for the STS actions on it.
        ("arn:aws:iam::111122223333:user/jsmith", "iam:ChangePassword", None),
        (ROLE, "iam:GetRole", None),
        (ROLE, "sts:AssumeRole", ROLE),
        (ROLE, "STS:tagsession", ROLE),  # actions ignore case
        ("arn:aws:iam::111122223333:role/district/App", "sts:SetSourceIdentity",
         "arn:aws:iam::111122223333:role/district/App"),
        # STS resources have no resource-based policies.
        ("arn:aws:sts::111122223333:federated-user/bob", "sts:GetFederationToken", None),
        # Every other service's resource needs describing itself.
        (QUEUE, "sqs:SendMessage", QUEUE),
        ("arn:aws:ec2:us-east-1:111122223333:instance/i-0abc", "ec2:CreateTags",
         "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc"),
        ("arn:aws:kms:us-east-1:111122223333:alias/records", "kms:CreateAlias",
         "arn:aws:kms:us-east-1:111122223333:alias/records"),
    ],
)
def test_which_resource_a_request_needs_described(resource, action, expected):
    assert governing_arn(resource, action) == expected


@pytest.mark.parametrize(
    "resource, action, error, message",
    [
        (
            "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "kms:Decrypt",
            UnsupportedPolicyFeature,
            "KMS isn't supported yet: every KMS key has a key policy that must allow the request",
        ),
        (
            "arn:aws:s3:us-east-1:111122223333:accesspoint/records",
            "s3:GetObject",
            UnsupportedPolicyFeature,
            "S3 resources other than buckets and objects, such as access points",
        ),
        ("arn:aws:s3:::district-*/roster.csv", "s3:GetObject", RequestError, "name one resource"),
        ("arn:aws:sqs:us-east-1:111122223333:alerts-?", "sqs:SendMessage", RequestError, "one"),
        ("arn:aws:iam::111122223333:role/*", "sts:AssumeRole", RequestError, "name one resource"),
        ("arn:aws:s3:::/roster.csv", "s3:GetObject", RequestError, "names no bucket"),
        ("roster.csv", "s3:GetObject", RequestError, 'must be "\\*" or a full ARN'),
        ("arn:aws:s3", "s3:GetObject", RequestError, "a full ARN"),
    ],
)
def test_resources_the_analyzer_refuses(resource, action, error, message):
    with pytest.raises(error, match=message):
        governing_arn(resource, action)


def test_wildcards_in_an_iam_resource_need_no_description():
    # Only a role, for the STS actions on it, can need describing.
    assert governing_arn("arn:aws:iam::111122223333:user/*", "iam:ListAccessKeys") is None


def test_describe_says_the_resource_has_no_resource_based_policy():
    assert describe(f"{BUCKET}/2026/roster.csv", "s3:GetObject") == Resource(BUCKET)
    assert describe(QUEUE, "sqs:SendMessage") == Resource(QUEUE)
    assert describe("arn:aws:iam::111122223333:user/jsmith", "iam:ChangePassword") is None


@pytest.mark.parametrize(
    "resource, expected",
    [
        ("arn:aws:iam::111122223333:user/jsmith", "111122223333"),
        ("arn:aws:sqs:us-east-1:012345678901:alerts", "012345678901"),
        (BUCKET, None),  # S3 ARNs name no account
        ("arn:aws:iam::aws:policy/ReadOnlyAccess", None),
        ("*", None),
    ],
)
def test_account_of(resource, expected):
    assert account_of(resource) == expected
