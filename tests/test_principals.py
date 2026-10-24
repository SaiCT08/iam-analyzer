import pytest

from iam_analyzer.context import RequestContext
from iam_analyzer.errors import RequestError, UnsupportedPolicyFeature
from iam_analyzer.models import Principal, PrincipalMatch, PrincipalType
from iam_analyzer.principals import caller, match, needs_caller, parse, strongest

KWONG = "arn:aws:iam::111122223333:user/counselors/kwong"
APP = "arn:aws:iam::111122223333:role/district/CampusApp"


def calling(arn):
    return RequestContext.of([("aws:PrincipalArn", arn)])


def aws(*values):
    return tuple(Principal(PrincipalType.AWS, value) for value in values)


def test_parse_reads_each_type_in_order():
    raw = {"AWS": ["111122223333", KWONG], "Service": "s3.amazonaws.com",
           "Federated": "accounts.google.com"}
    assert parse(raw, "p") == (
        *aws("111122223333", KWONG),
        Principal(PrincipalType.SERVICE, "s3.amazonaws.com"),
        Principal(PrincipalType.FEDERATED, "accounts.google.com"),
    )


def test_the_caller_comes_from_aws_principal_arn():
    user = caller(calling(KWONG))
    assert (user.partition, user.account) == ("aws", "111122223333")
    assert (user.kind, user.name) == ("user", "kwong")
    role = caller(calling(APP))
    assert (role.kind, role.name) == ("role", "CampusApp")


@pytest.mark.parametrize(
    "arn, error, message",
    [
        ("arn:aws:iam::111122223333:root", UnsupportedPolicyFeature, "IAM users and role sessions"),
        ("arn:aws:sts::111122223333:federated-user/bob", UnsupportedPolicyFeature, "IAM users"),
        ("arn:aws:sts::111122223333:assumed-role/App/s1", UnsupportedPolicyFeature, "IAM users"),
    ],
)
def test_callers_the_analyzer_doesnt_model(arn, error, message):
    with pytest.raises(error, match=message):
        caller(calling(arn))


def test_an_anonymous_or_ambiguous_caller_is_refused():
    with pytest.raises(RequestError, match="needs exactly one value"):
        caller(RequestContext.of(absent=["aws:PrincipalArn"]))
    with pytest.raises(RequestError, match="needs exactly one value"):
        caller(RequestContext.of([("aws:PrincipalArn", KWONG), ("aws:PrincipalArn", APP)]))


@pytest.mark.parametrize(
    "principals, arn, expected",
    [
        (aws("*"), KWONG, PrincipalMatch.EVERYONE),
        (aws(KWONG), KWONG, PrincipalMatch.USER),
        (aws(APP), APP, PrincipalMatch.ROLE),
        (aws("111122223333"), KWONG, PrincipalMatch.ACCOUNT),
        (aws("arn:aws:iam::111122223333:root"), APP, PrincipalMatch.ACCOUNT),
        # Another partition's account with the same ID is another account.
        (aws("arn:aws-us-gov:iam::111122223333:root"), KWONG, None),
        (aws("444455556666"), KWONG, None),
        # A user ARN must match exactly, path and case included.
        (aws("arn:aws:iam::111122223333:user/kwong"), KWONG, None),
        (aws("arn:aws:iam::111122223333:user/counselors/Kwong"), KWONG, None),
        # A role ARN never names a user, and a user ARN never names a role's session.
        (aws(APP), KWONG, None),
        (aws(KWONG), APP, None),
        (aws("arn:aws:sts::111122223333:federated-user/kwong"), KWONG, None),
        ((Principal(PrincipalType.SERVICE, "s3.amazonaws.com"),), APP, None),
        ((Principal(PrincipalType.FEDERATED, "accounts.google.com"),), APP, None),
        # The strongest match counts: a direct one, then the role, then the account.
        (aws("111122223333", APP), APP, PrincipalMatch.ROLE),
        (aws("111122223333", KWONG), KWONG, PrincipalMatch.USER),
        (aws(APP, "*"), APP, PrincipalMatch.EVERYONE),
    ],
)
def test_how_principals_name_the_caller(principals, arn, expected):
    assert match(principals, calling(arn), deny=False) is expected


@pytest.mark.parametrize(
    "principal, arn, message",
    [
        (aws("arn:aws:sts::111122223333:assumed-role/CampusApp/nightly"), APP, "session's name"),
        (aws("arn:aws:iam::111122223333:role/district/campusapp"), APP, "if case is ignored"),
        (aws("AROADBQP57FF2AEXAMPLE"), APP, "IAM unique ID"),
        ((Principal(PrincipalType.CANONICAL_USER, "79a59df900b949e5"),), KWONG, "canonical"),
    ],
)
def test_principals_the_account_file_cant_settle(principal, arn, message):
    with pytest.raises(UnsupportedPolicyFeature, match=message):
        match(principal, calling(arn), deny=False)


def test_a_refused_principal_is_moot_once_another_settles_the_statement():
    canonical = Principal(PrincipalType.CANONICAL_USER, "79a59df900b949e5")
    # An Allow needs the strongest match, so only a direct one settles it.
    assert match((*aws(KWONG), canonical), calling(KWONG), deny=False) is PrincipalMatch.USER
    with pytest.raises(UnsupportedPolicyFeature):
        match((*aws("111122223333"), canonical), calling(KWONG), deny=False)
    # A Deny applies on any match.
    assert match((*aws("111122223333"), canonical), calling(KWONG), deny=True) is (
        PrincipalMatch.ACCOUNT
    )


def test_sessions_of_other_roles_dont_name_the_caller():
    other = aws("arn:aws:sts::111122223333:assumed-role/OtherApp/nightly")
    assert match(other, calling(APP), deny=False) is None


def test_only_star_needs_no_caller():
    assert not needs_caller(aws("*"))
    assert not needs_caller((Principal(PrincipalType.SERVICE, "s3.amazonaws.com"),))
    assert needs_caller(aws("*", "111122223333"))
    # So "*" matches with nothing known about the caller.
    assert match(aws("*"), RequestContext(), deny=False) is PrincipalMatch.EVERYONE


def test_strongest():
    assert strongest([None, PrincipalMatch.ACCOUNT, PrincipalMatch.ROLE]) is PrincipalMatch.ROLE
    assert strongest([PrincipalMatch.ROLE, PrincipalMatch.USER]) is PrincipalMatch.USER
    assert strongest([None]) is None
    assert strongest([]) is None
