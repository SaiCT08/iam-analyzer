import pytest

from iam_analyzer.context import RequestContext
from iam_analyzer.errors import MissingContextError, PolicyParseError, UnsupportedPolicyFeature
from iam_analyzer.matching import match_resource
from iam_analyzer.variables import Literal, Variable, keys, parse, resolve

HOME = "arn:aws:s3:::district-staff-files/home/"
JSMITH = RequestContext.of([("aws:username", "jsmith")], ["aws:PrincipalTag/team"])


def test_parse_splits_text_variables_and_literals():
    assert parse(f"{HOME}${{aws:username}}/*") == (HOME, Variable("aws:username"), "/*")
    assert parse("a${*}b${?}c${$}") == ("a", Literal("*"), "b", Literal("?"), "c", Literal("$"))
    assert parse("${aws:PrincipalTag/team, 'company-wide'}") == (
        Variable("aws:PrincipalTag/team", "company-wide"),
    )
    assert parse("no variables") == ("no variables",)


def test_keys_lists_what_the_variables_read():
    template = parse("${aws:username}-${aws:PrincipalTag/team, 'x'}-${*}")
    assert keys(template) == ["aws:username", "aws:PrincipalTag/team"]


@pytest.mark.parametrize(
    "text",
    [
        "${}",
        "${aws:username",  # never closed
        "${username}",  # no service prefix
        "${ aws:username}",
        "${aws:PrincipalTag/team,'x'}",  # AWS documents a comma and a space
        '${aws:PrincipalTag/team, "x"}',  # and single quotes
    ],
)
def test_malformed_variables_are_refused(text):
    with pytest.raises(PolicyParseError, match="malformed policy variable"):
        parse(text)


def test_a_wildcard_in_a_default_is_refused():
    with pytest.raises(UnsupportedPolicyFeature, match="contains \\* or \\?"):
        parse("${aws:PrincipalTag/team, 'team-*'}")


def test_resolve_fills_in_values_and_defaults():
    assert resolve(parse(f"{HOME}${{aws:username}}/*"), JSMITH) == (
        (HOME, False),
        ("jsmith", True),
        ("/*", False),
    )
    # aws:PrincipalTag/team is absent, so the default is used.
    assert resolve(parse("${aws:PrincipalTag/team, 'company-wide'}"), JSMITH) == (
        ("company-wide", True),
    )


def test_variable_names_are_case_insensitive():
    assert resolve(parse("${AWS:UserName}"), JSMITH) == (("jsmith", True),)


def test_a_literal_star_only_matches_a_star():
    pattern = resolve(parse("arn:aws:s3:::district-uploads/${*}"), JSMITH)
    assert match_resource(pattern, "arn:aws:s3:::district-uploads/*")
    assert not match_resource(pattern, "arn:aws:s3:::district-uploads/report.csv")


def test_an_unknown_key_is_missing_context():
    with pytest.raises(MissingContextError) as exc:
        resolve(parse("${aws:userid}"), JSMITH)
    assert exc.value.keys == ("aws:userid",)


@pytest.mark.parametrize(
    "context, message",
    [
        (RequestContext.of(absent=["aws:username"]), "has no value in this request"),
        (RequestContext.of([("aws:username", "a"), ("aws:username", "b")]), "several values"),
        (RequestContext.of([("aws:username", "j*")]), "contains \\* or \\?"),
    ],
)
def test_values_aws_does_not_define_are_refused(context, message):
    with pytest.raises(UnsupportedPolicyFeature, match=message):
        resolve(parse(f"{HOME}${{aws:username}}/*"), context)
