import pytest

from iam_analyzer.context import RequestContext
from iam_analyzer.errors import MissingContextError, RequestError


def test_values_absent_and_unknown_keys():
    context = RequestContext.of([("aws:SourceIp", "203.0.113.5")], ["aws:MultiFactorAuthPresent"])
    assert context.get("aws:SourceIp") == ("203.0.113.5",)
    assert context.get("aws:MultiFactorAuthPresent") is None  # absent: the request lacks it
    assert context.knows("aws:SourceIp") and context.knows("aws:MultiFactorAuthPresent")
    assert not context.knows("aws:username")
    with pytest.raises(MissingContextError) as exc:
        context.get("aws:username")  # unknown: nobody said
    assert exc.value.keys == ("aws:username",)


def test_key_names_are_case_insensitive():
    context = RequestContext.of([("aws:SourceIp", "203.0.113.5")], ["aws:MultiFactorAuthPresent"])
    assert context.get("AWS:sourceip") == ("203.0.113.5",)
    assert context.get("aws:multifactorauthpresent") is None


def test_repeating_a_key_gives_it_several_values():
    context = RequestContext.of([("aws:TagKeys", "campus"), ("AWS:tagkeys", "grade")])
    assert context.get("aws:TagKeys") == ("campus", "grade")


def test_an_empty_string_is_a_value():
    # A request that lists a bucket's top level has s3:prefix "".
    assert RequestContext.of([("s3:prefix", "")]).get("s3:prefix") == ("",)


def test_an_empty_context_knows_nothing():
    assert not RequestContext().knows("aws:SourceIp")


@pytest.mark.parametrize(
    "values, absent, message",
    [
        ([("SourceIp", "203.0.113.5")], [], "'SourceIp' is not a condition key"),
        ([], [":x"], "':x' is not a condition key"),
        ([("aws:SourceIp", 5)], [], "values must be strings"),
        ([("aws:SourceIp", "203.0.113.5")], ["AWS:SourceIp"], "both have a value and be absent"),
    ],
)
def test_invalid_contexts(values, absent, message):
    with pytest.raises(RequestError, match=message):
        RequestContext.of(values, absent)


def test_absent_prefix_covers_a_family_of_keys():
    context = RequestContext.of(
        [("aws:PrincipalTag/campus", "campus-01")], absent_prefixes=["aws:PrincipalTag/"]
    )
    assert context.get("aws:PrincipalTag/campus") == ("campus-01",)
    assert context.get("aws:principaltag/grade") is None
    assert not context.knows("aws:RequestTag/grade")


def test_a_present_key_still_needs_a_value():
    context = RequestContext.of(present={"aws:PrincipalTag/campus": "it is always there"})
    assert not context.knows("aws:PrincipalTag/campus")
    with pytest.raises(MissingContextError):
        context.get("aws:PrincipalTag/campus")


# --- Merging the principal's keys with the caller's -------------------------------------

PRINCIPAL = RequestContext.of(
    [("aws:username", "jsmith")],
    absent_prefixes=["aws:PrincipalTag/"],
    source="acct.json user/jsmith",
)


def test_merging_contexts_about_different_keys():
    merged = PRINCIPAL.merged(RequestContext.of([("aws:SourceIp", "203.0.113.5")], ["aws:Referer"]))
    assert merged.get("aws:username") == ("jsmith",)
    assert merged.get("aws:SourceIp") == ("203.0.113.5",)
    assert merged.get("aws:Referer") is None
    assert merged.get("aws:PrincipalTag/campus") is None


@pytest.mark.parametrize(
    "caller",
    [
        RequestContext.of([("AWS:Username", "bob")]),
        RequestContext.of(absent=["aws:username"]),
        RequestContext.of([("aws:PrincipalTag/campus", "campus-01")]),  # under the absent family
    ],
)
def test_the_caller_cannot_change_keys_the_principal_sets(caller):
    with pytest.raises(RequestError, match="comes from acct.json user/jsmith"):
        PRINCIPAL.merged(caller)


def test_a_present_key_cannot_be_made_absent_but_can_get_a_value():
    principal = RequestContext.of(present={"aws:PrincipalTag/campus": "the role has this tag"})
    with pytest.raises(RequestError, match="'aws:principaltag/CAMPUS' can't be absent: the role"):
        principal.merged(RequestContext.of(absent=["aws:principaltag/CAMPUS"]))
    merged = principal.merged(RequestContext.of([("aws:PrincipalTag/campus", "campus-02")]))
    assert merged.get("aws:PrincipalTag/campus") == ("campus-02",)
