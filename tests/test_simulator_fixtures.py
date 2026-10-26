"""Replays the IAM policy simulator's recorded answers (tests/simulator_fixtures) against the
analyzer, without AWS. docs/simulator-check.md explains the cases and what AWS answered.

verdicts.json lists every case that doesn't simply agree, with the analyzer's answer today. A
change to the engine that affects one of them fails here until the entry and the doc are updated.
"""

import json

import pytest

from simulator_check import FIXTURE_DIR, outcomes, safety_problems

PATHS = sorted(FIXTURE_DIR.glob("*/*.json"))
FIXTURES = [json.loads(path.read_text()) for path in PATHS]
IDS = [fixture["case"] for fixture in FIXTURES]
VERDICTS = json.loads((FIXTURE_DIR / "verdicts.json").read_text())
LISTED = VERDICTS["cases"]
FORCED = outcomes.forced_verdicts(FIXTURES, VERDICTS["findings"])


def ours(fixture):
    return outcomes.ours(fixture["simulate"]["request"], fixture["absent"]).label


@pytest.mark.parametrize("fixture", FIXTURES, ids=IDS)
def test_the_analyzer_gives_the_simulators_answer(fixture):
    entry = LISTED.get(fixture["case"])
    if entry is None:
        assert ours(fixture) == outcomes.aws(fixture).label
    else:
        assert ours(fixture) == entry["analyzer"], "the analyzer's answer changed: update the doc"


def test_the_findings_come_from_the_fixtures():
    assert VERDICTS["findings"] == outcomes.findings(FIXTURES)


def test_the_findings_set_verdicts_even_when_the_answers_match():
    # So that a lucky match never counts as agreement.
    for case, verdict in FORCED.items():
        assert LISTED.get(case, {}).get("verdict") == verdict, case


def test_scp_allow_probes_that_differ_are_possible_simulator_limits():
    for fixture in FIXTURES:
        case = fixture["case"]
        if case.startswith(f"{outcomes.SCP_ALLOW_GROUP}/") and case not in FORCED:
            if ours(fixture) != outcomes.aws(fixture).label:
                assert LISTED[case]["verdict"] == outcomes.POSSIBLE_SIMULATOR_LIMIT, case


def test_a_limit_read_from_aws_docs_quotes_them():
    for case, entry in LISTED.items():
        from_docs = entry["verdict"] == outcomes.POSSIBLE_SIMULATOR_LIMIT or (
            entry["verdict"] == outcomes.SIMULATOR_LIMIT and case not in FORCED
        )
        if from_docs:
            assert entry.get("quote"), case
            assert entry.get("link", "").startswith("https://docs.aws.amazon.com/"), case


def test_every_listed_case_still_needs_its_entry():
    # Inconclusive cases and simulator limits stay listed even when the two answers match. The
    # other verdicts say the answers differ, so an entry whose answers now match is stale.
    recorded = {fixture["case"]: fixture for fixture in FIXTURES}
    differing = (outcomes.DIFFERS, outcomes.ANALYZER_REFUSES, outcomes.POSSIBLE_SIMULATOR_LIMIT)
    for case, entry in LISTED.items():
        assert case in recorded, f"{case} has no fixture"
        assert entry["verdict"] in outcomes.VERDICTS, case
        fixture = recorded[case]
        if entry["verdict"] in differing:
            assert ours(fixture) != outcomes.aws(fixture).label, f"{case} agrees: unlist it"
        if entry["verdict"] == outcomes.ANALYZER_REFUSES:
            assert entry["analyzer"] in ("refused", "rejected"), case


@pytest.mark.parametrize("fixture", FIXTURES, ids=IDS)
def test_both_sides_got_every_key_the_policies_use(fixture):
    given = {e["ContextKeyName"].casefold() for e in fixture["simulate"]["request"].get("ContextEntries", [])}
    absent = {key.casefold() for key in fixture["absent"]}
    assert {key.casefold() for key in outcomes.listed_keys(fixture)} <= given | absent
    assert {key.casefold() for key in outcomes.missing_context_values(fixture)} <= absent


@pytest.mark.parametrize("path", PATHS, ids=IDS)
def test_fixtures_are_safe_to_publish(path):
    assert safety_problems(path.read_text()) == []
