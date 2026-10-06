import itertools
import json
from pathlib import Path

import pytest

from iam_analyzer.evaluator import evaluate
from iam_analyzer.loader import parse_policy
from iam_analyzer.models import Decision, Request

BUCKET = "arn:aws:s3:::district-student-records"
OBJECT = f"{BUCKET}/2026/roster.csv"
GET = Request(action="s3:GetObject", resource=OBJECT)


def policy(name, *statements):
    return parse_policy({"Statement": list(statements)}, name=name)


def allow(action, resource, sid=None):
    return {"Sid": sid, "Effect": "Allow", "Action": action, "Resource": resource}


def deny(action, resource, sid=None):
    return {"Sid": sid, "Effect": "Deny", "Action": action, "Resource": resource}


def test_no_policies_is_implicit_deny():
    result = evaluate(GET, [])
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.reasons == ()
    assert not result.allowed


def test_matching_allow():
    result = evaluate(GET, [policy("p", allow("s3:GetObject", OBJECT, sid="A"))])
    assert result.decision is Decision.ALLOW
    assert result.allowed
    assert [(r.policy_name, r.statement.sid) for r in result.reasons] == [("p", "A")]


@pytest.mark.parametrize(
    "statement",
    [
        allow("s3:PutObject", OBJECT),  # wrong action
        allow("s3:GetObject", f"{BUCKET}-archive/*"),  # wrong resource
        allow("s3:GetObject", BUCKET),  # bucket ARN, not object ARN
    ],
)
def test_allow_for_something_else_is_implicit_deny(statement):
    assert evaluate(GET, [policy("p", statement)]).decision is Decision.IMPLICIT_DENY


def test_action_and_resource_must_both_match_in_the_same_statement():
    # One statement allows the action elsewhere, another allows a different action here.
    p = policy("p", allow("s3:GetObject", "arn:aws:s3:::other/*"), allow("s3:PutObject", OBJECT))
    assert evaluate(GET, [p]).decision is Decision.IMPLICIT_DENY


def test_wildcard_allow():
    p = policy("p", allow("s3:Get*", f"{BUCKET}/*"))
    assert evaluate(GET, [p]).decision is Decision.ALLOW


def test_any_entry_in_action_and_resource_lists_can_match():
    p = policy("p", allow(["ec2:*", "s3:GetObject"], ["arn:aws:s3:::other/*", f"{BUCKET}/*"]))
    assert evaluate(GET, [p]).decision is Decision.ALLOW


def test_explicit_deny_beats_allow_in_any_order():
    statements = [allow("s3:*", "*", sid="AllowAll"), deny("s3:GetObject", OBJECT, sid="NoGet")]
    for ordering in itertools.permutations(statements):
        # Same policy, both orders.
        assert evaluate(GET, [policy("p", *ordering)]).decision is Decision.EXPLICIT_DENY
        # Separate policies, both orders.
        policies = [policy(f"p{i}", s) for i, s in enumerate(ordering)]
        assert evaluate(GET, policies).decision is Decision.EXPLICIT_DENY


def test_explicit_deny_reasons_list_only_denies():
    policies = [
        policy("allow.json", allow("s3:*", "*", sid="AllowAll")),
        policy("deny.json", deny("s3:Get*", f"{BUCKET}/*", sid="NoGet")),
    ]
    result = evaluate(GET, policies)
    assert [(r.policy_name, r.statement.sid) for r in result.reasons] == [("deny.json", "NoGet")]


def test_deny_alone_is_explicit_deny():
    result = evaluate(GET, [policy("p", deny("*", "*"))])
    assert result.decision is Decision.EXPLICIT_DENY


def test_non_matching_deny_does_not_block_allow():
    p = policy("p", allow("s3:*", "*"), deny("s3:DeleteObject", f"{BUCKET}/*"))
    assert evaluate(GET, [p]).decision is Decision.ALLOW


def test_all_matching_allows_are_reported():
    policies = [
        policy("a.json", allow("s3:GetObject", OBJECT, sid="One")),
        policy("b.json", allow("s3:*", "*", sid="Two")),
    ]
    result = evaluate(GET, policies)
    assert [r.statement.sid for r in result.reasons] == ["One", "Two"]


# --- Data-driven scenarios -------------------------------------------------------------

SCENARIO_DIR = Path(__file__).parent / "scenarios"
SCENARIOS = sorted(SCENARIO_DIR.glob("*.json"))


@pytest.mark.parametrize("path", SCENARIOS, ids=[p.stem for p in SCENARIOS])
def test_scenario(path):
    scenario = json.loads(path.read_text())
    policies = [parse_policy(doc, name=name) for name, doc in scenario["policies"].items()]
    request = Request(**scenario["request"])
    result = evaluate(request, policies)
    assert result.decision is Decision(scenario["expected"]), scenario.get("description")
