import dataclasses
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


def test_via_group_is_carried_into_reasons():
    direct = policy("Direct", allow("s3:GetObject", OBJECT))
    inherited = dataclasses.replace(policy("Shared", allow("s3:*", "*")), via_group="Teachers")
    result = evaluate(GET, [direct, inherited])
    assert [(r.policy_name, r.via_group) for r in result.reasons] == [
        ("Direct", None),
        ("Shared", "Teachers"),
    ]


# --- NotAction / NotResource -----------------------------------------------------------


def statement(effect, sid=None, **elements):
    return {"Sid": sid, "Effect": effect, **elements}


def test_allow_not_action_allows_everything_except_listed():
    p = policy("p", statement("Allow", NotAction="s3:Delete*", Resource="*"))
    assert evaluate(GET, [p]).decision is Decision.ALLOW
    delete = Request(action="s3:DeleteObject", resource=OBJECT)
    assert evaluate(delete, [p]).decision is Decision.IMPLICIT_DENY


def test_deny_not_action_guardrail_blocks_everything_except_listed():
    guardrail = statement(
        "Deny", sid="ReadOnly", NotAction=["s3:Get*", "s3:List*"], Resource=f"{BUCKET}/*"
    )
    policies = [policy("p", allow("s3:*", "*"), guardrail)]
    assert evaluate(GET, policies).decision is Decision.ALLOW
    put = Request(action="s3:PutObject", resource=OBJECT)
    result = evaluate(put, policies)
    assert result.decision is Decision.EXPLICIT_DENY
    assert [r.statement.sid for r in result.reasons] == ["ReadOnly"]


def test_deny_not_action_only_applies_to_its_resource():
    guardrail = statement("Deny", NotAction="s3:Get*", Resource=f"{BUCKET}/*")
    put_elsewhere = Request(action="s3:PutObject", resource="arn:aws:s3:::other/file")
    p = policy("p", allow("s3:*", "*"), guardrail)
    assert evaluate(put_elsewhere, [p]).decision is Decision.ALLOW


def test_allow_not_resource_allows_everywhere_except_listed():
    p = policy("p", statement("Allow", Action="s3:GetObject", NotResource=f"{BUCKET}/*"))
    assert evaluate(GET, [p]).decision is Decision.IMPLICIT_DENY
    other = Request(action="s3:GetObject", resource="arn:aws:s3:::other/file")
    assert evaluate(other, [p]).decision is Decision.ALLOW


def test_deny_not_resource_blocks_everywhere_except_listed():
    p = policy(
        "p",
        allow("s3:*", "*"),
        statement("Deny", Action="s3:*", NotResource=[BUCKET, f"{BUCKET}/*"]),
    )
    assert evaluate(GET, [p]).decision is Decision.ALLOW
    other = Request(action="s3:GetObject", resource="arn:aws:s3:::other/file")
    assert evaluate(other, [p]).decision is Decision.EXPLICIT_DENY


def test_not_action_with_not_resource():
    # Deny anything except reads, anywhere except the public bucket.
    p = policy(
        "p",
        allow("*", "*"),
        statement("Deny", NotAction="s3:Get*", NotResource="arn:aws:s3:::public/*"),
    )

    def decide(action, resource):
        return evaluate(Request(action=action, resource=resource), [p]).decision

    assert decide("s3:GetObject", OBJECT) is Decision.ALLOW  # read: excluded action
    assert decide("s3:PutObject", "arn:aws:s3:::public/x") is Decision.ALLOW  # excluded resource
    assert decide("s3:PutObject", OBJECT) is Decision.EXPLICIT_DENY  # neither excluded


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
