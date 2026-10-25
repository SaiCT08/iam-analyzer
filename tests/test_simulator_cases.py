"""The simulator check's cases, and how they become AWS requests. Nothing here calls AWS."""

import json
import subprocess
import sys

import pytest

from simulator_check import REPO, outcomes, safety_problems
from simulator_check.cases import (
    PLACEHOLDER,
    SCENARIOS,
    Case,
    NotExpressible,
    load_cases,
    requests_for,
)

CASES = load_cases()
SCENARIO_CASES = [case for case in CASES if case.group == SCENARIOS]
READ = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::district-student-records/*"}
GET = {"action": "s3:GetObject", "resource": "arn:aws:s3:::district-student-records/2026/roster.csv"}
KWONG = "arn:aws:iam::111122223333:user/kwong"
CAMPUS_APP = "arn:aws:iam::111122223333:role/district/CampusApp"
# Built when the tests run, so that this file itself passes the safety scan.
OTHER_ACCOUNT = "9876543210" + "98"
ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documented example


def case(**definition):
    """A case reading a student record, with no resource-based policy unless it says otherwise."""
    fields = {"policies": {"p": {"Version": "2012-10-17", "Statement": [READ]}},
              "resource_policy": None, "request": GET, **definition}
    return Case("test/case", "tests/test_simulator_cases.py", fields)


def with_condition(condition, **definition):
    statement = {**READ, "Condition": condition}
    return case(policies={"p": {"Version": "2012-10-17", "Statement": [statement]}}, **definition)


def test_every_case_converts_or_says_why_not():
    refused = {}
    for each in CASES:
        try:
            requests_for(each)
        except NotExpressible as exc:
            refused[each.id] = str(exc)
    assert "trust policy" in refused["scenarios/trust_policy_naming_the_user_needs_no_identity_policy"]
    assert "management account" in refused["scenarios/scp_skips_management_account"]
    assert not any(case_id.partition("/")[0] != SCENARIOS for case_id in refused)


@pytest.mark.parametrize("scenario", SCENARIO_CASES, ids=[c.id for c in SCENARIO_CASES])
def test_a_scenario_keeps_its_answer_as_a_request(scenario):
    # The analyzer's side is rebuilt from the request, so a converter mistake would change it.
    try:
        requests = requests_for(scenario)
    except NotExpressible:
        pytest.skip("the simulator can't express it")
    answer = outcomes.ours(requests.simulate, requests.absent).label
    assert answer == scenario.definition["expected"]


def test_context_types_come_from_the_operators_that_read_the_keys():
    conditions = {
        "BoolIfExists": {"aws:MultiFactorAuthPresent": "true"},
        "IpAddress": {"aws:SourceIp": "203.0.113.0/24"},
        "DateLessThan": {"aws:CurrentTime": "2027-01-01T00:00:00Z"},
        "ForAnyValue:StringEquals": {"aws:TagKeys": "campus"},
        "NumericLessThan": {"s3:max-keys": "10"},
        "StringEquals": {"aws:PrincipalTag/campus": ["campus-01", "campus-02"]},
    }
    context = {
        "aws:MultiFactorAuthPresent": "true", "aws:SourceIp": "203.0.113.5",
        "aws:CurrentTime": "2026-10-25T00:00:00Z", "aws:TagKeys": "campus", "s3:max-keys": "5",
        "aws:PrincipalTag/campus": ["campus-01", "campus-02"],
    }
    simulate = requests_for(with_condition(conditions, context=context)).simulate
    assert {e["ContextKeyName"]: e["ContextKeyType"] for e in simulate["ContextEntries"]} == {
        "aws:MultiFactorAuthPresent": "boolean",
        "aws:SourceIp": "ip",
        "aws:CurrentTime": "date",
        "aws:TagKeys": "stringList",  # a set operator reads it
        "s3:max-keys": "numeric",
        "aws:PrincipalTag/campus": "stringList",  # the request gives it several values
    }


def test_a_key_the_analyzer_cant_type_needs_context_types():
    # The analyzer refuses a Bool value with a policy variable, so it can't read the key's type.
    bool_variable = {"Bool": {"aws:SecureTransport": "${aws:MultiFactorAuthPresent}"}}
    context = {"aws:SecureTransport": "true", "aws:MultiFactorAuthPresent": "true"}
    with pytest.raises(ValueError, match="give its type in context_types"):
        requests_for(with_condition(bool_variable, context=context))
    types = {"aws:SecureTransport": "boolean", "aws:MultiFactorAuthPresent": "boolean"}
    assert requests_for(with_condition(bool_variable, context=context, context_types=types))


def test_absent_keys_are_left_out_of_the_call():
    requests = requests_for(with_condition(
        {"StringNotEquals": {"aws:PrincipalTag/team": "blue"}}, context={"aws:PrincipalTag/team": None}
    ))
    assert "ContextEntries" not in requests.simulate
    assert requests.absent == ("aws:PrincipalTag/team",)


def test_every_key_a_policy_reads_must_be_given_or_absent():
    with pytest.raises(ValueError, match="doesn't give aws:principaltag/team"):
        requests_for(with_condition({"StringEquals": {"aws:PrincipalTag/team": "blue"}}))


def test_a_case_without_identity_policies_gets_the_placeholder():
    simulate = requests_for(case(policies={})).simulate
    assert [json.loads(text) for text in simulate["PolicyInputList"]] == [PLACEHOLDER]


def test_scp_levels_run_from_the_root_to_the_account():
    [scenario] = [c for c in SCENARIO_CASES if c.id == "scenarios/scp_deny_beats_admin"]
    levels = requests_for(scenario).simulate["OrderedOrganizationPolicyInputList"]
    effects = [
        [json.loads(text)["Statement"][0]["Effect"] for text in level["ServiceControlPolicyInputList"]]
        for level in levels
    ]
    assert effects == [["Allow"], ["Allow", "Deny"], ["Allow"]]  # root, OU Schools, the account


def test_the_caller_is_always_sent():
    assert requests_for(case()).simulate["CallerArn"] == "arn:aws:iam::111122223333:user/jsmith"
    named = case(context={"aws:PrincipalArn": KWONG})
    assert requests_for(named).simulate["CallerArn"] == KWONG
    with pytest.raises(ValueError, match="disagree"):
        requests_for(case(caller=CAMPUS_APP, context={"aws:PrincipalArn": KWONG}))


@pytest.mark.parametrize(
    "caller, context",
    [
        (KWONG, {"aws:username": "alee"}),  # not the caller's name
        (KWONG, {"aws:username": None}),  # a user always has one
        (CAMPUS_APP, {"aws:username": "CampusApp"}),  # AWS doesn't say what it fills in for a role
        (KWONG, {"aws:PrincipalAccount": "444455556666"}),
        (KWONG, {"aws:userid": "AIDAEXAMPLE"}),
    ],
)
def test_keys_the_simulator_fills_in_must_agree_with_the_caller(caller, context):
    with pytest.raises(NotExpressible, match="the simulator fills in"):
        requests_for(case(caller=caller, context=context))


def test_the_resource_owner_must_be_the_callers_account():
    same = case(resource_owner="arn:aws:iam::111122223333:root")
    assert requests_for(same).simulate["ResourceOwner"] == "arn:aws:iam::111122223333:root"
    with pytest.raises(NotExpressible, match="cross-account"):
        requests_for(case(resource_owner="arn:aws:iam::444455556666:root"))


def test_a_session_caller_cant_be_expressed():
    session = "arn:aws:sts::111122223333:assumed-role/CampusApp/nightly-export"
    with pytest.raises(NotExpressible, match="assumed role"):
        requests_for(case(caller=session))


def test_only_example_account_ids_are_sent():
    with pytest.raises(ValueError, match="aren't AWS's examples"):
        requests_for(case(caller=f"arn:aws:iam::{OTHER_ACCOUNT}:user/kwong"))


def test_the_safety_scan():
    # A request ID is a UUID, and its last group can be 12 digits by chance.
    assert safety_problems('"RequestId": "1cdb5b0a-4c15-11e5-b121-987654321098"') == []
    assert safety_problems("arn:aws:iam::111122223333:user/jsmith") == []
    assert safety_problems(f"arn:aws:iam::{OTHER_ACCOUNT}:user/jsmith") == [
        "1 account ID(s) that aren't AWS's examples"
    ]
    assert safety_problems(f"key {ACCESS_KEY_ID}") == ["an access key ID"]


def test_only_the_recorder_needs_boto3():
    # A fresh interpreter, so that nothing else this test run imported can hide an import.
    offline = "simulator_check.cases, simulator_check.outcomes, simulator_check.report"
    code = f"import sys, {offline}; assert 'boto3' not in sys.modules"
    subprocess.run([sys.executable, "-c", code], check=True, cwd=REPO)
