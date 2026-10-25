"""Both sides' answers for a recorded fixture, and what the calibration cases say about the simulator.

The analyzer's side is rebuilt from the request AWS was sent, not from the case file. That way both
sides read the same policy text, and a fixture keeps working if the cases or the converter change.
What the request can't say is in the fixture: the keys the case marks absent.

The verdicts for the cases that don't agree live in tests/simulator_fixtures/verdicts.json. Two
findings from the calibration cases set some of them, whatever the two answers are (see
`forced_verdicts`), so that a lucky match never counts as agreement.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from iam_analyzer import _validation, resources
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import (
    MissingContextError,
    MissingResourceError,
    PolicyParseError,
    RequestError,
    UnsupportedPolicyFeature,
)
from iam_analyzer.evaluator import evaluate
from iam_analyzer.loader import load_policy
from iam_analyzer.models import EvaluationResult, OrgTarget, Request, ScpLevel, TargetType
from simulator_check import Caller

DECISIONS = {"allowed": "ALLOW", "explicitDeny": "EXPLICIT_DENY", "implicitDeny": "IMPLICIT_DENY"}
# AWS's errors for a policy it won't accept, the same answer as the analyzer's "rejected".
AWS_REJECTS = ("InvalidInput", "MalformedPolicyDocument")

# How the simulator treats a key left out of the call.
ACT_AS_ABSENT = "act as absent"
ALWAYS_IMPLICIT_DENY = "always implicit deny"
MIXED = "mixed"
# Whether the simulator uses a resource-based policy when the caller is a role.
EVALUATED = "evaluated"
NEVER_MATCHED = "never matched"

# The verdicts, highest priority first. A case that verdicts.json doesn't list agrees.
INCONCLUSIVE = "inconclusive"
SIMULATOR_LIMIT = "simulator limit"
POSSIBLE_SIMULATOR_LIMIT = "possible simulator limit"
ANALYZER_REFUSES = "analyzer refuses"
DIFFERS = "differs"
VERDICTS = (INCONCLUSIVE, SIMULATOR_LIMIT, POSSIBLE_SIMULATOR_LIMIT, ANALYZER_REFUSES, DIFFERS)
# The probes of SCP Allow statements. The User Guide says the simulator evaluates "resource
# scoping in deny statements", so where they differ from the analyzer, it may be a simulator limit.
SCP_ALLOW_GROUP = "scp_allow_statements"


@dataclass(frozen=True)
class Outcome:
    """One side's answer.

    `label` is ALLOW, EXPLICIT_DENY or IMPLICIT_DENY; "refused" when the analyzer won't evaluate
    the case; "rejected" when the analyzer or AWS won't accept a policy; "request error"; or
    "AWS error CODE".
    """

    label: str
    detail: str = ""


def ours(request: dict[str, Any], absent: Sequence[str] = ()) -> Outcome:
    """The analyzer's answer to a SimulateCustomPolicy request, with the `absent` keys absent."""
    try:
        result = _evaluate(request, absent)
    except (MissingContextError, MissingResourceError):
        raise  # the case left something out: a harness bug, not an answer
    except UnsupportedPolicyFeature as exc:
        return Outcome("refused", str(exc))
    except PolicyParseError as exc:
        return Outcome("rejected", str(exc))
    except RequestError as exc:
        return Outcome("request error", str(exc))
    return Outcome(result.decision.value)


def aws(fixture: dict[str, Any]) -> Outcome:
    """The simulator's answer in a fixture."""
    call = fixture["simulate"]
    if call["error"] is not None:
        code = call["error"].get("Code", "")
        label = "rejected" if code in AWS_REJECTS else f"AWS error {code}"
        return Outcome(label, call["error"].get("Message", ""))
    [result] = call["response"]["EvaluationResults"]
    decision = result["EvalDecision"]
    for specific in result.get("ResourceSpecificResults", []):
        if specific["EvalResourceDecision"] != decision:
            raise ValueError(f"{fixture['case']}: the resource's decision isn't the overall one")
    return Outcome(DECISIONS[decision])


def missing_context_values(fixture: dict[str, Any]) -> list[str]:
    """The keys AWS says the simulation lacked, overall and for the resource."""
    return sorted({key for result in _results(fixture) for key in result.get("MissingContextValues", [])})


def matched_sources(fixture: dict[str, Any]) -> list[str]:
    """Which policies the statements AWS says decided the answer come from, such as
    "PolicyInputList.1" or "ResourcePolicy"."""
    return sorted({
        statement.get("SourcePolicyId", "?")
        for result in _results(fixture)
        for statement in result.get("MatchedStatements", [])
    })


def listed_keys(fixture: dict[str, Any]) -> list[str]:
    """The keys GetContextKeysForCustomPolicy says the case's policies use."""
    return sorted({
        key
        for call in fixture["context_keys"]
        if call["response"] is not None
        for key in call["response"].get("ContextKeyNames", [])
    })


def details(fixture: dict[str, Any]) -> dict[str, bool]:
    """What AWS says about the boundary and the SCPs, when it says anything."""
    results = _results(fixture)
    if not results:
        return {}
    found = {}
    for detail, name in (
        ("PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary"),
        ("OrganizationsDecisionDetail", "AllowedByOrganizations"),
    ):
        if detail in results[0]:
            found[name] = results[0][detail].get(name)
    return found


def role_caller_with_resource_policy(fixture: dict[str, Any]) -> bool:
    """Whether the case gives the simulator a resource-based policy while a role is the caller."""
    request = fixture["simulate"]["request"]
    caller = Caller.parse(request["CallerArn"])
    return "ResourcePolicy" in request and caller is not None and caller.kind == "role"


def resource_policy_matched(fixture: dict[str, Any]) -> bool:
    """Whether AWS says a statement of the resource-based policy decided the answer."""
    return any(
        statement.get("SourcePolicyId") == "ResourcePolicy"
        or "resource" in statement.get("SourcePolicyType", "").casefold()
        for result in _results(fixture)
        for statement in result.get("MatchedStatements", [])
    )


def findings(fixtures: Iterable[dict[str, Any]]) -> dict[str, str]:
    """What the calibration cases show about the simulator, as verdicts.json records it.

    - "missing_keys": how the simulator treats a key left out of the call, judged by the cases
      with an absent key whose documented answer isn't an implicit deny. ALWAYS_IMPLICIT_DENY if
      each came back implicitDeny, ACT_AS_ABSENT if each gave its documented answer, MIXED if
      neither.
    - "role_caller_resource_policies": whether a resource-based policy ever decides an answer
      while a role is the caller. AWS's "Simulation of resource-based policies isn't supported for
      IAM roles" can mean that it never does. Implicit denies list no statements, so the
      calibration cases include an Allow and a Deny that a resource-based policy should decide.

    A finding with no cases recorded yet is left out.
    """
    fixtures = list(fixtures)
    found = {}
    calibration = [
        f for f in fixtures
        if f.get("documented") and f["absent"] and f["documented"]["decision"] != "IMPLICIT_DENY"
    ]
    if calibration:
        answers = [(aws(f).label, f["documented"]["decision"]) for f in calibration]
        if all(answer == "IMPLICIT_DENY" for answer, _ in answers):
            found["missing_keys"] = ALWAYS_IMPLICIT_DENY
        elif all(answer == documented for answer, documented in answers):
            found["missing_keys"] = ACT_AS_ABSENT
        else:
            found["missing_keys"] = MIXED
    role_cases = [f for f in fixtures if role_caller_with_resource_policy(f)]
    if role_cases:
        matched = any(resource_policy_matched(f) for f in role_cases)
        found["role_caller_resource_policies"] = EVALUATED if matched else NEVER_MATCHED
    return found


def forced_verdicts(fixtures: Iterable[dict[str, Any]], found: dict[str, str]) -> dict[str, str]:
    """The verdicts that the findings in `found` set, by case, whatever the two answers are.

    If missing keys always give an implicit deny, every case with an absent key is inconclusive.
    If a resource-based policy never decides an answer for a role, every case that relies on one
    is a simulator limit.
    """
    forced = {}
    for fixture in fixtures:
        if found.get("missing_keys") == ALWAYS_IMPLICIT_DENY and fixture["absent"]:
            forced[fixture["case"]] = INCONCLUSIVE
        elif (
            found.get("role_caller_resource_policies") == NEVER_MATCHED
            and role_caller_with_resource_policy(fixture)
        ):
            forced[fixture["case"]] = SIMULATOR_LIMIT
    return forced


def _results(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """The overall result and each resource's, or none when AWS answered with an error."""
    call = fixture["simulate"]
    if call["error"] is not None:
        return []
    [result] = call["response"]["EvaluationResults"]
    return [result, *result.get("ResourceSpecificResults", [])]


def _evaluate(request: dict[str, Any], absent: Sequence[str]) -> EvaluationResult:
    caller = Caller.parse(request["CallerArn"])
    if caller is None:
        raise ValueError(f"CallerArn {request['CallerArn']} isn't a user or role ARN")
    [action] = request["ActionNames"]
    [resource] = request.get("ResourceArns", ["*"])
    policies = [
        load_policy(text, name=f"PolicyInputList.{index}")
        for index, text in enumerate(request["PolicyInputList"], 1)
    ]
    boundary = None
    if "PermissionsBoundaryPolicyInputList" in request:
        [text] = request["PermissionsBoundaryPolicyInputList"]
        boundary = load_policy(text, name="PermissionsBoundaryPolicyInputList.1")
    document = None
    if "ResourcePolicy" in request:
        document = _validation.load_json(
            request["ResourcePolicy"], "ResourcePolicy", error=PolicyParseError
        )
    described = resources.describe(resource, action, document, name="ResourcePolicy")
    return evaluate(
        Request(action=action, resource=resource, context=_context(request, absent, caller)),
        policies,
        boundary=boundary,
        scps=_scp_levels(request, caller),
        resource=described,
    )


def _context(request: dict[str, Any], absent: Sequence[str], caller: Caller) -> RequestContext:
    values = [
        (entry["ContextKeyName"], value)
        for entry in request.get("ContextEntries", [])
        for value in entry["ContextKeyValues"]
    ]
    known = {key.casefold() for key, _ in values} | {key.casefold() for key in absent}
    # The simulator knows these from CallerArn. The analyzer reads them from the context: the
    # caller's ARN to match Principal elements, and its account for IAM and STS resources.
    for key, value in (("aws:PrincipalArn", caller.arn), ("aws:PrincipalAccount", caller.account)):
        if key.casefold() not in known:
            values.append((key, value))
    return RequestContext.of(values, absent)


def _scp_levels(request: dict[str, Any], caller: Caller) -> tuple[ScpLevel, ...]:
    levels = request.get("OrderedOrganizationPolicyInputList", [])
    if not levels or caller.service_linked:
        # As Organization.scp_levels_for(service_linked=True): SCPs never restrict a
        # service-linked role.
        return ()
    found = []
    for index, level in enumerate(levels, 1):
        if index == 1:
            target = OrgTarget(TargetType.ROOT, "Root")
        elif index == len(levels):
            target = OrgTarget(TargetType.ACCOUNT, caller.account)
        else:
            target = OrgTarget(TargetType.ORGANIZATIONAL_UNIT, f"OU {index - 1}")
        policies = tuple(
            load_policy(text, name=f"OrderedOrganizationPolicyInputList.{index}.{number}")
            for number, text in enumerate(level.get("ServiceControlPolicyInputList", []), 1)
        )
        found.append(ScpLevel(target, policies))
    return tuple(found)
