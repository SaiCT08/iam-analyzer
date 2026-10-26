"""The cases the harness sends to the simulator, and how each one becomes AWS requests.

A case has the shape of a scenario in tests/scenarios: identity `policies`, an optional `boundary`,
`organization` with `account_id`, `resource_policy` (null for none), a `context` (where null marks
an absent key) and a `request`. It can also have:
  - `caller`: the simulated caller, sent as CallerArn. It defaults to the context's
    aws:PrincipalArn, or else DEFAULT_CALLER. It is always sent, because the simulator fills in
    some keys from it (FILLED_IN) and might otherwise take them from the real identity behind the
    profile.
  - `resource_owner`: sent as ResourceOwner. It must be the caller's own account.
  - `question` and `readings`: what each answer AWS could give would mean.
  - `documented`: for calibration, the answer AWS's documentation gives, with a quote and a link.
  - `context_types`: the ContextKeyType of a key, for when the analyzer can't load a policy that
    reads it and so can't tell its type.

Hand-written cases live in simulator_check/cases/*.json, one file per question, as
{"title", "question", "defaults", "cases": [...]}: each case is `defaults` updated with its own
fields. The scenarios in tests/scenarios are cases too, with SCENARIO_EXTRAS added.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iam_analyzer import _validation, conditions, resources, variables
from iam_analyzer.errors import PolicyError, PolicyParseError
from iam_analyzer.loader import parse_policy
from iam_analyzer.models import PolicyType, Statement
from iam_analyzer.organization import parse_organization
from simulator_check import REPO, Caller, safety_problems

CASES_DIR = Path(__file__).parent / "cases"
SCENARIO_DIR = REPO / "tests" / "scenarios"
SCENARIOS = "scenarios"  # the group of the cases that come from tests/scenarios

DEFAULT_CALLER = "arn:aws:iam::111122223333:user/jsmith"

# SimulateCustomPolicy needs at least one identity policy. A case with none gets this one, which
# allows nothing the cases ask about. Both sides evaluate it.
PLACEHOLDER = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "NothingTheCaseAsksAbout", "Effect": "Allow",
                   "Action": "iam:GetAccountSummary", "Resource": "*"}],
}

# The keys the simulator fills in from the caller, in lowercase. AWS: "How condition key
# evaluation works in the IAM policy simulator".
FILLED_IN = frozenset(key.casefold() for key in (
    "aws:PrincipalAccount", "aws:PrincipalId", "aws:PrincipalType", "aws:UserId", "aws:UserName",
    "aws:PrincipalOrgID", "aws:PrincipalOrgMasterAccountId", "aws:PrincipalOrgPaths",
))

_USER_GUIDE = "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
_OPERATORS = f"{_USER_GUIDE}reference_policies_elements_condition_operators.html"

# What a scenario file leaves out because the analyzer doesn't need it, by scenario name.
SCENARIO_EXTRAS: dict[str, dict[str, Any]] = {
    # The simulator needs a service-linked role as the caller to show whether it exempts one.
    "scp_skips_service_linked_role": {
        "caller": "arn:aws:iam::111122223333:role/aws-service-role/support.amazonaws.com/"
                  "AWSServiceRoleForSupport",
    },
    # These three also calibrate absent keys, because AWS documents their answers.
    "condition_for_all_values_holds_when_the_key_is_missing": {"documented": {
        "decision": "ALLOW",
        "source": "The ForAllValues qualifier returns true if there are no context keys in the "
                  "request or if the context key value resolves to a null dataset, such as an "
                  "empty string.",
        "link": f"{_OPERATORS}#conditions_arn_multivalued",
    }},
    "condition_bool_if_exists_denies_access_keys": {"documented": {
        "decision": "EXPLICIT_DENY",
        "source": "If the key is not present, evaluate the condition element as true.",
        "link": f"{_OPERATORS}#Conditions_IfExists",
    }},
    "policy_variable_default_when_tag_is_absent": {"documented": {
        "decision": "ALLOW",
        "source": "For users without team tags, it sets a default value of company-wide for the "
                  "bucket name.",
        "link": f"{_USER_GUIDE}reference_policies_variables.html#policy-vars-default-values",
    }},
}

SCENARIO_FIELDS = {
    "description", "policies", "boundary", "organization", "account_id", "service_linked",
    "resource_policy", "context", "request", "expected",
}
CASE_FIELDS = SCENARIO_FIELDS | {
    "caller", "resource_owner", "question", "readings", "documented", "context_types",
}

# ContextKeyType for the values each operator family reads. Null only checks whether a key is
# there, so it says nothing about the type.
_FAMILY_TYPES = {
    "String": "string", "ARN": "string", "Numeric": "numeric", "Date": "date", "Bool": "boolean",
    "Binary": "binary", "IP address": "ip",
}
CONTEXT_KEY_TYPES = frozenset({*_FAMILY_TYPES.values(), *(f"{t}List" for t in _FAMILY_TYPES.values())})

_ROLE_ACTIONS = frozenset(action.casefold() for action in resources.ROLE_ACTIONS)
# Stands in for each SCP when only the organization's tree is needed (`_scp_levels`).
_STAND_IN_SCP = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


@dataclass(frozen=True)
class Case:
    id: str  # "group/name", which is also where its fixture goes under tests/simulator_fixtures
    source: str  # the file it comes from, relative to the repository
    definition: dict[str, Any]

    @property
    def group(self) -> str:
        return self.id.partition("/")[0]


class NotExpressible(Exception):
    """The simulator can't be given the case faithfully. The message says why."""


@dataclass(frozen=True)
class Requests:
    """What the harness sends AWS for one case."""

    context_keys: dict[str, Any]  # GetContextKeysForCustomPolicy's arguments: every policy
    simulate: dict[str, Any]  # SimulateCustomPolicy's arguments
    absent: tuple[str, ...]  # keys left out of the call, which the analyzer's side marks absent


def load_cases() -> list[Case]:
    """Every case: the hand-written ones, then the scenarios."""
    found = []
    for path in sorted(CASES_DIR.glob("*.json")):
        document = _load(path)
        for raw in document["cases"]:
            definition = {"question": document["question"], **document.get("defaults", {}), **raw}
            name = definition.pop("name")
            found.append(_case(f"{path.stem}/{name}", path, definition))
    for path in sorted(SCENARIO_DIR.glob("*.json")):
        definition = {**_load(path), **SCENARIO_EXTRAS.get(path.stem, {})}
        found.append(_case(f"{SCENARIOS}/{path.stem}", path, definition))
    return found


def requests_for(case: Case) -> Requests:
    """The AWS requests for `case`.

    Raises NotExpressible when the simulator can't be given the case faithfully, and ValueError
    when the case itself is wrong, such as a key a policy reads that the case doesn't give.
    """
    d = case.definition
    action, resource = d["request"]["action"], d["request"]["resource"]
    if resources.is_role_arn(resource) and action.casefold() in _ROLE_ACTIONS:
        raise NotExpressible(
            "it needs the role's trust policy, and AWS says \"Simulation of resource-based "
            "policies isn't supported for IAM roles\""
        )
    levels = _scp_levels(case) if "organization" in d else []
    caller = _caller(case)
    context = d.get("context", {})
    _check_filled_in(context, caller)

    policies = list(d["policies"].values())
    if not policies:
        if action.casefold() == "iam:getaccountsummary":
            raise ValueError(f"{case.id}: the placeholder policy would allow {action}")
        policies = [PLACEHOLDER]
    documents = [(policy, PolicyType.IDENTITY) for policy in policies]
    simulate: dict[str, Any] = {"PolicyInputList": [_text(policy) for policy in policies]}
    if d.get("boundary") is not None:
        documents.append((d["boundary"], PolicyType.PERMISSIONS_BOUNDARY))
        simulate["PermissionsBoundaryPolicyInputList"] = [_text(d["boundary"])]
    if levels:
        documents += [(scp, PolicyType.SCP) for level in levels for scp in level]
        simulate["OrderedOrganizationPolicyInputList"] = [
            {"ServiceControlPolicyInputList": [_text(scp) for scp in level]} for level in levels
        ]
    if d.get("resource_policy") is not None:
        documents.append((d["resource_policy"], PolicyType.RESOURCE_BASED))
        simulate["ResourcePolicy"] = _text(d["resource_policy"])
    if "resource_owner" in d:
        if d["resource_owner"] != f"arn:aws:iam::{caller.account}:root":
            raise NotExpressible(
                f"the resource's owner {d['resource_owner']} isn't the caller's account, and the "
                "analyzer doesn't evaluate cross-account requests"
            )
        simulate["ResourceOwner"] = d["resource_owner"]
    simulate["CallerArn"] = caller.arn
    simulate["ActionNames"] = [action]
    simulate["ResourceArns"] = [resource]

    reads = _Reads.of(documents)
    unread = sorted(set(reads.types) - {key.casefold() for key in context})
    if unread:
        raise ValueError(
            f"{case.id}: the case doesn't give {', '.join(unread)}, which a policy reads: give a "
            "value, or null if the request doesn't include it"
        )
    types = d.get("context_types", {})
    entries = [_entry(key, value, reads, types) for key, value in context.items() if value is not None]
    if entries:
        simulate["ContextEntries"] = entries
    absent = tuple(key for key, value in context.items() if value is None)

    context_keys = {"PolicyInputList": [_text(document) for document, _ in documents]}
    problems = safety_problems(json.dumps([context_keys, simulate]))
    if problems:
        raise ValueError(f"{case.id}: {'; '.join(problems)}")
    return Requests(context_keys, simulate, absent)


def _load(path: Path) -> dict[str, Any]:
    return _validation.load_json(path.read_text(encoding="utf-8"), path.name, error=PolicyParseError)


def _case(case_id: str, path: Path, definition: dict[str, Any]) -> Case:
    unknown = set(definition) - CASE_FIELDS
    if unknown:
        raise ValueError(f"{case_id}: unknown field(s) {', '.join(sorted(unknown))}")
    return Case(case_id, path.relative_to(REPO).as_posix(), definition)


def _text(document: Any) -> str:
    return json.dumps(document, indent=2)


def _caller(case: Case) -> Caller:
    d = case.definition
    context = d.get("context", {})
    named = [value for key, value in context.items() if key.casefold() == "aws:principalarn"]
    if named == [None]:
        raise NotExpressible("every simulated request has a caller, so aws:PrincipalArn can't be absent")
    arn = d.get("caller") or (named[0] if named else DEFAULT_CALLER)
    if named and named[0] != arn:
        raise ValueError(f"{case.id}: the caller {arn} and aws:PrincipalArn {named[0]} disagree")
    caller = Caller.parse(arn)
    if caller is None:
        raise NotExpressible(
            f"the caller {arn} isn't an IAM user or role, and AWS says \"You cannot specify the "
            "ARN of an assumed role, federated user, or a service principal\""
        )
    if "organization" in d and d["account_id"] != caller.account:
        raise ValueError(f"{case.id}: account_id {d['account_id']} isn't the caller's account")
    if d.get("service_linked", False) != caller.service_linked:
        raise ValueError(f"{case.id}: service_linked doesn't match the caller's path")
    return caller


def _check_filled_in(context: dict[str, Any], caller: Caller) -> None:
    """Refuse a case whose keys disagree with what the simulator fills in from the caller."""
    known = {"aws:principalaccount": caller.account}
    if caller.kind == "user":
        known |= {"aws:username": caller.name, "aws:principaltype": "User"}
    for key, value in context.items():
        folded = key.casefold()
        if folded in FILLED_IN and (value is None or known.get(folded) != value):
            state = "absent" if value is None else repr(value)
            raise NotExpressible(
                f"the simulator fills in {key} from the caller {caller.arn}, so the case can't make "
                f"it {state}"
            )


def _scp_levels(case: Case) -> list[list[Any]]:
    """The SCP documents at each level from the root down to the case's account."""
    d = case.definition
    raw = d["organization"]["ServiceControlPolicies"]
    # Only the tree is needed here, so each SCP is swapped for one the analyzer always loads. The
    # simulator still gets the real ones, including any the analyzer refuses, such as one with a
    # short ARN.
    tree = {**d["organization"], "ServiceControlPolicies": {name: _STAND_IN_SCP for name in raw}}
    organization = parse_organization(tree, name="organization")
    if d["account_id"] == organization.management_account_id:
        raise NotExpressible(
            "SCPs never apply to the management account, and nothing tells the simulator which "
            "account that is"
        )
    # The full path: the simulator gets the SCPs even for a service-linked role, to show whether
    # it applies AWS's exemption.
    path = organization.scp_levels_for(d["account_id"])
    return [[raw[policy.name] for policy in level.policies] for level in path]


def _entry(key: str, value: Any, reads: "_Reads", types: dict[str, str]) -> dict[str, Any]:
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(v, str) for v in values):
        raise ValueError(f"context key {key}: give a string or a non-empty list of strings")
    kind = types.get(key) or reads.type_of(key, many=isinstance(value, list))
    if kind not in CONTEXT_KEY_TYPES:
        raise ValueError(f"context key {key}: {kind!r} isn't a ContextKeyType")
    return {"ContextKeyName": key, "ContextKeyValues": values, "ContextKeyType": kind}


@dataclass
class _Reads:
    """What a case's policies read from the request context, as far as the analyzer can load them."""

    # Each key read, in lowercase, with the ContextKeyTypes its operators expect.
    types: dict[str, set[str]] = field(default_factory=dict)
    sets: set[str] = field(default_factory=set)  # keys read with ForAllValues or ForAnyValue
    complete: bool = True  # whether the analyzer could load every policy

    @classmethod
    def of(cls, documents: list[tuple[Any, PolicyType]]) -> "_Reads":
        reads = cls()
        for document, kind in documents:
            try:
                policy = parse_policy(document, name="policy", kind=kind)
            except PolicyError:
                reads.complete = False
                continue
            for statement in policy.statements:
                reads._statement(statement)
        return reads

    def type_of(self, key: str, *, many: bool) -> str:
        """The ContextKeyType to send `key` as."""
        folded = key.casefold()
        if folded not in self.types and not self.complete:
            raise ValueError(
                f"context key {key}: a policy the analyzer can't load may read it, so give its type "
                "in context_types"
            )
        found = self.types.get(folded, set())
        if len(found) > 1:
            raise ValueError(
                f"context key {key} is read as {' and '.join(sorted(found))}: give its type in "
                "context_types"
            )
        kind = next(iter(found), "string")  # read only by Null, or not at all: any type will do
        return f"{kind}List" if many or folded in self.sets else kind

    def _statement(self, statement: Statement) -> None:
        if statement.policy_variables:
            for pattern in statement.resources:
                self._read(variables.keys(variables.parse(pattern)), "string")
        for condition in statement.conditions:
            family = conditions.OPERATORS[condition.operator].family
            self._read([condition.key], _FAMILY_TYPES.get(family.name))
            if condition.set_operator is not None:
                self.sets.add(condition.key.casefold())
            if statement.policy_variables and family.takes_variables:
                for value in condition.values:
                    self._read(variables.keys(variables.parse(value)), "string")

    def _read(self, keys: list[str], kind: str | None) -> None:
        for key in keys:
            found = self.types.setdefault(key.casefold(), set())
            if kind is not None:
                found.add(kind)
