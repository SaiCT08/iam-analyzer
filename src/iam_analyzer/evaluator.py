"""AWS policy evaluation for identity policies, permissions boundaries and SCPs.

A request is checked against one or more layers of policy:
  - the identity policies attached to the principal (always),
  - the principal's permissions boundary, if it has one, and
  - the SCPs of the principal's AWS organization, if it is in one. Each level of the
    organization (the root, each OU, then the account) is a layer of its own.

The logic, in three steps:
  1. Match:   in each layer, keep statements whose Action AND Resource both match the
              request. NotAction / NotResource flip the test: the statement matches when
              the request is NOT in the list.
  2. Deny:    a matching Deny in ANY layer    -> EXPLICIT_DENY (a Deny always wins)
  3. Allow:   a matching Allow in EVERY layer -> ALLOW
              otherwise                       -> IMPLICIT_DENY (the default is "no")

So boundaries and SCPs never grant anything by themselves; they only limit what identity
policies allow.
"""

from collections.abc import Iterable, Sequence

from iam_analyzer.matching import match_action, match_resource
from iam_analyzer.models import (
    Decision,
    Effect,
    EvaluationResult,
    Layer,
    MatchedStatement,
    Policy,
    PolicyType,
    Request,
    ScpLevel,
    Statement,
)


def statement_matches(statement: Statement, request: Request) -> bool:
    # `!=` with the flag acts as "flip the result when negated".
    action_ok = any(match_action(p, request.action) for p in statement.actions)
    resource_ok = any(match_resource(p, request.resource) for p in statement.resources)
    return (action_ok != statement.not_action) and (resource_ok != statement.not_resource)


def evaluate(
    request: Request,
    policies: Iterable[Policy],
    *,
    boundary: Policy | None = None,
    scps: Sequence[ScpLevel] = (),
) -> EvaluationResult:
    """Evaluate `request` against identity `policies`, an optional permissions boundary,
    and the SCP levels from the organization root down to the principal's account."""
    layers = [(Layer(PolicyType.IDENTITY), tuple(policies))]
    if boundary is not None:
        layers.append((Layer(PolicyType.PERMISSIONS_BOUNDARY), (boundary,)))
    # A level with no SCPs has no Allow, so it denies: the safe default.
    layers += [(Layer(PolicyType.SCP, level.target), level.policies) for level in scps]

    matched = [
        (layer, _matching(request, layer, layer_policies)) for layer, layer_policies in layers
    ]
    every = [m for _, found in matched for m in found]

    denies = tuple(m for m in every if m.statement.effect is Effect.DENY)
    if denies:
        return EvaluationResult(Decision.EXPLICIT_DENY, denies)

    # No Deny matched, so every matched statement is an Allow. Each layer needs one.
    not_allowed_by = tuple(layer for layer, found in matched if not found)
    if not_allowed_by:
        return EvaluationResult(Decision.IMPLICIT_DENY, not_allowed_by=not_allowed_by)

    return EvaluationResult(Decision.ALLOW, tuple(every))


def _matching(request: Request, layer: Layer, policies: Iterable[Policy]) -> list[MatchedStatement]:
    """Every statement in `policies` that matches `request`, tagged with `layer`."""
    return [
        MatchedStatement(policy.name, statement, policy.via_group, layer)
        for policy in policies
        for statement in policy.statements
        if statement_matches(statement, request)
    ]
