"""AWS policy evaluation for identity policies and permissions boundaries.

A request is checked against one or more layers of policy:
  - the identity policies attached to the principal (always), and
  - the principal's permissions boundary, if it has one.

The logic, in three steps:
  1. Match:   in each layer, keep statements whose Action AND Resource both match the
              request. NotAction / NotResource flip the test: the statement matches when
              the request is NOT in the list.
  2. Deny:    a matching Deny in ANY layer    -> EXPLICIT_DENY (a Deny always wins)
  3. Allow:   a matching Allow in EVERY layer -> ALLOW
              otherwise                       -> IMPLICIT_DENY (the default is "no")

So a boundary never grants anything by itself; it only limits what identity policies allow.
"""

from collections.abc import Iterable

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
    Statement,
)


def statement_matches(statement: Statement, request: Request) -> bool:
    # `!=` with the flag acts as "flip the result when negated".
    action_ok = any(match_action(p, request.action) for p in statement.actions)
    resource_ok = any(match_resource(p, request.resource) for p in statement.resources)
    return (action_ok != statement.not_action) and (resource_ok != statement.not_resource)


def evaluate(
    request: Request, policies: Iterable[Policy], *, boundary: Policy | None = None
) -> EvaluationResult:
    """Evaluate `request` against identity `policies` and an optional permissions boundary."""
    layers = [(Layer(PolicyType.IDENTITY), tuple(policies))]
    if boundary is not None:
        layers.append((Layer(PolicyType.PERMISSIONS_BOUNDARY), (boundary,)))

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
