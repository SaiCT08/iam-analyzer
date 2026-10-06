"""AWS policy evaluation for identity-based policies.

The logic, in three steps:
  1. Collect: every statement from every policy attached to the principal.
  2. Match:   keep statements whose Action AND Resource both match the request.
  3. Decide:  any matching Deny  -> EXPLICIT_DENY (a Deny always wins)
              else any Allow     -> ALLOW
              else               -> IMPLICIT_DENY (the default is "no")
"""

from collections.abc import Iterable

from iam_analyzer.matching import match_action, match_resource
from iam_analyzer.models import (
    Decision,
    Effect,
    EvaluationResult,
    MatchedStatement,
    Policy,
    Request,
    Statement,
)


def statement_matches(statement: Statement, request: Request) -> bool:
    return any(match_action(p, request.action) for p in statement.actions) and any(
        match_resource(p, request.resource) for p in statement.resources
    )


def evaluate(request: Request, policies: Iterable[Policy]) -> EvaluationResult:
    matched = [
        MatchedStatement(policy.name, statement)
        for policy in policies
        for statement in policy.statements
        if statement_matches(statement, request)
    ]

    denies = tuple(m for m in matched if m.statement.effect is Effect.DENY)
    if denies:
        return EvaluationResult(Decision.EXPLICIT_DENY, denies)

    allows = tuple(m for m in matched if m.statement.effect is Effect.ALLOW)
    if allows:
        return EvaluationResult(Decision.ALLOW, allows)

    return EvaluationResult(Decision.IMPLICIT_DENY)
