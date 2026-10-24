"""AWS policy evaluation for identity policies, permissions boundaries and SCPs.

A request is checked against one or more layers of policy:
  - the identity policies attached to the principal (always),
  - the principal's permissions boundary, if it has one, and
  - the SCPs of the principal's AWS organization, if it is in one. Each level of the
    organization (the root, each OU, then the account) is a layer of its own.

The logic, in three steps:
  1. Match:   in each layer, keep statements whose Action AND Resource both match the
              request, and whose conditions all hold. NotAction / NotResource flip the
              test: the statement matches when the request is NOT in the list. Policy
              variables, such as ${aws:username}, are filled in from the request context.
  2. Deny:    a matching Deny in ANY layer    -> EXPLICIT_DENY (a Deny always wins)
  3. Allow:   a matching Allow in EVERY layer -> ALLOW
              otherwise                       -> IMPLICIT_DENY (the default is "no")

So boundaries and SCPs never grant anything by themselves; they only limit what identity
policies allow.

When matching a statement needs a condition key the request context says nothing about,
there is no answer to give: evaluation raises one MissingContextError that names every such
key and the statements that use it.

A request on a specific resource also needs that resource described (`models.Resource`, and
`resources` for which requests need one), because the analyzer can't tell from an ARN whether the
resource has a resource-based policy or which account it is in. Without a description, evaluation
raises MissingResourceError. Requests on a resource in another account are refused, since they
also need that account's policies.
"""

from collections.abc import Iterable, Sequence

from iam_analyzer import conditions, resources, variables
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import (
    MissingContextError,
    MissingResourceError,
    PolicyError,
    RequestError,
    UnsupportedPolicyFeature,
)
from iam_analyzer.matching import Pattern, match_action, match_resource
from iam_analyzer.models import (
    Decision,
    Effect,
    EvaluationResult,
    Layer,
    MatchedStatement,
    Policy,
    PolicyType,
    Request,
    Resource,
    ScpLevel,
    Statement,
)

# The principal's account, which a request on an IAM or STS resource needs, so that a request on
# another account's resource isn't mistaken for one within the principal's own account.
PRINCIPAL_ACCOUNT = "aws:PrincipalAccount"


def statement_matches(statement: Statement, request: Request) -> bool:
    """Whether `statement` applies to `request`.

    Raises MissingContextError when the answer depends on a condition key the request context
    says nothing about. Keys are only needed once the action matches, and condition keys once
    the resource matches too.
    """
    # `!=` with the flag acts as "flip the result when negated".
    action_ok = any(match_action(p, request.action) for p in statement.actions)
    if action_ok == statement.not_action:
        return False
    resources = _resource_patterns(statement, request.context)
    resource_ok = any(match_resource(p, request.resource) for p in resources)
    if resource_ok == statement.not_resource:
        return False
    _require(conditions.keys(statement), request.context)
    return _conditions_hold(statement, request.context)


def _conditions_hold(statement: Statement, context: RequestContext) -> bool:
    """Whether every condition holds.

    One condition that fails is enough for the statement not to apply, whatever AWS does with
    the others. So a condition the analyzer refuses only matters when all the rest hold.
    """
    refused = None
    for condition in statement.conditions:
        try:
            if not conditions.holds(condition, context, statement.policy_variables):
                return False
        except UnsupportedPolicyFeature as exc:
            refused = refused or exc
    if refused is not None:
        raise refused
    return True


def evaluate(
    request: Request,
    policies: Iterable[Policy],
    *,
    boundary: Policy | None = None,
    scps: Sequence[ScpLevel] = (),
    resource: Resource | None = None,
) -> EvaluationResult:
    """Evaluate `request` against identity `policies`, an optional permissions boundary,
    and the SCP levels from the organization root down to the principal's account.

    `resource` describes the resource the request is on. Every request on a specific resource
    needs one, except a request on an IAM or STS resource.
    """
    missing: list[tuple[str, str]] = []
    described = _check_resource(request, resource)
    _check_same_account(request, described, missing)

    layers = [(Layer(PolicyType.IDENTITY), tuple(policies))]
    if boundary is not None:
        layers.append((Layer(PolicyType.PERMISSIONS_BOUNDARY), (boundary,)))
    # A level with no SCPs has no Allow, so it denies: the safe default.
    layers += [(Layer(PolicyType.SCP, level.target), level.policies) for level in scps]

    matched = [
        (layer, _matching(request, layer, layer_policies, missing))
        for layer, layer_policies in layers
    ]
    if missing:
        raise _missing_context(missing)
    every = [m for _, found in matched for m in found]

    denies = tuple(m for m in every if m.statement.effect is Effect.DENY)
    if denies:
        return EvaluationResult(Decision.EXPLICIT_DENY, denies)

    # No Deny matched, so every matched statement is an Allow. Each layer needs one.
    not_allowed_by = tuple(layer for layer, found in matched if not found)
    if not_allowed_by:
        return EvaluationResult(Decision.IMPLICIT_DENY, not_allowed_by=not_allowed_by)

    return EvaluationResult(Decision.ALLOW, tuple(every))


def _check_resource(request: Request, resource: Resource | None) -> bool:
    """Check that `resource` describes what the request needs. Returns whether it needed one."""
    governing = resources.governing_arn(request.resource, request.action)
    if governing is None:
        if resource is not None and resource.policy is not None:
            raise RequestError(
                f"no resource-based policy applies to {request.action} on {request.resource}"
            )
        return False
    if resources.is_role_arn(governing):
        raise UnsupportedPolicyFeature(
            f"{request.action} on {governing}: role trust policies aren't supported yet"
        )
    if resource is None:
        raise MissingResourceError(
            f"nothing describes {governing}: it can have a resource-based policy, and the analyzer "
            "can't tell whether it has one, or which account it is in",
            governing,
        )
    if resource.arn != governing:
        raise RequestError(
            f"a request on {request.resource} needs {governing} described, not {resource.arn}"
        )
    if resource.policy is not None:
        raise UnsupportedPolicyFeature(f"{governing}: resource-based policies aren't supported yet")
    return True


def _check_same_account(request: Request, described: bool, missing: list[tuple[str, str]]) -> None:
    """Refuse a request on a resource in another account, which also needs that account's
    policies.

    A described resource is in the principal's account by its description. For an IAM or STS
    resource, whose ARN names its account, the principal's account must be known: if it isn't,
    PRINCIPAL_ACCOUNT is added to `missing`.
    """
    account = resources.account_of(request.resource)
    if account is None:
        return
    context = request.context
    if not context.knows(PRINCIPAL_ACCOUNT):
        if not described:
            check = f"the check that {request.resource} is in the principal's account"
            missing.append((PRINCIPAL_ACCOUNT, check))
        return
    found = context.get(PRINCIPAL_ACCOUNT)
    if found is None or len(found) != 1:
        raise RequestError(
            f"condition key {PRINCIPAL_ACCOUNT!r} needs exactly one value: every request has one, "
            "the principal's account"
        )
    if found[0] != account:
        raise UnsupportedPolicyFeature(
            f"{request.resource} is in account {account}, and the principal is in account "
            f"{found[0]}: cross-account requests aren't supported yet"
        )


def _matching(
    request: Request,
    layer: Layer,
    policies: Iterable[Policy],
    missing: list[tuple[str, str]],
) -> list[MatchedStatement]:
    """Every statement in `policies` that matches `request`, tagged with `layer`.

    Condition keys that a statement needs but the request context lacks are added to
    `missing` as (key, statement) pairs, so that one error can name them all.
    """
    found = []
    for policy in policies:
        for index, statement in enumerate(policy.statements):
            try:
                if statement_matches(statement, request):
                    found.append(MatchedStatement(policy.name, statement, policy.via_group, layer))
            except MissingContextError as exc:
                missing += [(key, _where(policy, index, statement)) for key in exc.keys]
            except PolicyError as exc:
                raise type(exc)(f"{_where(policy, index, statement)}: {exc}") from None
    return found


def _resource_patterns(statement: Statement, context: RequestContext) -> Sequence[Pattern]:
    """The statement's resource patterns, with any policy variables filled in."""
    if not statement.policy_variables:
        return statement.resources
    templates = [variables.parse(resource) for resource in statement.resources]
    _require([key for template in templates for key in variables.keys(template)], context)
    return [variables.resolve(template, context) for template in templates]


def _require(keys: Iterable[str], context: RequestContext) -> None:
    """Raise one MissingContextError naming each of `keys` that `context` says nothing about."""
    unknown: dict[str, str] = {}
    for key in keys:
        if not context.knows(key):
            unknown.setdefault(key.casefold(), key)
    if unknown:
        names = list(unknown.values())
        raise MissingContextError(
            f"the request context says nothing about {', '.join(map(repr, names))}", names
        )


def _missing_context(missing: list[tuple[str, str]]) -> MissingContextError:
    """One error that names each missing key once, with every statement that needs it."""
    places: dict[str, tuple[str, list[str]]] = {}
    for key, where in missing:
        _, wheres = places.setdefault(key.casefold(), (key, []))
        if where not in wheres:
            wheres.append(where)
    lines = [f"  {key}, used by {'; '.join(wheres)}" for key, wheres in places.values()]
    return MissingContextError(
        "the request context says nothing about these condition keys:\n" + "\n".join(lines),
        [key for key, _ in places.values()],
    )


def _where(policy: Policy, index: int, statement: Statement) -> str:
    """Name a statement the way the loader does: "Policy statement 0 (Sid=X)"."""
    where = f"{policy.name} statement {index}"
    return f"{where} (Sid={statement.sid})" if statement.sid else where
