"""AWS policy evaluation for identity policies, permissions boundaries, SCPs and resource-based
policies.

A request is checked against one or more layers of policy:
  - the identity policies attached to the principal (always),
  - the principal's permissions boundary, if it has one,
  - the SCPs of the principal's AWS organization, if it is in one. Each level of the
    organization (the root, each OU, then the account) is a layer of its own, and
  - the resource-based policy of the resource the request is on, if it has one, such as an S3
    bucket policy. For the STS actions on a role, such as sts:AssumeRole, it is the role's trust
    policy, which must allow the request.

The logic, in three steps:
  1. Match:   in each layer, keep statements whose Action AND Resource both match the request,
              whose Principal names the caller (resource-based policies only), and whose
              conditions all hold. NotAction / NotResource flip the test: the statement matches
              when the request is NOT in the list. Policy variables, such as ${aws:username},
              are filled in from the request context.
  2. Deny:    a matching Deny in ANY layer -> EXPLICIT_DENY (a Deny always wins)
  3. Allow:   every SCP level needs a matching Allow. Within one account, AWS then allows the
              request when the identity policies allow it, and the boundary too if there is
              one, or when the resource-based policy grants it. What that policy's Principal
              names decides what else is needed:
                - the caller's user, or everyone ("*"): nothing else;
                - the caller's role: the boundary must still allow;
                - the caller's account: AWS says that "delegates authority to the account",
                  so the identity policies and the boundary must allow, as with no grant.
              A trust policy must allow too, as AWS says role trust policies "must explicitly
              allow access". If it names the caller directly while the caller's boundary doesn't
              allow the request, AWS's docs disagree, so the analyzer refuses.
              Otherwise -> IMPLICIT_DENY (the default is "no")

So boundaries and SCPs never grant anything by themselves; they only limit what identity
and resource-based policies allow.

When matching a statement needs a condition key the request context says nothing about,
there is no answer to give: evaluation raises one MissingContextError that names every such
key and the statements that use it.

A NotPrincipal Deny is refused once the rest of its statement applies to the request. AWS says
NotPrincipal "might validate the account first, then the role, and then the assumed-role user",
depending on the service, so whom it leaves out isn't settled. Requests the statement doesn't
cover are answered as usual.

s3:ListAllMyBuckets has no resource, so its request is on "*". AWS's own evaluation example
settles which statements cover it, so it is matched as arn:aws:s3:::, a bucket ARN with an empty
name (see `_matched_resource`).

A request on a specific resource also needs that resource described (`models.Resource`, and
`resources` for which requests need one), because the analyzer can't tell from an ARN whether the
resource has a resource-based policy or which account it is in. Without a description, evaluation
raises MissingResourceError. Requests on a resource in another account are refused, since they
also need that account's policies.
"""

from collections.abc import Iterable, Sequence

from iam_analyzer import conditions, principals, resources, variables
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
    PrincipalMatch,
    Request,
    Resource,
    ScpLevel,
    Statement,
)

# The principal's account, which a request on an IAM or STS resource needs, so that a request on
# another account's resource isn't mistaken for one within the principal's own account.
PRINCIPAL_ACCOUNT = "aws:PrincipalAccount"
# Requests that SAML and OIDC users make, rather than IAM users and role sessions.
FEDERATED_ACTIONS = ("sts:assumerolewithsaml", "sts:assumerolewithwebidentity")
# The action with no resource that AWS's evaluation example covers with arn:aws:s3:::*, and the
# bucket ARN with an empty name that its request is matched as (see `_matched_resource`).
LIST_ALL_MY_BUCKETS = "s3:ListAllMyBuckets"
EVERY_BUCKET = "arn:aws:s3:::"
NOT_PRINCIPAL_REFUSAL = (
    "'NotPrincipal' isn't supported yet: AWS says which principals it checks depends on the "
    "service, and recommends aws:PrincipalArn conditions instead"
)


def statement_matches(statement: Statement, request: Request) -> bool:
    """Whether `statement` applies to `request`.

    Raises MissingContextError when the answer depends on a condition key the request context
    says nothing about. Keys are only needed once the action matches, and condition keys once
    the resource, and in a resource-based policy the principal, match too.
    """
    applies, _ = _applies(statement, request)
    return applies


def _applies(statement: Statement, request: Request) -> tuple[bool, PrincipalMatch | None]:
    """Whether `statement` applies to `request`, and how its Principal names the caller."""
    # `!=` with the flag acts as "flip the result when negated".
    action_ok = any(match_action(p, request.action) for p in statement.actions)
    if action_ok == statement.not_action:
        return False, None
    if statement.resources:  # a trust policy names none: it covers the role it belongs to
        patterns = _resource_patterns(statement, request.context)
        resource = _matched_resource(request)
        resource_ok = any(match_resource(p, resource) for p in patterns)
        if resource_ok == statement.not_resource:
            return False, None
    found = refused = None
    if statement.not_principal:
        refused = UnsupportedPolicyFeature(NOT_PRINCIPAL_REFUSAL)
    elif statement.principals is not None:
        if principals.needs_caller(statement.principals):
            _require([principals.CALLER_KEY], request.context)
        deny = statement.effect is Effect.DENY
        try:
            found = principals.match(statement.principals, request.context, deny=deny)
        except UnsupportedPolicyFeature as exc:
            refused = exc  # like a refused condition, it only matters if the conditions hold
        else:
            if found is None:
                return False, None
    _require(conditions.keys(statement), request.context)
    if not _conditions_hold(statement, request.context):
        return False, None
    if refused is not None:
        raise refused
    return True, found


def _matched_resource(request: Request) -> str:
    """The resource that statements' Resource and NotResource are matched against: the request's
    own, except for s3:ListAllMyBuckets on "*".

    That action has no resource, and AWS's evaluation example settles which statements cover it:
      - an Allow on arn:aws:s3:::* does: "The AllowS3ListRead statement in this policy allows
        Carlos to view a list of all of the buckets in the account";
      - a Deny on arn:aws:s3:::*log* doesn't, although its s3:* covers the action. It "denies
        Carlos access to any S3 bucket with log in its name", and the example still lets Carlos
        list all buckets.
    So the request is matched as arn:aws:s3:::, a bucket ARN with an empty name, in the aws
    partition that the account file assumes too. A statement covers it when its Resource covers
    every bucket, as "*" and arn:aws:s3:::* do. It doesn't when its Resource names a bucket, or
    needs characters in the name, as arn:aws:s3:::*log* does. The IAM policy simulator matched
    only the "*" it was sent (list_all_my_buckets/allowed_on_every_bucket_arn), which says
    nothing about the resource a real request carries.

    Other requests on "*" are matched as "*". For an action with no resource type, the Service
    Authorization Reference says "you must specify all resources ("*") in your policy", and "If
    you specify a resource that is not valid for the action, any request to use that action
    fails, and the statement's Effect does not apply."
    """
    if request.resource == "*" and request.action.casefold() == LIST_ALL_MY_BUCKETS.casefold():
        return EVERY_BUCKET
    return request.resource


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
    if request.action.casefold() in FEDERATED_ACTIONS:
        raise UnsupportedPolicyFeature(
            f"{request.action} is called by a SAML or OIDC user, not an IAM user or a role "
            "session, and the analyzer doesn't evaluate requests by federated users yet"
        )
    missing: list[tuple[str, str]] = []
    governing = resources.governing_arn(request.resource, request.action)
    _check_same_account(request, governing is not None and resource is not None, missing)
    _check_resource(request, governing, resource)

    layers = [(Layer(PolicyType.IDENTITY), tuple(policies))]
    if boundary is not None:
        layers.append((Layer(PolicyType.PERMISSIONS_BOUNDARY), (boundary,)))
    # A level with no SCPs has no Allow, so it denies: the safe default.
    layers += [(Layer(PolicyType.SCP, level.target), level.policies) for level in scps]
    resource_layer = None
    if governing is not None and resource.policy is not None:
        resource_layer = Layer(resources.policy_kind(governing), resource=governing)
        layers.append((resource_layer, (resource.policy,)))

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

    # No Deny matched, so every matched statement is an Allow.
    grant = principals.strongest(m.principal_match for m in every if m.layer == resource_layer)
    if resource_layer is not None and resource_layer.policy_type is PolicyType.TRUST:
        _check_trust_boundary(matched, grant)
    not_allowed_by = _not_allowed_by(matched, grant, resource_layer)
    if not_allowed_by:
        return EvaluationResult(Decision.IMPLICIT_DENY, not_allowed_by=not_allowed_by)

    return EvaluationResult(Decision.ALLOW, tuple(every))


def _not_allowed_by(
    matched: list[tuple[Layer, list[MatchedStatement]]],
    grant: PrincipalMatch | None,
    resource_layer: Layer | None,
) -> tuple[Layer, ...]:
    """The layers whose missing Allow stops the request.

    Every SCP level and a role's trust policy need an Allow, and so do the identity policies and
    the boundary, unless the resource-based policy's `grant` spares them. When a resource-based
    policy such as a bucket policy grants nothing and the identity side doesn't allow either, it
    is listed too: it was the other way in.
    """
    blocked = [layer for layer, found in matched if not found and _needed(layer, grant)]
    identity_side = (PolicyType.IDENTITY, PolicyType.PERMISSIONS_BOUNDARY)
    if resource_layer is not None and resource_layer.policy_type is PolicyType.RESOURCE_BASED:
        if grant is None and any(layer.policy_type in identity_side for layer in blocked):
            blocked.append(resource_layer)
    return tuple(blocked)


def _needed(layer: Layer, grant: PrincipalMatch | None) -> bool:
    """Whether `layer` must allow the request, given how the resource-based policy granted it.

    AWS: grants to a user ARN "are not limited by an implicit deny in an identity-based policy or
    permissions boundary", and grants to a role ARN "are limited by an implicit deny in a
    permissions boundary". A grant to everyone ("*") counts as direct, and one to the account
    grants nothing by itself. AWS: "IAM role trust policies ... must explicitly allow access".
    """
    if layer.policy_type in (PolicyType.SCP, PolicyType.TRUST):
        return True
    if layer.policy_type is PolicyType.IDENTITY:
        return grant in (None, PrincipalMatch.ACCOUNT)
    if layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        return grant is None or not grant.direct
    return False


def _check_resource(request: Request, governing: str | None, resource: Resource | None) -> None:
    """Check that `resource` describes what the request needs: the resource whose ARN is
    `governing`, or nothing when that is None."""
    if governing is None:
        if resource is not None and resource.policy is not None:
            raise RequestError(
                f"no resource-based policy applies to {request.action} on {request.resource}"
            )
        return
    role = resources.is_role_arn(governing)
    if resource is None:
        message = (
            f"nothing gives the trust policy of {governing}, which every role has and which must "
            "allow this request"
            if role
            else f"nothing describes {governing}: it can have a resource-based policy, and the "
            "analyzer can't tell whether it has one, or which account it is in"
        )
        raise MissingResourceError(message, governing)
    if resource.arn != governing:
        raise RequestError(
            f"a request on {request.resource} needs {governing} described, not {resource.arn}"
        )
    if resource.policy is not None:
        resources.check_policy_support(governing, where=resource.policy.name)
    elif role:
        raise RequestError(
            f"{governing} is a role, and every role has a trust policy that must allow this "
            "request: give it instead of saying there is none"
        )


def _check_trust_boundary(
    matched: list[tuple[Layer, list[MatchedStatement]]], grant: PrincipalMatch | None
) -> None:
    """Refuse where AWS's docs disagree: a trust policy that names the caller directly, when the
    caller's permissions boundary doesn't allow the request.

    The trust policy page says "If a permissions boundary is set for the user, then it must allow
    the sts:AssumeRole action". The evaluation logic page says grants to an IAM user ARN "are not
    limited by an implicit deny in an identity-based policy or permissions boundary".
    """
    if grant is None or not grant.direct:
        return
    for layer, found in matched:
        if layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY and not found:
            raise UnsupportedPolicyFeature(
                "the trust policy names the caller directly, and the caller's permissions "
                "boundary doesn't allow this: AWS's trust policy page says the boundary must "
                "allow it, but its evaluation logic page says a boundary doesn't limit a grant "
                "to a user ARN"
            )


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
                applies, principal_match = _applies(statement, request)
                if applies:
                    found.append(MatchedStatement(
                        policy.name, statement, policy.via_group, layer, principal_match, index
                    ))
            except MissingContextError as exc:
                missing += [(key, _where(policy, index, statement)) for key in exc.keys]
            except PolicyError as exc:
                raise type(exc)(f"{_where(policy, index, statement)}: {exc}") from None
    return found


def _resource_patterns(statement: Statement, context: RequestContext) -> Sequence[Pattern]:
    """The statement's resource patterns, with any policy variables filled in.

    A pattern with a variable that has no value matches nothing (see `variables`), so it is left
    out: a Resource with only such patterns covers nothing, and a NotResource excludes nothing.
    """
    if not statement.policy_variables:
        return statement.resources
    templates = [variables.parse(resource) for resource in statement.resources]
    _require([key for template in templates for key in variables.keys(template)], context)
    patterns = [variables.resolve(template, context) for template in templates]
    return [pattern for pattern in patterns if pattern is not None]


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
