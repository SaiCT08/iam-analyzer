"""Plain data types shared by the loader, evaluator and CLI."""

import re
from dataclasses import dataclass, field
from enum import Enum

from iam_analyzer.context import RequestContext
from iam_analyzer.errors import RequestError

# One concrete action: a service prefix, a colon, and a name with no wildcards.
_CONCRETE_ACTION = re.compile(r"[A-Za-z0-9-]+:[^*?]+")


class Effect(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"


class Decision(str, Enum):
    """The three possible outcomes of AWS policy evaluation."""

    ALLOW = "ALLOW"
    EXPLICIT_DENY = "EXPLICIT_DENY"  # a matching Deny statement exists
    IMPLICIT_DENY = "IMPLICIT_DENY"  # nothing allowed it (the default)

    @property
    def allowed(self) -> bool:
        return self is Decision.ALLOW


class PolicyType(str, Enum):
    """The kinds of policy AWS evaluates, named as in the AWS docs."""

    IDENTITY = "identity"
    PERMISSIONS_BOUNDARY = "permissions boundary"
    SCP = "SCP"


class TargetType(str, Enum):
    """What an SCP can be attached to, using AWS Organizations' names."""

    ROOT = "ROOT"
    ORGANIZATIONAL_UNIT = "ORGANIZATIONAL_UNIT"
    ACCOUNT = "ACCOUNT"


class SetOperator(str, Enum):
    """A condition prefix for keys that can have several values in the request."""

    FOR_ALL_VALUES = "ForAllValues"  # every request value must pass
    FOR_ANY_VALUE = "ForAnyValue"  # at least one request value must pass


@dataclass(frozen=True)
class Condition:
    """One test from a statement's Condition block: does the request's `key` pass `operator`?

    "ForAnyValue:StringLikeIfExists" is stored as operator "StringLike", set_operator
    FOR_ANY_VALUE and if_exists True. Values are kept as text, since AWS lets numbers and
    booleans go unquoted: 10 is stored as "10" and true as "true".
    """

    operator: str
    key: str  # as written, such as "aws:SourceIp"
    values: tuple[str, ...]
    set_operator: SetOperator | None = None
    if_exists: bool = False

    @property
    def name(self) -> str:
        """The operator as a policy writes it, such as "ForAnyValue:StringLikeIfExists"."""
        prefix = f"{self.set_operator.value}:" if self.set_operator else ""
        return f"{prefix}{self.operator}{'IfExists' if self.if_exists else ''}"


@dataclass(frozen=True)
class Statement:
    """One normalized policy statement. Action and Resource are always tuples.

    `not_action` / `not_resource` mean the statement used NotAction / NotResource: the
    patterns list what the statement does NOT cover, and it applies to everything else.

    `policy_variables` is True when the policy has "Version": "2012-10-17". Then ${...} in a
    resource or condition value is a policy variable that AWS fills in from the request;
    otherwise it is plain text.

    The statement applies only when every one of its `conditions` holds.
    """

    effect: Effect
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    sid: str | None = None
    not_action: bool = False
    not_resource: bool = False
    policy_variables: bool = False
    conditions: tuple[Condition, ...] = ()


@dataclass(frozen=True)
class Policy:
    """A named policy: the name is used when explaining results (e.g. the file name).

    `via_group` records how a principal got this policy: the group's name when it was
    inherited through group membership, None when attached directly.
    """

    name: str
    statements: tuple[Statement, ...]
    via_group: str | None = None


@dataclass(frozen=True)
class Request:
    """The question being asked: can the principal perform `action` on `resource`?

    Like a real AWS request, it names one concrete action ("s3:GetObject"), never a pattern
    such as "s3:*". A pattern would be matched as literal text, so a policy's "s3:*" would
    match it while a Deny on "s3:DeleteObject" would not: a wrong answer.

    `context` holds the request's condition keys, such as aws:username, which policy
    variables read. By default it knows nothing, which is enough for policies without them.
    """

    action: str
    resource: str
    context: RequestContext = field(default_factory=RequestContext)

    def __post_init__(self) -> None:
        if not _CONCRETE_ACTION.fullmatch(self.action):
            raise RequestError(
                "the action must be one AWS action such as 's3:GetObject', with no wildcards; "
                f"got {self.action!r}"
            )


@dataclass(frozen=True)
class OrgTarget:
    """A place in an AWS organization that SCPs attach to: the root, an OU, or an account."""

    type: TargetType
    name: str  # "Root", the OU's name, or the 12-digit account ID


@dataclass(frozen=True)
class ScpLevel:
    """One step on the path from the organization root down to an account, with the SCPs
    attached there. Any SCP at a level can allow a request, but every level must allow it.
    """

    target: OrgTarget
    policies: tuple[Policy, ...]


@dataclass(frozen=True)
class Layer:
    """One layer of evaluation: the identity policies, the permissions boundary, or the
    SCPs at one level of the organization.

    A request needs a matching Allow in every layer that applies, and a matching Deny in
    any layer denies it. SCPs apply level by level (the root, each OU, then the account),
    so each level is its own layer and `org_target` says which one.
    """

    policy_type: PolicyType
    org_target: OrgTarget | None = None


@dataclass(frozen=True)
class MatchedStatement:
    """A statement that matched the request, plus the policy and layer it came from."""

    policy_name: str
    statement: Statement
    via_group: str | None = None
    layer: Layer = Layer(PolicyType.IDENTITY)


@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    # Statements that determined the decision: the matching Denies for EXPLICIT_DENY,
    # the matching Allows from every layer for ALLOW, and empty for IMPLICIT_DENY.
    reasons: tuple[MatchedStatement, ...] = field(default_factory=tuple)
    # For IMPLICIT_DENY: each layer that had no matching Allow. Empty otherwise.
    not_allowed_by: tuple[Layer, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.decision.allowed
