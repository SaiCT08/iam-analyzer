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
    RESOURCE_BASED = "resource-based"  # attached to a resource, such as an S3 bucket policy
    # A role's trust policy, IAM's kind of resource-based policy. It must allow the STS actions on
    # its role, such as sts:AssumeRole.
    TRUST = "trust"


class PrincipalType(str, Enum):
    """The kinds of principal a Principal element names, spelled as in a policy."""

    AWS = "AWS"
    SERVICE = "Service"
    FEDERATED = "Federated"
    CANONICAL_USER = "CanonicalUser"


class PrincipalMatch(str, Enum):
    """How a resource-based policy's statement named the caller. It decides which other layers
    still have to allow the request."""

    EVERYONE = "everyone"  # "*"
    USER = "user"  # the caller's own user ARN
    ROLE = "role"  # the ARN of the role whose session the caller is
    ACCOUNT = "account"  # the caller's account, which delegates to its identity-based policies

    @property
    def direct(self) -> bool:
        """A grant straight to the caller, which neither identity policies nor a boundary limit."""
        return self in (PrincipalMatch.EVERYONE, PrincipalMatch.USER)


@dataclass(frozen=True)
class Principal:
    """One principal from a Principal element: {"AWS": "111122223333"} is
    Principal(PrincipalType.AWS, "111122223333"). "Principal": "*" is stored as AWS "*", which AWS
    documents as the same thing."""

    type: PrincipalType
    value: str


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

    `principals` is the Principal element of a resource-based policy's statement: it applies only
    when one of them names the caller. It is None in identity-based policies, which have none.
    `not_principal` means the statement used NotPrincipal, which AWS only allows with Deny: the
    principals are the ones it does NOT cover.

    `resources` is empty in a role's trust policy, which has no Resource element: its statements
    cover the role the policy belongs to.
    """

    effect: Effect
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    sid: str | None = None
    not_action: bool = False
    not_resource: bool = False
    policy_variables: bool = False
    conditions: tuple[Condition, ...] = ()
    principals: tuple[Principal, ...] | None = None
    not_principal: bool = False


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
class Resource:
    """What the analyzer can't tell from a resource's ARN: its resource-based policy, and that it
    is in the principal's own account.

    `arn` is the resource the policy is attached to. For an S3 object, that is its bucket, whose
    policy covers its objects. `policy` is None when the resource has no resource-based policy.

    Describing an S3 bucket also says its ACLs are disabled (Object Ownership "Bucket owner
    enforced"). Then the bucket policy is the only resource-based control on its objects: with
    ACLs on, ACL grants could add access and objects could belong to other accounts, and the
    analyzer models neither.
    """

    arn: str
    policy: Policy | None = None


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
    """One layer of evaluation: the identity policies, the permissions boundary, the SCPs at one
    level of the organization, or the resource-based policy of the resource the request is on.

    A matching Deny in any layer denies the request. SCPs apply level by level (the root, each
    OU, then the account), so each level is its own layer and `org_target` says which one. Every
    SCP level needs a matching Allow. A resource-based policy can stand in for the identity
    policies, and sometimes the boundary, as `evaluator` explains. `resource` is the ARN that
    policy is attached to.
    """

    policy_type: PolicyType
    org_target: OrgTarget | None = None
    resource: str | None = None


@dataclass(frozen=True)
class MatchedStatement:
    """A statement that matched the request, plus the policy and layer it came from.

    For a resource-based policy's statement, `principal_match` says how its Principal named the
    caller. `index` is the statement's position in its policy, counting from 0, so a statement
    without a Sid can still be named: "FullAWSAccess statement 0".
    """

    policy_name: str
    statement: Statement
    via_group: str | None = None
    layer: Layer = Layer(PolicyType.IDENTITY)
    principal_match: PrincipalMatch | None = None
    index: int | None = None


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
