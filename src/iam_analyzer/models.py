"""Plain data types shared by the loader, evaluator and CLI."""

from dataclasses import dataclass, field
from enum import Enum


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


@dataclass(frozen=True)
class Statement:
    """One normalized policy statement. Action and Resource are always tuples.

    `not_action` / `not_resource` mean the statement used NotAction / NotResource: the
    patterns list what the statement does NOT cover, and it applies to everything else.
    """

    effect: Effect
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    sid: str | None = None
    not_action: bool = False
    not_resource: bool = False


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
    """The question being asked: can the principal perform `action` on `resource`?"""

    action: str
    resource: str


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
