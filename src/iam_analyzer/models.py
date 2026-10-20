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
class MatchedStatement:
    """A statement that matched the request, plus the policy it came from."""

    policy_name: str
    statement: Statement
    via_group: str | None = None


@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    # Statements that determined the decision: the matching Denies for EXPLICIT_DENY,
    # the matching Allows for ALLOW, and empty for IMPLICIT_DENY.
    reasons: tuple[MatchedStatement, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.decision.allowed
