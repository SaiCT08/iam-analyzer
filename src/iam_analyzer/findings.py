"""Policy findings: AWS surprises in the policy text, which need no question to find.

Each finding type says what AWS does, why it matters, how to fix it, and the evidence behind it:
answers recorded from AWS's IAM policy simulator (fixtures in tests/simulator_fixtures, with
AWS's decision) and quotes from AWS's documentation. Tests check that every cited fixture exists
and that AWS's recorded decision is the one the finding type claims.

Severity follows one rule, unless a finding type says otherwise: high when the surprise can let a
request through that the policy's author meant to stop, such as a Deny that never applies or an
Allow that always applies, and low when it can only stop a request the author meant to let through.

Every policy is scanned: the account file's named policies (identity policies and boundaries,
with where each is attached), its bucket policies and trust policies, and with an organization,
its SCPs. Where a policy is used stays in typed fields until the report prints it.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from iam_analyzer.account import Account
from iam_analyzer.framework import Severity
from iam_analyzer.models import Condition, Effect, OrgTarget, Policy, PolicyType, Statement
from iam_analyzer.organization import Organization

SIMULATOR_FIXTURES = "tests/simulator_fixtures"
POLICY_VARIABLES_PAGE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html"
)


@dataclass(frozen=True)
class Fixture:
    """An answer recorded from AWS's IAM policy simulator: the case, and AWS's decision."""

    case: str  # such as "dates_without_a_time_zone/four_digits"
    aws: str  # "ALLOW", "EXPLICIT_DENY" or "IMPLICIT_DENY"


@dataclass(frozen=True)
class Doc:
    link: str
    quote: str


@dataclass(frozen=True)
class FindingType:
    id: str
    title: str
    why: str
    fix: str
    fixtures: tuple[Fixture, ...] = ()
    docs: tuple[Doc, ...] = ()


@dataclass(frozen=True)
class Use:
    """Where a policy applies: attached to a user, group or role (`principal`), as a user's or
    role's permissions boundary, on a resource or role (`resource`), or as an SCP on part of the
    organization (`org_target`)."""

    policy_type: PolicyType
    principal: str | None = None
    resource: str | None = None
    org_target: OrgTarget | None = None


@dataclass(frozen=True)
class Finding:
    """One finding: a statement, where its policy is used, and the condition it's about."""

    type: FindingType
    severity: Severity
    kind: PolicyType  # the kind of policy: identity (boundaries included), resource-based, trust, SCP
    policy: Policy
    index: int
    uses: tuple[Use, ...]  # empty when the policy isn't attached to anything
    condition: Condition | None = None

    @property
    def statement(self) -> Statement:
        return self.policy.statements[self.index]


# --- Finding types ---------------------------------------------------------------------

DATE_NUMBER = FindingType(
    id="date-number-is-epoch-seconds",
    title="A four-digit date is read as epoch seconds",
    why="AWS reads a number in a date condition as epoch seconds, four digits included, so a "
    "value such as 2027 is a moment early on January 1, 1970, not the year.",
    fix="Write the date in ISO 8601 with a time zone, such as 2027-01-01T00:00:00Z.",
    fixtures=(Fixture("dates_without_a_time_zone/four_digits", "ALLOW"),),
)
BOOL_VARIABLE = FindingType(
    id="bool-variable-never-matches",
    title="A Bool value with a policy variable never matches",
    why="AWS doesn't fill in a policy variable in a Bool value: the text stays as written, so it "
    "is neither true nor false, and the condition never matches a request that has the key.",
    fix="Compare the key with true or false. A policy variable only works in String and ARN "
    "values.",
    fixtures=(
        Fixture("bool_with_a_variable/mfa_true", "IMPLICIT_DENY"),
        Fixture("bool_with_a_variable/mfa_false", "IMPLICIT_DENY"),
    ),
    docs=(Doc(POLICY_VARIABLES_PAGE,
              "You can't use a policy variable with other operators, such as Numeric, Date, "
              "Boolean, Binary, IP Address, or Null operators."),),
)

TYPES = (DATE_NUMBER, BOOL_VARIABLE)


# --- Scanning --------------------------------------------------------------------------

Detector = Callable[[PolicyType, Statement], Iterator[tuple[FindingType, Severity, Condition]]]


def scan(account: Account, *, organization: Organization | None) -> tuple[Finding, ...]:
    """Every finding in the account file's policies, and in the organization's SCPs."""
    found: list[Finding] = []
    for name, policy in account.policies.items():
        found += _findings(PolicyType.IDENTITY, policy, _uses(account, name))
    for arn, resource in account.resources.items():
        if resource.policy is not None:
            uses = (Use(PolicyType.RESOURCE_BASED, resource=arn),)
            found += _findings(PolicyType.RESOURCE_BASED, resource.policy, uses)
    for role in account.roles.values():
        if role.trust_policy is not None:
            uses = (Use(PolicyType.TRUST, resource=role.trust_policy.name),)
            found += _findings(PolicyType.TRUST, role.trust_policy, uses)
    if organization is not None:
        for name, policy in organization.policies.items():
            found += _findings(PolicyType.SCP, policy, _scp_uses(organization, name))
    return tuple(sorted(found, key=lambda f: (f.severity.rank, f.policy.name, f.index)))


def _findings(kind: PolicyType, policy: Policy, uses: tuple[Use, ...]) -> list[Finding]:
    return [
        Finding(finding_type, severity, kind, policy, index, uses, condition)
        for index, statement in enumerate(policy.statements)
        for detect in DETECTORS
        for finding_type, severity, condition in detect(kind, statement)
    ]


def _uses(account: Account, name: str) -> tuple[Use, ...]:
    """Where the account file attaches the policy called `name`."""
    uses = []
    for user_name, user in account.users.items():
        if name in user.policies:
            uses.append(Use(PolicyType.IDENTITY, principal=f"user/{user_name}"))
        if user.boundary == name:
            uses.append(Use(PolicyType.PERMISSIONS_BOUNDARY, principal=f"user/{user_name}"))
    for group_name, group in account.groups.items():
        if name in group.policies:
            uses.append(Use(PolicyType.IDENTITY, principal=f"group/{group_name}"))
    for role_name, role in account.roles.items():
        if name in role.policies:
            uses.append(Use(PolicyType.IDENTITY, principal=f"role/{role_name}"))
        if role.boundary == name:
            uses.append(Use(PolicyType.PERMISSIONS_BOUNDARY, principal=f"role/{role_name}"))
    return tuple(uses)


def _scp_uses(organization: Organization, name: str) -> tuple[Use, ...]:
    """Where the organization attaches the SCP called `name`: each root, OU or account once."""
    uses: list[Use] = []
    for levels in organization.account_paths.values():
        for level in levels:
            use = Use(PolicyType.SCP, org_target=level.target)
            if any(p.name == name for p in level.policies) and use not in uses:
                uses.append(use)
    return tuple(uses)


def _opens(statement: Statement, *, always: bool) -> Severity:
    """The severity rule for a condition that always holds (`always`) or never does."""
    allow = statement.effect is Effect.ALLOW
    return Severity.HIGH if allow == always else Severity.LOW


# --- Detectors -------------------------------------------------------------------------

# Date operators that hold for every moment after a value in 1970, and the ones that never do.
_ALWAYS_AFTER_1970 = ("DateGreaterThan", "DateGreaterThanEquals", "DateNotEquals")


def _date_numbers(kind: PolicyType, statement: Statement):
    for condition in statement.conditions:
        if condition.operator.startswith("Date") and any(
                len(value) == 4 and value.isdigit() for value in condition.values):
            always = condition.operator in _ALWAYS_AFTER_1970
            yield DATE_NUMBER, _opens(statement, always=always), condition


def _bool_variables(kind: PolicyType, statement: Statement):
    for condition in statement.conditions:
        if (condition.operator == "Bool" and statement.policy_variables
                and any("${" in value for value in condition.values)):
            yield BOOL_VARIABLE, _opens(statement, always=False), condition


DETECTORS: tuple[Detector, ...] = (_date_numbers, _bool_variables)
