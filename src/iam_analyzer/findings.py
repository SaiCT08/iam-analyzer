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

import ipaddress
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from iam_analyzer.account import Account
from iam_analyzer.conditions import OPERATORS
from iam_analyzer.framework import Severity
from iam_analyzer.matching import match_action
from iam_analyzer.models import (
    Condition,
    Effect,
    OrgTarget,
    Policy,
    PolicyType,
    Principal,
    PrincipalType,
    SetOperator,
    Statement,
)
from iam_analyzer.organization import Organization
from iam_analyzer.resources import Arn

SIMULATOR_FIXTURES = "tests/simulator_fixtures"
POLICY_VARIABLES_PAGE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html"
)
PRINCIPAL_PAGE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
)
S3_PUBLIC_PAGE = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
    "#access-control-block-public-access-policy-status"
)
EXTERNAL_ID_PAGE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html"
    "#id_roles_third-party_external-id"
)
EVERYONE = Principal(PrincipalType.AWS, "*")
_ACCOUNT_ID = re.compile(r"[0-9]{12}")


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
    """One finding: a statement, where its policy is used, and the condition or the principal
    it's about. `unsettled` lists conditions whose effect AWS's docs don't settle, such as a
    condition on a principal key that S3's definition of public doesn't name."""

    type: FindingType
    severity: Severity
    kind: PolicyType  # the kind of policy: identity (boundaries included), resource-based, trust, SCP
    policy: Policy
    index: int
    uses: tuple[Use, ...]  # empty when the policy isn't attached to anything
    condition: Condition | None = None
    principal: Principal | None = None
    unsettled: tuple[Condition, ...] = ()

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

PUBLIC_BUCKET = FindingType(
    id="public-bucket-policy",
    title="A bucket policy grants access to everyone",
    why='The statement allows "*", and no condition limits it to fixed values of a key that S3 '
    "names, such as aws:SourceVpce or aws:PrincipalOrgID, so S3 counts the policy as public: "
    "anyone on the internet can make the request, unless S3 Block Public Access stops it, which "
    "the analyzer doesn't model.",
    fix="Name the account or role that needs access instead of \"*\", or limit the grant with a "
    "fixed aws:SourceVpce or aws:PrincipalOrgID, and turn on S3 Block Public Access.",
    docs=(Doc(S3_PUBLIC_PAGE,
              "When evaluating a bucket policy, Amazon S3 begins by assuming that the policy is "
              "public. It then evaluates the policy to determine whether it qualifies as "
              "non-public."),),
)
TRUST_EVERYONE = FindingType(
    id="trust-policy-names-everyone",
    title="A trust policy lets everyone assume the role",
    why='The statement names "*", so any principal in any AWS account can assume the role, '
    "unless its conditions stop them.",
    fix="Name the accounts, users or roles that may assume the role instead of \"*\".",
    docs=(Doc(PRINCIPAL_PAGE, "Do not leave your role accessible to everyone!"),),
)
CROSS_ACCOUNT_TRUST = FindingType(
    id="cross-account-trust-without-external-id",
    title="Another account can assume the role without an external ID",
    why="The trust policy lets an account outside the organization assume the role with no "
    "sts:ExternalId condition. If that account is a third party serving several customers, "
    "anyone it serves could get it to use this role: the confused deputy problem.",
    fix="Add a condition such as StringEquals sts:ExternalId with the ID the third party gives "
    "you.",
    docs=(Doc(EXTERNAL_ID_PAGE,
              "The primary function of the external ID is to address and prevent The confused "
              "deputy problem."),),
)
UNIQUE_ID = FindingType(
    id="principal-is-a-unique-id",
    title="A principal is shown as a unique ID, so it was deleted",
    why="AWS shows a principal's unique ID when the user or role it named was deleted. The "
    "statement no longer applies to anyone, even to a new principal with the same name.",
    fix="Name the principal again by its ARN, or remove the statement.",
    docs=(Doc(PRINCIPAL_PAGE,
              "The policy no longer applies, even if you recreate the role because the new role "
              "has a new principal ID that does not match the ID stored in the trust policy."),),
)

TYPES = (DATE_NUMBER, BOOL_VARIABLE, PUBLIC_BUCKET, TRUST_EVERYONE, CROSS_ACCOUNT_TRUST, UNIQUE_ID)


# --- Scanning --------------------------------------------------------------------------

@dataclass(frozen=True)
class _Scope:
    """What a detector may need to know beyond the statement."""

    kind: PolicyType
    account_id: str | None
    organization_accounts: frozenset[str]  # empty without an organization


@dataclass(frozen=True)
class _Hit:
    type: FindingType
    severity: Severity
    condition: Condition | None = None
    principal: Principal | None = None
    unsettled: tuple[Condition, ...] = ()


Detector = Callable[[Statement, _Scope], Iterator[_Hit]]


def scan(account: Account, *, organization: Organization | None) -> tuple[Finding, ...]:
    """Every finding in the account file's policies, and in the organization's SCPs."""
    accounts = frozenset(organization.account_paths) if organization else frozenset()

    def findings(kind: PolicyType, policy: Policy, uses: tuple[Use, ...]) -> list[Finding]:
        scope = _Scope(kind, account.account_id, accounts)
        return [
            Finding(hit.type, hit.severity, kind, policy, index, uses, hit.condition,
                    hit.principal, hit.unsettled)
            for index, statement in enumerate(policy.statements)
            for detect in DETECTORS
            for hit in detect(statement, scope)
        ]

    found: list[Finding] = []
    for name, policy in account.policies.items():
        found += findings(PolicyType.IDENTITY, policy, _uses(account, name))
    for arn, resource in account.resources.items():
        if resource.policy is not None:
            uses = (Use(PolicyType.RESOURCE_BASED, resource=arn),)
            found += findings(PolicyType.RESOURCE_BASED, resource.policy, uses)
    for role in account.roles.values():
        if role.trust_policy is not None:
            uses = (Use(PolicyType.TRUST, resource=role.trust_policy.name),)
            found += findings(PolicyType.TRUST, role.trust_policy, uses)
    if organization is not None:
        for name, policy in organization.policies.items():
            found += findings(PolicyType.SCP, policy, _scp_uses(organization, name))
    return tuple(sorted(found, key=lambda f: (f.severity.rank, f.policy.name, f.index)))


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


def _covers_action(statement: Statement, action: str) -> bool:
    # NotAction covers every action it doesn't list.
    return any(match_action(p, action) for p in statement.actions) != statement.not_action


# --- Detectors -------------------------------------------------------------------------

# Date operators that hold for every moment after a value in 1970, and the ones that never do.
_ALWAYS_AFTER_1970 = ("DateGreaterThan", "DateGreaterThanEquals", "DateNotEquals")


def _date_numbers(statement: Statement, scope: _Scope) -> Iterator[_Hit]:
    for condition in statement.conditions:
        if condition.operator.startswith("Date") and any(
                len(value) == 4 and value.isdigit() for value in condition.values):
            always = condition.operator in _ALWAYS_AFTER_1970
            yield _Hit(DATE_NUMBER, _opens(statement, always=always), condition)


def _bool_variables(statement: Statement, scope: _Scope) -> Iterator[_Hit]:
    for condition in statement.conditions:
        if (condition.operator == "Bool" and statement.policy_variables
                and any("${" in value for value in condition.values)):
            yield _Hit(BOOL_VARIABLE, _opens(statement, always=False), condition)


# The keys S3's definition of public names: a "*" grant limited to fixed values of one of them
# isn't public.
_S3_LISTED_KEYS = frozenset(key.casefold() for key in (
    "aws:SourceIp", "aws:SourceArn", "aws:SourceVpc", "aws:SourceVpce", "aws:SourceOwner",
    "aws:SourceAccount", "aws:userid", "s3:DataAccessPointArn", "s3:DataAccessPointAccount",
    "aws:PrincipalOrgID",
))


def _public_bucket(statement: Statement, scope: _Scope) -> Iterator[_Hit]:
    """A bucket policy's "*" grant that S3 counts as public: no condition limits it to fixed
    values of a key S3 names. A fixed condition on another principal key, such as
    aws:PrincipalArn, is reported as unsettled: S3 gives aws:PrincipalOrgID only as an example of
    "An AWS principal, user, role, or service principal"."""
    if (scope.kind is not PolicyType.RESOURCE_BASED or statement.effect is not Effect.ALLOW
            or EVERYONE not in (statement.principals or ())):
        return
    variables = statement.policy_variables
    if any(_s3_pins(condition, variables) for condition in statement.conditions):
        return
    unsettled = tuple(
        condition for condition in statement.conditions
        if condition.key.casefold().startswith("aws:principal") and _pins(condition, variables)
    )
    yield _Hit(PUBLIC_BUCKET, Severity.HIGH, principal=EVERYONE, unsettled=unsettled)


def _pins(condition: Condition, policy_variables: bool) -> bool:
    """Whether the condition limits a request to fixed values of its key: values with no wildcard
    and no policy variable, with an operator that only holds for those values."""
    return _limits(condition) and all(_fixed(v, policy_variables) for v in condition.values)


def _limits(condition: Condition) -> bool:
    """Whether the operator only holds for a request with one of the condition's values.
    Negated operators, IfExists, ForAllValues and Null hold for other requests too: ones with
    other values, or without the key."""
    return not (OPERATORS[condition.operator].negated or condition.operator == "Null"
                or condition.if_exists or condition.set_operator is SetOperator.FOR_ALL_VALUES)


def _s3_pins(condition: Condition, policy_variables: bool) -> bool:
    """Whether the condition pins a key S3 names, with S3's rules for two of them."""
    key = condition.key.casefold()
    if key not in _S3_LISTED_KEYS:
        return False
    if key == "aws:sourceip":
        # "values broader than /8 for IPv4 and /32 for IPv6 (excluding RFC1918 private ranges)"
        # are public. Every RFC1918 range is /8 or narrower, so that exception changes nothing.
        return condition.operator == "IpAddress" and _pins(condition, policy_variables) and all(
            ipaddress.ip_network(value, strict=False).prefixlen >= (8 if ":" not in value else 32)
            for value in condition.values
        )
    if key == "s3:dataaccesspointarn":
        # A wildcard in the access point's name is fine, "as long as the account ID is fixed".
        return _pins_access_point(condition, policy_variables)
    return _pins(condition, policy_variables)


def _pins_access_point(condition: Condition, policy_variables: bool) -> bool:
    if not _limits(condition):
        return False
    for value in condition.values:
        fields = value.split(":", 5)
        if len(fields) != 6 or not all(_fixed(field, policy_variables) for field in fields[:5]):
            return False
        name = fields[5].removeprefix("accesspoint/")
        if name == fields[5] or (policy_variables and "${" in name):
            return False
    return True


def _fixed(value: str, policy_variables: bool) -> bool:
    return "*" not in value and "?" not in value and not (policy_variables and "${" in value)


def _trust_everyone(statement: Statement, scope: _Scope) -> Iterator[_Hit]:
    if (scope.kind is PolicyType.TRUST and statement.effect is Effect.ALLOW
            and EVERYONE in (statement.principals or ())):
        severity = Severity.HIGH if statement.conditions else Severity.CRITICAL
        yield _Hit(TRUST_EVERYONE, severity, principal=EVERYONE)


def _cross_account_trust(statement: Statement, scope: _Scope) -> Iterator[_Hit]:
    """An AssumeRole grant to another account, or its users and roles, with no sts:ExternalId
    condition. Accounts in the organization aren't third parties, so they're left out."""
    if (scope.kind is not PolicyType.TRUST or statement.effect is not Effect.ALLOW
            or not _covers_action(statement, "sts:AssumeRole")
            or any(c.key.casefold() == "sts:externalid" for c in statement.conditions)):
        return
    for principal in statement.principals or ():
        account = _account_of(principal)
        if account and account != scope.account_id and account not in scope.organization_accounts:
            yield _Hit(CROSS_ACCOUNT_TRUST, Severity.MEDIUM, principal=principal)


def _account_of(principal: Principal) -> str | None:
    """The account a principal names: an account ID, or the account field of its ARN."""
    if principal.type is not PrincipalType.AWS:
        return None
    if _ACCOUNT_ID.fullmatch(principal.value):
        return principal.value
    arn = Arn.parse(principal.value)
    return None if arn is None else arn.account_id


def _unique_ids(statement: Statement, scope: _Scope) -> Iterator[_Hit]:
    """An AWS principal that's neither "*", an account ID nor an ARN. The loader accepts nothing
    else but IAM unique IDs (`principals`)."""
    if scope.kind not in (PolicyType.RESOURCE_BASED, PolicyType.TRUST):
        return
    for principal in statement.principals or ():
        value = principal.value
        if (principal.type is PrincipalType.AWS and value != "*"
                and not _ACCOUNT_ID.fullmatch(value) and Arn.parse(value) is None):
            severity = Severity.HIGH if statement.effect is Effect.DENY else Severity.LOW
            yield _Hit(UNIQUE_ID, severity, principal=principal)


DETECTORS: tuple[Detector, ...] = (
    _date_numbers, _bool_variables, _public_bucket, _trust_everyone, _cross_account_trust,
    _unique_ids,
)
