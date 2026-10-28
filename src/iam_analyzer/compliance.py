"""Running a framework's checks against an account file.

Each check asks the engine one question per principal, action and resource (an *item*), and
grades the answers as PASS, FAIL, DEPENDS or CAN'T TELL:
  - A check that forbids access ("only", "requires") FAILs when any answer allows the request, and
    the item lists the values that allow it. It PASSes when every answer is denied, and is CAN'T
    TELL when none allows but the engine refused some. DEPENDS never softens a prohibition.
  - A "can" check PASSes when every answer allows the request, FAILs when every answer denies it,
    and DEPENDS when some values allow it and others don't.
A check takes its worst item: FAIL, then DEPENDS, then CAN'T TELL, then PASS.

An item can have several answers because a check states only what its question fixes. When a
matching statement needs a condition key the check doesn't give, and AWS documents every value the
key can have (`condition_keys`), the engine is asked once with each value. Which keys a request
needs depends only on matching its action, resource and principal, never on the keys' values, so
one try finds them all. A key whose values AWS doesn't list stays the engine's refusal, CAN'T
TELL, until the check gives it a value.

A refusal is never a PASS, and neither is a principal the engine can't ask about. When a resource
or trust policy allows the action for someone outside the account file, such as "*" or another
account, the check gets a CAN'T TELL entry that cites the statement.

A "requires" check on a key AWS checks when a role is assumed, such as aws:MultiFactorAuthPresent
(`condition_keys`), treats roles differently. A role's own requests never show MFA, so a role
allowed to do something without MFA is asked a second question: can anyone assume the role
without MFA? If no one can, and the trust policy lets no one outside the account file assume it,
the role's item PASSes. If someone can, it FAILs and names them; otherwise it's CAN'T TELL. The
second question goes one level deep: it doesn't ask it again about the roles it asks.
"""

import itertools
import re
from collections.abc import Iterator
from dataclasses import dataclass, replace
from enum import Enum

from iam_analyzer import condition_keys, resources
from iam_analyzer.account import Account
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import (
    AccountError,
    FrameworkError,
    MissingContextError,
    MissingResourceError,
    PolicyError,
    RequestError,
    UnsupportedPolicyFeature,
)
from iam_analyzer.framework import Check, CheckType, Framework
from iam_analyzer.matching import match_action, match_resource
from iam_analyzer.models import (
    Effect,
    EvaluationResult,
    Layer,
    Policy,
    Principal,
    PrincipalType,
    Statement,
)
from iam_analyzer.organization import Organization

_ACCOUNT_ID = re.compile(r"[0-9]{12}")


class Result(str, Enum):
    FAIL = "FAIL"
    DEPENDS = "DEPENDS"
    CANT_TELL = "CANT_TELL"
    PASS = "PASS"

    @property
    def rank(self) -> int:
        """0 for the worst result. A check takes the worst result of its items."""
        return list(Result).index(self)


@dataclass(frozen=True)
class Refusal:
    """Why the engine gave no answer: the error's kind and message, and the condition keys or the
    resource it says it needs."""

    kind: str  # such as "MissingResourceError"
    message: str
    keys: tuple[str, ...] = ()
    resource: str | None = None


@dataclass(frozen=True)
class Answer:
    """The engine's answer when the keys tried have these values. None means absent."""

    values: tuple[tuple[str, str | None], ...] = ()
    result: EvaluationResult | None = None
    refusal: Refusal | None = None

    @property
    def allowed(self) -> bool | None:
        """Whether the request is allowed, or None when the engine refused."""
        return None if self.result is None else self.result.allowed


@dataclass(frozen=True)
class RoleMfaNote:
    """For a role in a "requires" check on a key AWS checks when a role is assumed, such as
    aws:MultiFactorAuthPresent. `statements` are the indexes of the trust policy's Allows that let
    someone assume the role, with sts:AssumeRole or as a SAML or OIDC user. The trust policy is
    None when the account file doesn't give it.

    When the role is allowed without the key, `assume` is the second question the check asked
    about it: can anyone assume the role without the key? Its result is the role item's result.
    `refusal` says why it couldn't be asked, which makes the item CAN'T TELL.
    """

    role: str
    key: str
    trust_policy: Policy | None
    statements: tuple[int, ...] = ()
    assume: "CheckResult | None" = None
    refusal: Refusal | None = None

    @property
    def asked(self) -> bool:
        """Whether the role was allowed without the key, so the second question was asked."""
        return self.assume is not None or self.refusal is not None

    @property
    def result(self) -> "Result":
        """What the second question means for the role's item."""
        return self.assume.result if self.assume is not None else Result.CANT_TELL


@dataclass(frozen=True)
class Item:
    """One question: can `principal` do `action` on `resource`? `turns_on` names the keys whose
    value alone changes the answer."""

    principal: str
    action: str
    resource: str
    result: Result
    answers: tuple[Answer, ...]
    turns_on: tuple[str, ...] = ()
    note: RoleMfaNote | None = None


@dataclass(frozen=True)
class Outside:
    """A statement in a resource or trust policy that allows `action` on `resource` for
    `principals` outside the account file, whom the engine can't ask about."""

    policy: Policy
    index: int
    layer: Layer
    principals: tuple[Principal, ...]
    action: str
    resource: str


@dataclass(frozen=True)
class CheckResult:
    """A check's result. `not_asked` are the principals an "only" check allows, or a "requires"
    check leaves out, so they have no items."""

    check: Check
    result: Result
    items: tuple[Item, ...]
    outside: tuple[Outside, ...] = ()
    not_asked: tuple[str, ...] = ()


def run(
    framework: Framework, account: Account, *, organization: Organization | None
) -> tuple[CheckResult, ...]:
    """Run every check in `framework` against `account`. `organization` is None when the account
    isn't in one, so no SCPs apply."""
    if organization is not None:
        if account.account_id is None:
            raise AccountError(f"{account.name}: needs an 'AccountId' to look up its SCPs")
        organization.scp_levels_for(account.account_id)  # refuses an account it doesn't hold
    return tuple(
        run_check(check, account, organization=organization, where=framework.name)
        for check in framework.checks
    )


def run_check(
    check: Check, account: Account, *, organization: Organization | None, where: str = "framework"
) -> CheckResult:
    where = f"{where} check {check.id!r}"
    named = _members(check.exempt if check.type is CheckType.REQUIRES else check.principals,
                     account, where)
    if check.type is CheckType.CAN:
        asked, not_asked = named, ()
    else:
        everyone = [f"user/{name}" for name in account.users] + [
            f"role/{name}" for name in account.roles
        ]
        asked, not_asked = [p for p in everyone if p not in named], tuple(named)
    assumed: dict[str, CheckResult | None] = {}  # each role's second question, asked once
    items = tuple(
        _item(check, account, organization, principal, action, resource, where, assumed)
        for principal in asked
        for action in check.actions
        for resource in check.resources
    )
    outside = () if check.type is CheckType.CAN else tuple(
        _outside(check.actions, check.resources, account)
    )
    return CheckResult(check, _worst(items, outside), items, outside, not_asked)


def _worst(items: tuple["Item", ...], outside: tuple["Outside", ...]) -> Result:
    results = [item.result for item in items] + [Result.CANT_TELL] * bool(outside)
    return min(results, key=lambda r: r.rank, default=Result.PASS)


def _members(names: tuple[str, ...], account: Account, where: str) -> list[str]:
    """The users and roles `names` stand for: a group stands for its members."""
    found: list[str] = []
    for name in names:
        kind, _, rest = name.partition("/")
        if kind == "group":
            if rest not in account.groups:
                raise FrameworkError(f"{where}: no group {rest!r} in {account.name}")
            members = [f"user/{user}" for user, entry in account.users.items()
                       if rest in entry.groups]
        else:
            if rest not in (account.users if kind == "user" else account.roles):
                raise FrameworkError(f"{where}: no {kind} {rest!r} in {account.name}")
            members = [name]
        found += [member for member in members if member not in found]
    return found


def _item(
    check: Check,
    account: Account,
    organization: Organization | None,
    principal: str,
    action: str,
    resource: str,
    where: str,
    assumed: dict[str, "CheckResult | None"] | None = None,
) -> Item:
    """One question and its answers. With `assumed`, a role in a "requires" check on a key AWS
    checks when a role is assumed gets a note, and the second question when it's allowed without
    the key. Without it, as inside the second question, no role is asked a second question."""
    answers = _answers(check, account, organization, principal, action, resource, where)
    result = _grade(check.type, answers)
    note = None
    if assumed is not None and principal.startswith("role/") and _checked_when_assumed(check):
        note = _role_mfa_note(account, principal, check.key)
        if result is Result.FAIL:  # allowed without the key, so it hangs on who can assume it
            if principal not in assumed:
                assumed[principal] = _assume_question(check, account, organization, principal,
                                                      where)
            second = assumed[principal]
            refusal = None if second is not None else Refusal(
                "AccountError",
                f"{account.name} has no AccountId, so the analyzer can't name {principal}'s ARN "
                "to ask who can assume it",
            )
            note = replace(note, assume=second, refusal=refusal)
            result = note.result
    return Item(principal, action, resource, result, answers, _turns_on(answers), note)


def _checked_when_assumed(check: Check) -> bool:
    return check.type is CheckType.REQUIRES and condition_keys.values_of(
        check.key).checked_when_assumed


def _assume_question(
    check: Check,
    account: Account,
    organization: Organization | None,
    role: str,
    where: str,
) -> "CheckResult | None":
    """The second question about a role: can anyone in the account file do sts:AssumeRole on it
    with the check's key set to its other values, such as MFA false or absent? A trust policy that
    lets someone outside the file assume the role, by sts:AssumeRole or as a SAML or OIDC user,
    makes it CAN'T TELL: AWS says that for SAML and OIDC users it "cannot determine whether that
    provider required MFA". None when the account file has no AccountId to name the role's ARN.
    """
    if account.account_id is None:
        return None
    name = role.partition("/")[2]
    arn = f"arn:aws:iam::{account.account_id}:role{account.roles[name].path}{name}"
    question = Check(
        id=f"{check.id}:assume:{name}",
        title=f"No one can assume {role} unless {check.key} is {check.value}",
        severity=check.severity,
        type=CheckType.REQUIRES,
        actions=("sts:AssumeRole",),
        resources=(arn,),
        fix=f"Require {check.key} {check.value} in every statement of {role}'s trust policy that "
        "lets someone assume it.",
        key=check.key,
        value=check.value,
    )
    everyone = [f"user/{user}" for user in account.users] + [
        f"role/{other}" for other in account.roles
    ]
    items = tuple(
        _item(question, account, organization, principal, "sts:AssumeRole", arn,
              f"{where} (who can assume {role})")
        for principal in everyone
    )
    outside = tuple(_outside(resources.ASSUME_ACTIONS, (arn,), account))
    return CheckResult(question, _worst(items, outside), items, outside)


def _answers(
    check: Check,
    account: Account,
    organization: Organization | None,
    principal: str,
    action: str,
    resource: str,
    where: str,
) -> tuple[Answer, ...]:
    """Ask once for each combination of the keys tried.

    A "requires" check tries its key's other values: for MFA true, false and absent. Any other key
    is tried once the engine says a statement needs it and AWS documents all its values.
    """
    tried: list[tuple[str, tuple[str | None, ...]]] = []
    if check.type is CheckType.REQUIRES:
        known = condition_keys.values_of(check.key)
        tried.append((known.key, tuple(v for v in known.values if v != check.value)))
    while True:
        answers = []
        needed: dict[str, condition_keys.KeyValues] = {}
        for combination in itertools.product(*(values for _, values in tried)):
            values = tuple(zip((key for key, _ in tried), combination))
            answer = _answer(check, account, organization, principal, action, resource, values,
                             where)
            if isinstance(answer, Answer):
                answers.append(answer)
            else:
                needed.update((known.key.casefold(), known) for known in answer)
        if not needed:
            return tuple(answers)
        tried += [(known.key, known.values) for known in needed.values()]


def _answer(
    check: Check,
    account: Account,
    organization: Organization | None,
    principal: str,
    action: str,
    resource: str,
    values: tuple[tuple[str, str | None], ...],
    where: str,
) -> Answer | list[condition_keys.KeyValues]:
    """The engine's answer with the keys tried set to `values`, or the keys it needs that are
    worth trying. Those are keys AWS documents every value of, that aren't tried yet."""
    tried = RequestContext.of(
        [(key, value) for key, value in values if value is not None],
        [key for key, value in values if value is None],
    )
    try:
        request = account.request(principal, action, resource, context=check.context.merged(tried))
    except RequestError as exc:
        raise FrameworkError(f"{where}: {exc}") from None
    try:
        return Answer(values, result=account.evaluate(principal, request,
                                                      organization=organization))
    except MissingContextError as exc:
        known = [condition_keys.values_of(key) for key in exc.keys]
        already = {key.casefold() for key, _ in values}
        if all(known) and not any(entry.key.casefold() in already for entry in known):
            return known
        return Answer(values, refusal=Refusal(type(exc).__name__, str(exc), keys=exc.keys))
    except MissingResourceError as exc:
        return Answer(values, refusal=Refusal(type(exc).__name__, str(exc),
                                              resource=exc.resource))
    except (UnsupportedPolicyFeature, AccountError) as exc:
        return Answer(values, refusal=Refusal(type(exc).__name__, str(exc)))
    except RequestError as exc:
        # A request AWS couldn't receive, such as a check's value that doesn't fit an operator.
        raise FrameworkError(f"{where}: asking about {principal}: {exc}") from None


def _grade(check_type: CheckType, answers: tuple[Answer, ...]) -> Result:
    allowed = any(answer.allowed is True for answer in answers)
    denied = any(answer.allowed is False for answer in answers)
    refused = any(answer.refusal is not None for answer in answers)
    if check_type.forbids:
        if allowed:
            return Result.FAIL
        return Result.CANT_TELL if refused else Result.PASS
    if allowed and denied:
        return Result.DEPENDS
    if refused:
        return Result.CANT_TELL
    return Result.PASS if allowed else Result.FAIL


def _turns_on(answers: tuple[Answer, ...]) -> tuple[str, ...]:
    """The keys whose value alone changes whether the request is allowed: two answers that differ
    only in that key, one allowed and one not."""
    decided = [answer for answer in answers if answer.allowed is not None]
    keys = [key for key, _ in decided[0].values] if decided else []
    found = []
    for position, key in enumerate(keys):
        outcomes: dict[tuple, set[bool]] = {}
        for answer in decided:
            others = answer.values[:position] + answer.values[position + 1:]
            outcomes.setdefault(others, set()).add(answer.allowed)
        if any(len(seen) > 1 for seen in outcomes.values()):
            found.append(key)
    return tuple(found)


def _role_mfa_note(account: Account, principal: str, key: str) -> RoleMfaNote:
    trust_policy = account.roles[principal.partition("/")[2]].trust_policy
    if trust_policy is None:
        return RoleMfaNote(principal, key, None)
    assumes = tuple(
        index for index, statement in enumerate(trust_policy.statements)
        if statement.effect is Effect.ALLOW
        and any(_covers_action(statement, action) for action in resources.ASSUME_ACTIONS)
    )
    return RoleMfaNote(principal, key, trust_policy, assumes)


def _outside(
    actions: tuple[str, ...], requested: tuple[str, ...], account: Account
) -> Iterator[Outside]:
    """The resource and trust policy statements that allow `actions` on the `requested` resources
    for someone outside the account file. Their conditions aren't read, so a condition that limits
    them to the account still counts: the check can't PASS on a guess."""
    for action in actions:
        for resource in requested:
            try:
                described = account.resource_for(resource, action)
            except PolicyError:
                continue  # the items already say why the engine can't answer
            if described is None or described.policy is None:
                continue
            layer = Layer(resources.policy_kind(described.arn), resource=described.arn)
            for index, statement in enumerate(described.policy.statements):
                if statement.effect is not Effect.ALLOW or not _covers(statement, action, resource):
                    continue
                strangers = tuple(
                    principal for principal in statement.principals or ()
                    if _outside_the_file(principal, account)
                )
                if strangers:
                    yield Outside(described.policy, index, layer, strangers, action, resource)


def _covers_action(statement: Statement, action: str) -> bool:
    # NotAction covers every action it doesn't list.
    return any(match_action(p, action) for p in statement.actions) != statement.not_action


def _covers(statement: Statement, action: str, resource: str) -> bool:
    """Whether `statement` covers `action` on `resource`, leaving its conditions aside. A pattern
    with a policy variable could cover it for someone, so it counts."""
    if not _covers_action(statement, action):
        return False
    if not statement.resources:
        return True  # a trust policy covers the role it belongs to
    if statement.policy_variables and any("${" in pattern for pattern in statement.resources):
        return True
    return any(match_resource(p, resource) for p in statement.resources) != statement.not_resource


def _outside_the_file(principal: Principal, account: Account) -> bool:
    """Whether `principal` can name someone the account file doesn't define: everyone ("*"),
    another account or its principals, a service, an identity provider, a canonical user, or an
    IAM unique ID. The account itself only delegates to its own identity policies."""
    if principal.type is not PrincipalType.AWS or principal.value == "*":
        return True
    value = principal.value
    if _ACCOUNT_ID.fullmatch(value):
        return value != account.account_id
    if value == f"arn:aws:iam::{account.account_id}:root":
        return False
    users = {f"arn:aws:iam::{account.account_id}:user{user.path}{name}"
             for name, user in account.users.items()}
    roles = {f"arn:aws:iam::{account.account_id}:role{role.path}{name}"
             for name, role in account.roles.items()}
    sessions = tuple(f"arn:aws:sts::{account.account_id}:assumed-role/{name}/"
                     for name in account.roles)
    return value not in users | roles and not value.startswith(sessions)
