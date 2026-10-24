"""The Principal element of a resource-based policy: whom a statement is about.

    "Principal": {"AWS": ["arn:aws:iam::111122223333:user/kwong", "444455556666"]}

A statement applies when any of its principals names the caller, an IAM user or a role session,
read from the request's aws:PrincipalArn. How it names the caller decides which other layers still
have to allow the request (`models.PrincipalMatch`, and `evaluator`):
  - "*" names everyone.
  - The caller's own user ARN names the user.
  - The ARN of the role whose session the caller is names the role.
  - The caller's account, as an ID or arn:aws:iam::ID:root, names the account. AWS: "This
    delegates authority to the account", so the account's identity-based policies decide.
Service and federated principals, and federated-user sessions, never name an IAM user or a role
session.

The analyzer refuses (UnsupportedPolicyFeature) what the account file can't settle:
  - a role session's ARN for the caller's role, because the session's name isn't known;
  - S3 canonical user IDs, and IAM unique IDs, which AWS shows for a principal that was deleted;
  - a role ARN that matches the caller's only when case is ignored. AWS says the user name in a
    principal's ARN is case sensitive, but says nothing about role names.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from iam_analyzer.context import RequestContext
from iam_analyzer.errors import PolicyParseError, RequestError, UnsupportedPolicyFeature
from iam_analyzer.models import Principal, PrincipalMatch, PrincipalType

CALLER_KEY = "aws:PrincipalArn"

_TYPES = {kind.value: kind for kind in PrincipalType}
_ACCOUNT_ID = re.compile(r"[0-9]{12}")
# IAM unique IDs start with a four-letter prefix, such as AIDA for users and AROA for roles.
_UNIQUE_ID = re.compile(r"A[A-Z]{3}[A-Z0-9]{12,}")
_PRINCIPAL_ARN = re.compile(
    r"arn:[a-z-]+:(iam::[0-9]{12}:(root|user/.+|role/.+)"
    r"|sts::[0-9]{12}:(assumed-role/[^/]+/.+|federated-user/.+))"
)
# The caller's aws:PrincipalArn: an IAM user's ARN, or for a role session, the role's ARN.
_CALLER_ARN = re.compile(r"arn:([a-z-]+):iam::([0-9]{12}):(user|role)/(?:.*/)?([^/]+)")
_RANK = {PrincipalMatch.ACCOUNT: 0, PrincipalMatch.ROLE: 1}  # the direct matches rank highest


@dataclass(frozen=True)
class Caller:
    """Who makes the request: an IAM user, or a session of an IAM role."""

    arn: str  # aws:PrincipalArn: the user's ARN, or the role's
    partition: str
    account: str
    kind: str  # "user" or "role"
    name: str  # the user's or role's name, without its path


def parse(raw: Any, where: str) -> tuple[Principal, ...]:
    """Read a Principal element: "*", or {"AWS": ..., "Service": ..., ...}."""
    if raw == "*":
        return (Principal(PrincipalType.AWS, "*"),)
    if not isinstance(raw, dict) or not raw:
        raise PolicyParseError(
            f"{where}: 'Principal' must be \"*\" or a non-empty JSON object, such as "
            '{"AWS": "111122223333"}'
        )
    found = []
    for key, value in raw.items():
        if key not in _TYPES:
            raise PolicyParseError(
                f"{where}: unknown principal type {key!r}; AWS uses AWS, Service, Federated and "
                "CanonicalUser"
            )
        values = value if isinstance(value, list) else [value]
        if not values or not all(isinstance(text, str) and text for text in values):
            raise PolicyParseError(
                f"{where}: principal type {key!r} needs a string or a non-empty list of strings"
            )
        found += [_check(Principal(_TYPES[key], text), where) for text in values]
    return tuple(found)


def needs_caller(principals: tuple[Principal, ...]) -> bool:
    """Whether matching `principals` needs to know the caller: anything but "*" does."""
    return any(p.type is PrincipalType.AWS and p.value != "*" for p in principals)


def caller(context: RequestContext) -> Caller:
    """The caller, read from aws:PrincipalArn. The context must know the key."""
    found = context.get(CALLER_KEY)
    if found is None or len(found) != 1:
        raise RequestError(
            f"condition key {CALLER_KEY!r} needs exactly one value, the caller's ARN: the "
            "analyzer doesn't evaluate anonymous requests"
        )
    match = _CALLER_ARN.fullmatch(found[0])
    if match is None:
        raise UnsupportedPolicyFeature(
            f"{CALLER_KEY} {found[0]!r}: resource-based policies are only evaluated for requests "
            "by IAM users and role sessions, whose aws:PrincipalArn is a user or role ARN"
        )
    partition, account, kind, name = match.groups()
    return Caller(found[0], partition, account, kind, name)


def match(
    principals: tuple[Principal, ...], context: RequestContext, *, deny: bool
) -> PrincipalMatch | None:
    """How `principals` name the caller, or None when none does.

    For an Allow, the strongest match counts (a direct one, then the role, then the account), so
    a principal the analyzer can't check is refused unless another one already names the caller
    directly. For a Deny, any match is enough. The context must know the caller if
    `needs_caller(principals)`.
    """
    who = caller(context) if needs_caller(principals) else None
    found = []
    refused = None
    for principal in principals:
        try:
            found.append(_match(principal, who))
        except UnsupportedPolicyFeature as exc:
            refused = refused or exc
    best = strongest(found)
    settled = best is not None and (deny or best.direct)
    if refused is not None and not settled:
        raise refused
    return best


def strongest(matches: Iterable[PrincipalMatch | None]) -> PrincipalMatch | None:
    """The strongest of `matches`: a direct grant, then one to the caller's role, then one to
    the caller's account. None when there are none."""
    present = [found for found in matches if found is not None]
    return max(present, key=_rank, default=None)


def _match(principal: Principal, who: Caller | None) -> PrincipalMatch | None:
    value = principal.value
    if principal.type is PrincipalType.CANONICAL_USER:
        raise UnsupportedPolicyFeature(
            f"principal {{\"CanonicalUser\": {value!r}}}: the account file doesn't record S3 "
            "canonical user IDs"
        )
    if principal.type is not PrincipalType.AWS:
        return None  # a service or a federated identity provider, never an IAM user or role
    if value == "*":
        return PrincipalMatch.EVERYONE
    assert who is not None
    if _ACCOUNT_ID.fullmatch(value):
        return PrincipalMatch.ACCOUNT if value == who.account else None
    if _UNIQUE_ID.fullmatch(value):
        raise UnsupportedPolicyFeature(
            f"principal {value!r} is an IAM unique ID, which AWS shows when the principal a "
            "policy named was deleted; the account file doesn't record unique IDs"
        )
    if not _PRINCIPAL_ARN.fullmatch(value):
        raise PolicyParseError(f"{value!r} isn't an AWS principal")
    _, partition, _, _, account, resource = value.split(":", 5)
    if resource == "root":
        same_account = (partition, account) == (who.partition, who.account)
        return PrincipalMatch.ACCOUNT if same_account else None
    if resource.startswith("user/"):
        return PrincipalMatch.USER if who.kind == "user" and value == who.arn else None
    if resource.startswith("role/") and who.kind == "role":
        if value == who.arn:
            return PrincipalMatch.ROLE
        if value.casefold() == who.arn.casefold():
            raise UnsupportedPolicyFeature(
                f"principal {value!r} matches the caller's role {who.arn!r} only if case is "
                "ignored, and AWS doesn't say whether role names in a principal are case sensitive"
            )
    if resource.startswith("assumed-role/") and who.kind == "role" and account == who.account:
        role = resource.split("/")[1]
        if role.casefold() == who.name.casefold():
            raise UnsupportedPolicyFeature(
                f"principal {value!r} names a session of the caller's role, and the analyzer "
                "doesn't know the session's name"
            )
    return None


def _check(principal: Principal, where: str) -> Principal:
    """Check one principal the way AWS does when a policy is saved."""
    value = principal.value
    if principal.type is PrincipalType.AWS and value == "*":
        return principal
    if value == "*":
        raise PolicyParseError(
            f"{where}: {principal.type.value!r} can't be \"*\"; only \"AWS\": \"*\" names everyone"
        )
    if "*" in value or "?" in value:
        raise PolicyParseError(
            f"{where}: principal {value!r}: AWS doesn't allow a wildcard in part of a principal's "
            "name or ARN"
        )
    forms = (_ACCOUNT_ID, _PRINCIPAL_ARN, _UNIQUE_ID)
    if principal.type is PrincipalType.AWS and not any(form.fullmatch(value) for form in forms):
        raise PolicyParseError(
            f"{where}: {value!r} isn't an AWS principal; use an account ID, or the ARN of an "
            "account (root), user, role, role session or federated user"
        )
    return principal


def _rank(found: PrincipalMatch) -> int:
    return 2 if found.direct else _RANK[found]
