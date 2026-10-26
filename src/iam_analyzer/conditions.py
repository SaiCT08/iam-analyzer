"""The Condition element: its operators, and how a condition is checked against a request.

    "Condition": {"StringEquals": {"aws:PrincipalTag/campus": ["campus-01", "campus-02"]}}

A statement applies only when every one of its conditions holds. Within one condition:
  - Several values in the policy: any one can match (OR). A negated operator, such as
    StringNotEquals, holds only when none match (NOR).
  - A key the request doesn't include: a negated operator holds and any other doesn't, unless
    the operator ends in IfExists (then it holds) or is Null (which tests exactly that).
  - Several values in the request, as aws:TagKeys can have: ForAllValues needs every one to
    pass, and also holds when the key is missing. ForAnyValue needs at least one, and fails when
    the key is missing, even with IfExists or on Null. With neither set operator, StringEquals
    and StringNotEquals never hold, and other operators are refused.
  - Policy variables can be used in the values of String and ARN operators. A value whose
    variable has no value matches nothing (see `variables`), so a negated operator holds. In a
    Bool value, a variable isn't filled in, and the value matches nothing.

Where AWS's documentation leaves a case open, the analyzer refuses (UnsupportedPolicyFeature)
instead of guessing, unless AWS's IAM policy simulator answered it (tests/simulator_fixtures).
"""

import base64
import ipaddress
import operator
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from iam_analyzer import variables
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import PolicyParseError, RequestError, UnsupportedPolicyFeature
from iam_analyzer.matching import Pattern, wildcard_match
from iam_analyzer.models import Condition, SetOperator, Statement
from iam_analyzer.variables import Template


class _Undefined(ValueError):
    """A value AWS accepts, but whose meaning its documentation leaves open."""


# --- Reading values --------------------------------------------------------------------

_NUMBER = re.compile(r"[+-]?\d+(\.\d+)?")
_DATE_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})")
# With no time zone, the forms the IAM policy simulator read as UTC: a month, a day, or a day and
# a time to the minute or the second.
_UTC_DATE = re.compile(r"(\d{4})-(\d{2})(?:-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2}))?)?)?")
# W3C's one other ISO 8601 form with no time zone: a time with fractions of a second.
_ZONELESS_FRACTION = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+")


def _number(text: str) -> Decimal:
    if not _NUMBER.fullmatch(text):
        raise ValueError("expected an integer or decimal number, such as 10 or 2.5")
    return Decimal(text)


def _date(text: str) -> datetime:
    """An ISO 8601 date and time, or epoch seconds.

    AWS's IAM policy simulator read the W3C forms with no time zone as UTC: 2026-08 is midnight
    UTC on August 1, 2026-08-15 is midnight UTC that day, and 2026-08-15T07:30 is 07:30:00 UTC. A
    number is epoch seconds, four digits included: 2026 is 1970-01-01T00:33:46Z, not the year
    (dates_without_a_time_zone/*). A time with fractions of a second and no time zone wasn't
    probed, so it is refused.
    """
    if _ZONELESS_FRACTION.fullmatch(text):
        raise _Undefined(
            "AWS doesn't say which moment a time with fractions of a second and no time zone "
            "stands for; give one such as 2026-08-15T07:30:00.5Z"
        )
    try:
        if text.isdigit():
            return datetime.fromtimestamp(int(text), tz=timezone.utc)
        if _DATE_TIME.fullmatch(text):
            return datetime.fromisoformat(text)
        utc = _UTC_DATE.fullmatch(text)
        if utc:
            year, month, day, hour, minute, second = (int(part or 0) for part in utc.groups())
            return datetime(year, month, day or 1, hour, minute, second, tzinfo=timezone.utc)
    except (OverflowError, OSError, ValueError):
        pass
    raise ValueError(
        "expected a date and time such as 2026-08-15T07:30:00Z, a date such as 2026-08-15, or "
        "epoch seconds"
    )


def _bool(text: str) -> bool:
    if text not in ("true", "false"):
        raise ValueError("expected true or false")
    return text == "true"


def _binary(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except ValueError:
        raise ValueError("expected base64 text") from None


def _network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """A policy's IP range in CIDR form.

    A bare address stands for just that address. AWS documents a default prefix of /32, which only
    fits IPv4, and the IAM policy simulator treated a bare IPv6 address as /128
    (ip_ranges/bare_ipv6_address*). Host bits are masked, as the simulator did
    (ip_ranges/range_with_host_bits): 203.0.113.5/24 is 203.0.113.0/24.
    """
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError("expected an IP range such as 203.0.113.0/24") from None


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise ValueError("expected an IP address such as 203.0.113.5") from None


def _arn_fields(template: Template) -> list[Template]:
    """Split an ARN pattern into its six fields, at the first five colons of its plain text.

    The split happens before policy variables are filled in, so a value can't move a field.
    """
    fields: list[list] = [[]]
    for part in template:
        if isinstance(part, str) and len(fields) < 6:
            first, *rest = part.split(":", 6 - len(fields))
            fields[-1].append(first)
            fields += [[chunk] for chunk in rest]
        else:
            fields[-1].append(part)
    return [tuple(field) for field in fields]


def _arn(text: str) -> list[str]:
    fields = text.split(":", 5)
    if len(fields) != 6:
        raise ValueError(
            "expected an ARN with six fields, such as arn:aws:iam::111122223333:role/ITAdmin"
        )
    return fields


def _template(value: str, policy_variables: bool) -> Template:
    return variables.parse(value) if policy_variables else (value,)


def _check_arn(value: str, policy_variables: bool) -> None:
    if len(_arn_fields(_template(value, policy_variables))) != 6:
        raise _Undefined(
            "ARN operators check each of an ARN's six fields, and AWS doesn't say how a value "
            "with fewer fields is matched"
        )


# --- Operator families -----------------------------------------------------------------


@dataclass(frozen=True)
class _Family:
    """How a family of operators (String, Numeric, ...) reads its values."""

    name: str
    # Checks a policy value when the policy is loaded. Raises ValueError or _Undefined.
    check: Callable[[str, bool], object]
    # Turns a policy value into what the operator compares, or None when it matches nothing.
    # String and ARN values can hold policy variables, so they are only ready once the request
    # context is known.
    policy_value: Callable[[str, RequestContext, bool], Any]
    # Turns a request value into what the operator compares. Raises ValueError.
    request_value: Callable[[str], Any]

    @property
    def takes_variables(self) -> bool:
        return self.name in ("String", "ARN")


def _plain(name: str, read: Callable[[str], Any]) -> _Family:
    """A family whose values can't hold policy variables, so each is always read the same way."""
    return _Family(
        name,
        check=lambda value, policy_variables: read(value),
        policy_value=lambda value, context, policy_variables: read(value),
        request_value=read,
    )


def _string_pattern(value: str, context: RequestContext, policy_variables: bool) -> Pattern | None:
    if not policy_variables:
        return value
    return variables.resolve(variables.parse(value), context)


def _arn_pattern(
    value: str, context: RequestContext, policy_variables: bool
) -> list[Pattern] | None:
    fields = _arn_fields(_template(value, policy_variables))
    patterns = [variables.resolve(field, context) for field in fields]
    return None if any(pattern is None for pattern in patterns) else patterns


def _bool_value(value: str, context: RequestContext, policy_variables: bool) -> bool | None:
    """A Bool policy value. AWS doesn't fill in a policy variable there: the text stays as
    written, so it is neither true nor false and matches nothing (bool_with_a_variable/*)."""
    if policy_variables and "${" in value:
        return None
    return _bool(value)


STRING = _Family("String", check=_template, policy_value=_string_pattern, request_value=str)
ARN = _Family("ARN", check=_check_arn, policy_value=_arn_pattern, request_value=_arn)
NUMERIC = _plain("Numeric", _number)
DATE = _plain("Date", _date)
BOOL = _Family(
    "Bool",
    check=lambda value, policy_variables: _bool(value),
    policy_value=_bool_value,
    request_value=_bool,
)
BINARY = _plain("Binary", _binary)
NULL = _plain("Null", _bool)
IP_ADDRESS = _Family(
    "IP address",
    check=lambda value, policy_variables: _network(value),
    policy_value=lambda value, context, policy_variables: _network(value),
    request_value=_address,
)


def _text(pattern: Pattern) -> str:
    return pattern if isinstance(pattern, str) else "".join(text for text, _ in pattern)


def _equals(request: str, pattern: Pattern) -> bool:
    return request == _text(pattern)


def _equals_ignoring_case(request: str, pattern: Pattern) -> bool:
    return request.casefold() == _text(pattern).casefold()


def _like(request: str, pattern: Pattern) -> bool:
    return wildcard_match(pattern, request)


def _in_network(address: Any, network: Any) -> bool:
    return address in network  # False when one is IPv4 and the other IPv6


def _arn_like(request: list[str], fields: list[Pattern]) -> bool:
    # AWS: "Each of the six colon-delimited components of the ARN is checked separately", and the
    # IAM policy simulator agrees (wildcards_and_colons/arn_like_star_ending_the_region_field):
    # unlike in Resource, a * that ends the region field doesn't run on into the account field.
    # Within a field, * and ? match any characters. Only the resource part holds colons, and there
    # they match them, as in Resource (wildcards_and_colons/arn_like_*).
    return all(wildcard_match(p, r) for p, r in zip(fields, request, strict=True))


@dataclass(frozen=True)
class Operator:
    family: _Family
    # Whether a request value matches one policy value, before negation.
    compare: Callable[[Any, Any], bool]
    negated: bool = False


_ORDERINGS = {
    "Equals": (operator.eq, False),
    "NotEquals": (operator.eq, True),
    "LessThan": (operator.lt, False),
    "LessThanEquals": (operator.le, False),
    "GreaterThan": (operator.gt, False),
    "GreaterThanEquals": (operator.ge, False),
}

OPERATORS: dict[str, Operator] = {
    "StringEquals": Operator(STRING, _equals),
    "StringNotEquals": Operator(STRING, _equals, negated=True),
    "StringEqualsIgnoreCase": Operator(STRING, _equals_ignoring_case),
    "StringNotEqualsIgnoreCase": Operator(STRING, _equals_ignoring_case, negated=True),
    "StringLike": Operator(STRING, _like),
    "StringNotLike": Operator(STRING, _like, negated=True),
    **{f"Numeric{n}": Operator(NUMERIC, c, negated) for n, (c, negated) in _ORDERINGS.items()},
    **{f"Date{n}": Operator(DATE, c, negated) for n, (c, negated) in _ORDERINGS.items()},
    "Bool": Operator(BOOL, operator.eq),
    "BinaryEquals": Operator(BINARY, operator.eq),
    "IpAddress": Operator(IP_ADDRESS, _in_network),
    "NotIpAddress": Operator(IP_ADDRESS, _in_network, negated=True),
    # AWS: "The ArnEquals and ArnLike condition operators behave identically."
    "ArnEquals": Operator(ARN, _arn_like),
    "ArnLike": Operator(ARN, _arn_like),
    "ArnNotEquals": Operator(ARN, _arn_like, negated=True),
    "ArnNotLike": Operator(ARN, _arn_like, negated=True),
    "Null": Operator(NULL, operator.eq),
}


# --- Loading ---------------------------------------------------------------------------


def parse_operator(name: str) -> tuple[SetOperator | None, str, bool]:
    """Split "ForAnyValue:StringLikeIfExists" into (FOR_ANY_VALUE, "StringLike", True).

    Operator names must be spelled exactly as AWS documents them.
    """
    set_operator = None
    base = name
    prefix, colon, rest = name.partition(":")
    if colon:
        if prefix not in {s.value for s in SetOperator}:
            raise PolicyParseError(f"unknown condition operator {name!r}")
        set_operator, base = SetOperator(prefix), rest
    if_exists = base.endswith("IfExists")
    if if_exists:
        base = base.removesuffix("IfExists")
    if base not in OPERATORS:
        raise PolicyParseError(f"unknown condition operator {name!r}")
    if base == "Null" and if_exists:
        raise PolicyParseError(f"{name!r}: AWS doesn't allow IfExists on Null")
    return set_operator, base, if_exists


def check(condition: Condition, policy_variables: bool) -> None:
    """Check a condition's values when its policy is loaded.

    Raises PolicyParseError for a value AWS would reject, and UnsupportedPolicyFeature for one
    whose meaning AWS's documentation leaves open.
    """
    family = OPERATORS[condition.operator].family
    where = f"condition {condition.name!r} on {condition.key!r}"
    for value in condition.values:
        if policy_variables and "${" in value and not family.takes_variables:
            if family is BOOL:
                # AWS accepts this, but doesn't fill the variable in: the IAM policy simulator
                # treated the text as written (bool_with_a_variable/*). It matches nothing.
                continue
            raise PolicyParseError(
                f"{where}: AWS doesn't allow policy variables with {family.name} operators"
            )
        try:
            family.check(value, policy_variables)
        except _Undefined as exc:
            raise UnsupportedPolicyFeature(f"{where}: {exc}, got {value!r}") from None
        except ValueError as exc:
            raise PolicyParseError(f"{where}: {exc}, got {value!r}") from None
        except (PolicyParseError, UnsupportedPolicyFeature) as exc:
            raise type(exc)(f"{where}: {exc}") from None


def keys(statement: Statement) -> list[str]:
    """Every condition key the statement's conditions read, including their policy variables'."""
    found = []
    for condition in statement.conditions:
        found.append(condition.key)
        if statement.policy_variables and OPERATORS[condition.operator].family.takes_variables:
            for value in condition.values:
                found += variables.keys(variables.parse(value))
    return found


# --- Evaluating ------------------------------------------------------------------------


def holds(condition: Condition, context: RequestContext, policy_variables: bool) -> bool:
    """Whether the request passes `condition`. The context must know the condition's key.

    Raises UnsupportedPolicyFeature for a case AWS's documentation leaves open, and
    RequestError for a request value that doesn't fit the operator.
    """
    op = OPERATORS[condition.operator]
    found = context.get(condition.key)
    where = f"condition {condition.name!r} on {condition.key!r}"
    if found is None and condition.set_operator is not None:
        # Whatever the operator, ForAllValues holds on a missing key and ForAnyValue doesn't. The
        # IAM policy simulator showed it for Null (set_operator_on_null/*), and that ForAnyValue
        # wins over IfExists (for_any_value_if_exists/key_absent).
        return condition.set_operator is SetOperator.FOR_ALL_VALUES
    if op.family is NULL:
        return _null(condition, found, where)
    if found is None:
        return condition.if_exists or op.negated
    if found == ("",) and condition.set_operator is SetOperator.FOR_ALL_VALUES:
        # AWS: ForAllValues is true when the value "resolves to a null dataset, such as an
        # empty string". Under ForAnyValue, "" is an ordinary value (empty_values/for_any_value).
        return True
    if condition.set_operator is None and len(found) > 1:
        if condition.operator in ("StringEquals", "StringNotEquals"):
            # The IAM policy simulator: with several values and no set operator, neither one ever
            # holds (several_values_without_a_set_operator/*). IfExists changes nothing, since the
            # key is in the request.
            return False
        raise UnsupportedPolicyFeature(
            f"{where}: the request gives {condition.key!r} several values, and AWS requires "
            "ForAllValues or ForAnyValue for that"
        )

    filled = [op.family.policy_value(v, context, policy_variables) for v in condition.values]
    # A value that matches nothing drops out. If none is left, a negated operator holds.
    policy = [value for value in filled if value is not None]

    def passes(text: str) -> bool:
        try:
            request = op.family.request_value(text)
        except ValueError as exc:
            raise RequestError(f"condition key {condition.key!r}: {exc}, got {text!r}") from None
        return any(op.compare(request, value) for value in policy) != op.negated

    if condition.set_operator is SetOperator.FOR_ALL_VALUES:
        return all(passes(text) for text in found)
    return any(passes(text) for text in found)  # ForAnyValue, or the one value


def _null(condition: Condition, found: tuple[str, ...] | None, where: str) -> bool:
    """Null: true holds when the request doesn't include the key, and false when it does.

    An empty value counts as present (empty_values/null_true). With a set operator, a missing key
    is decided before this, and when the key is present, Null's own answer stands
    (set_operator_on_null/for_all_values_null_false).
    """
    present = found is not None
    result = any(present != _bool(value) for value in condition.values)
    if not result and found == ("",) and condition.set_operator is SetOperator.FOR_ALL_VALUES:
        raise UnsupportedPolicyFeature(
            f"{where}: the request's only value is empty. ForAllValues holds for that null "
            "dataset, but Null counts the key as present, and AWS doesn't say which wins"
        )
    return result
