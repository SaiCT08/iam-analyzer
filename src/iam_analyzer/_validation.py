"""Shape checks shared by the account and organization file loaders.

Both files are JSON objects keyed by name, whose entries refer to each other by name. Each
check raises the `error` class it is given, so each loader reports its own error type.
"""

import re
from typing import Any

from iam_analyzer.errors import PolicyError

_ACCOUNT_ID = re.compile(r"[0-9]{12}")


def section(document: dict, key: str, where: str, *, error: type[PolicyError]) -> dict:
    """The JSON object under `key`, or an empty one if the key is missing."""
    value = document.get(key, {})
    if not isinstance(value, dict):
        raise error(f"{where}: '{key}' must be a JSON object keyed by name")
    return value


def entry(raw: Any, allowed: set[str], where: str, *, error: type[PolicyError]) -> dict:
    """Check that `raw` is a JSON object that only uses the `allowed` keys."""
    if not isinstance(raw, dict):
        raise error(f"{where}: must be a JSON object")
    unknown = set(raw) - allowed
    if unknown:
        raise error(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    return raw


def refs(
    fields: dict, key: str, defined: dict, kind: str, where: str, *, error: type[PolicyError]
) -> tuple[str, ...]:
    """Read a list of names under `key` and check each one is defined."""
    values = fields.get(key, [])
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise error(f"{where}: '{key}' must be a list of names")
    for value in values:
        if value not in defined:
            raise error(f"{where}: unknown {kind} {value!r}")
    return tuple(values)


def ref(
    fields: dict, key: str, defined: dict, kind: str, where: str, *, error: type[PolicyError]
) -> str | None:
    """Read an optional single name under `key` and check it is defined."""
    if key not in fields:
        return None
    value = fields[key]
    if not isinstance(value, str):
        raise error(f"{where}: '{key}' must be a {kind} name")
    if value not in defined:
        raise error(f"{where}: unknown {kind} {value!r}")
    return value


def account_id(value: Any, where: str, *, error: type[PolicyError]) -> str:
    """Check that `value` is an AWS account ID: 12 digits, written as a string.

    A JSON number would lose the leading zeros some account IDs have, so it is rejected.
    """
    if not isinstance(value, str) or not _ACCOUNT_ID.fullmatch(value):
        raise error(f"{where}: {value!r} is not an AWS account ID (12 digits, in a string)")
    return value
