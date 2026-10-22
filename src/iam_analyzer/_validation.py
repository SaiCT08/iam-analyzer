"""Checks shared by the file loaders (policy, account and organization files).

Account and organization files are JSON objects keyed by name, whose entries refer to each
other by name. Each check raises the `error` class it is given, so each loader reports its
own error type.
"""

import json
import re
from typing import Any

from iam_analyzer.errors import PolicyError

_ACCOUNT_ID = re.compile(r"[0-9]{12}")


def load_json(text: str, where: str, *, error: type[PolicyError]) -> Any:
    """Decode JSON text, refusing any object that repeats a key.

    Python's json module silently keeps the last copy of a repeated key, which could drop a
    Deny (a second "Effect") or an SCP (an account listed twice). AWS rejects such
    documents, so the analyzer does too.
    """

    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise error(f"{where}: duplicate key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=unique_keys)
    except json.JSONDecodeError as exc:
        raise error(f"{where}: invalid JSON: {exc}") from exc


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
