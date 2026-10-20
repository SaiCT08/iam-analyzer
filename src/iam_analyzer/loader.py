"""Turn policy JSON into normalized `Policy` objects.

AWS allows `Statement`, `Action` and `Resource` to be either a single value or a list.
The loader always produces lists (tuples), so the evaluator only deals with one shape.
"""

import json
from pathlib import Path
from typing import Any

from iam_analyzer.errors import PolicyParseError, UnsupportedPolicyFeature
from iam_analyzer.models import Effect, Policy, Statement

# Elements the analyzer recognises but can't evaluate yet (later phases).
UNSUPPORTED_ELEMENTS = ("Condition", "Principal", "NotPrincipal")
KNOWN_ELEMENTS = {
    "Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", *UNSUPPORTED_ELEMENTS
}


def load_policy_file(path: str | Path) -> Policy:
    """Load a policy from a JSON file. The policy is named after the file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyParseError(f"{path}: cannot read file: {exc.strerror}") from exc
    return load_policy(text, name=path.name)


def load_policy(text: str, name: str) -> Policy:
    """Load a policy from a JSON string."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyParseError(f"{name}: invalid JSON: {exc}") from exc
    return parse_policy(document, name=name)


def parse_policy(document: Any, name: str) -> Policy:
    """Build a Policy from an already-decoded JSON document."""
    if not isinstance(document, dict):
        raise PolicyParseError(f"{name}: policy must be a JSON object")
    if "Statement" not in document:
        raise PolicyParseError(f"{name}: policy has no 'Statement'")

    raw_statements = _as_list(document["Statement"])
    statements = tuple(
        _parse_statement(raw, f"{name} statement {index}")
        for index, raw in enumerate(raw_statements)
    )
    return Policy(name=name, statements=statements)


def _parse_statement(raw: Any, where: str) -> Statement:
    if not isinstance(raw, dict):
        raise PolicyParseError(f"{where}: statement must be a JSON object")

    sid = raw.get("Sid")
    if sid is not None:
        where = f"{where} (Sid={sid})"

    for element in UNSUPPORTED_ELEMENTS:
        if element in raw:
            raise UnsupportedPolicyFeature(f"{where}: '{element}' is not supported yet")
    unknown = set(raw) - KNOWN_ELEMENTS
    if unknown:
        raise PolicyParseError(f"{where}: unknown element(s): {', '.join(sorted(unknown))}")

    try:
        effect = Effect(raw.get("Effect"))
    except ValueError:
        raise PolicyParseError(
            f"{where}: 'Effect' must be \"Allow\" or \"Deny\", got {raw.get('Effect')!r}"
        ) from None

    actions, not_action = _patterns(raw, "Action", "NotAction", where)
    resources, not_resource = _patterns(raw, "Resource", "NotResource", where)
    return Statement(
        effect=effect,
        actions=actions,
        resources=resources,
        sid=sid,
        not_action=not_action,
        not_resource=not_resource,
    )


def _patterns(raw: dict, key: str, not_key: str, where: str) -> tuple[tuple[str, ...], bool]:
    """Read exactly one of `key` / `not_key`. Returns (patterns, negated)."""
    if key in raw and not_key in raw:
        raise PolicyParseError(f"{where}: cannot have both '{key}' and '{not_key}'")
    if not_key in raw:
        return _string_list(raw, not_key, where), True
    if key not in raw:
        raise PolicyParseError(f"{where}: missing '{key}' or '{not_key}'")
    return _string_list(raw, key, where), False


def _string_list(raw: dict, key: str, where: str) -> tuple[str, ...]:
    if key not in raw:
        raise PolicyParseError(f"{where}: missing '{key}'")
    values = _as_list(raw[key])
    if not values or not all(isinstance(v, str) and v for v in values):
        raise PolicyParseError(f"{where}: '{key}' must be a non-empty string or list of strings")
    return tuple(values)


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]
