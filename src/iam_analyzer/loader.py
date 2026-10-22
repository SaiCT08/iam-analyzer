"""Turn policy JSON into normalized `Policy` objects.

AWS allows `Statement`, `Action` and `Resource` to be either a single value or a list.
The loader always produces lists (tuples), so the evaluator only deals with one shape.

The loader also enforces the rules AWS applies when a policy is saved (allowed keys,
Version values, Sid format, action format), so a policy AWS would reject is refused here
instead of being evaluated.
"""

import re
from pathlib import Path
from typing import Any

from iam_analyzer import _validation
from iam_analyzer.errors import PolicyParseError, UnsupportedPolicyFeature
from iam_analyzer.models import Effect, Policy, Statement

# The policy language versions. A policy without a Version uses the older one, which has no
# policy variables: there, "${aws:username}" is plain text.
CURRENT_VERSION = "2012-10-17"
VERSIONS = (CURRENT_VERSION, "2008-10-17")
TOP_LEVEL_KEYS = {"Version", "Statement"}

# Elements the analyzer recognises but can't evaluate yet (later phases).
UNSUPPORTED_ELEMENTS = ("Condition",)
# Elements AWS only allows in resource-based policies (such as S3 bucket policies). Identity
# policies, permissions boundaries and SCPs, the only kinds loaded so far, can't use them.
RESOURCE_POLICY_ELEMENTS = ("Principal", "NotPrincipal")
KNOWN_ELEMENTS = {
    "Sid", "Effect", "Action", "NotAction", "Resource", "NotResource",
    *UNSUPPORTED_ELEMENTS, *RESOURCE_POLICY_ELEMENTS,
}

# IAM allows only ASCII letters and digits in a Sid. "" is treated as no Sid.
_SID = re.compile(r"[A-Za-z0-9]*")
# An action is "*" or starts with a service prefix: "s3:GetObject", "ec2:Describe*".
_ACTION = re.compile(r"\*|[A-Za-z0-9-]+:.+")
# A policy variable such as ${aws:username}, ${*} or ${aws:PrincipalTag/team, 'default'}.
_POLICY_VARIABLE = re.compile(r"\$\{[^}]*\}")


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
    document = _validation.load_json(text, name, error=PolicyParseError)
    return parse_policy(document, name=name)


def parse_policy(document: Any, name: str) -> Policy:
    """Build a Policy from an already-decoded JSON document."""
    if not isinstance(document, dict):
        raise PolicyParseError(f"{name}: policy must be a JSON object")
    if "Id" in document:
        raise _resource_policy_only("Id", name)
    unknown = set(document) - TOP_LEVEL_KEYS
    if unknown:
        raise PolicyParseError(f"{name}: unknown top-level key(s): {', '.join(sorted(unknown))}")
    version = document.get("Version")
    if "Version" in document and version not in VERSIONS:
        raise PolicyParseError(
            f"{name}: 'Version' must be \"2012-10-17\" or \"2008-10-17\", got {version!r}"
        )
    if "Statement" not in document:
        raise PolicyParseError(f"{name}: policy has no 'Statement'")

    raw_statements = _as_list(document["Statement"])
    if not raw_statements:
        raise PolicyParseError(f"{name}: 'Statement' must not be empty")
    statements = tuple(
        _parse_statement(raw, f"{name} statement {index}", version)
        for index, raw in enumerate(raw_statements)
    )
    _check_unique_sids(statements, name)
    return Policy(name=name, statements=statements)


def _parse_statement(raw: Any, where: str, version: str | None) -> Statement:
    if not isinstance(raw, dict):
        raise PolicyParseError(f"{where}: statement must be a JSON object")

    sid = raw.get("Sid")
    if sid is not None and not (isinstance(sid, str) and _SID.fullmatch(sid)):
        raise PolicyParseError(
            f"{where}: 'Sid' must be a string of ASCII letters and digits, got {sid!r}"
        )
    sid = sid or None
    if sid is not None:
        where = f"{where} (Sid={sid})"

    for element in RESOURCE_POLICY_ELEMENTS:
        if element in raw:
            raise _resource_policy_only(element, where)
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
    _check_actions(actions, "NotAction" if not_action else "Action", where)
    resources, not_resource = _patterns(raw, "Resource", "NotResource", where)
    if version == CURRENT_VERSION:
        _refuse_policy_variables(resources, "NotResource" if not_resource else "Resource", where)
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


def _check_actions(actions: tuple[str, ...], key: str, where: str) -> None:
    """Without a service prefix, "s3*" would also match every "s3control:" action."""
    for action in actions:
        if not _ACTION.fullmatch(action):
            raise PolicyParseError(
                f"{where}: '{key}' entry {action!r} needs a service prefix, such as 's3:GetObject'"
            )


def _refuse_policy_variables(resources: tuple[str, ...], key: str, where: str) -> None:
    """With Version 2012-10-17, AWS replaces ${...} in a resource with a value from the
    request, such as the caller's user name. The analyzer can't do that yet, and matching the
    text literally would give wrong answers, so it refuses."""
    for resource in resources:
        variable = _POLICY_VARIABLE.search(resource)
        if variable:
            raise UnsupportedPolicyFeature(
                f"{where}: policy variable {variable.group()!r} in '{key}' is not supported yet"
            )


def _check_unique_sids(statements: tuple[Statement, ...], name: str) -> None:
    """IAM requires each Sid to be unique within a policy."""
    seen = set()
    for statement in statements:
        if statement.sid in seen:
            raise PolicyParseError(f"{name}: Sid {statement.sid!r} is used more than once")
        if statement.sid is not None:
            seen.add(statement.sid)


def _resource_policy_only(element: str, where: str) -> UnsupportedPolicyFeature:
    return UnsupportedPolicyFeature(
        f"{where}: '{element}' is only allowed in resource-based policies, "
        "which the analyzer does not support yet"
    )


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]
