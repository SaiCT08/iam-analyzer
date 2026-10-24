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

from iam_analyzer import _validation, conditions, principals, variables
from iam_analyzer.context import CONDITION_KEY
from iam_analyzer.errors import PolicyError, PolicyParseError, UnsupportedPolicyFeature
from iam_analyzer.models import Condition, Effect, Policy, PolicyType, Principal, Statement

# The policy language versions. A policy without a Version uses the older one, which has no
# policy variables: there, "${aws:username}" is plain text.
CURRENT_VERSION = "2012-10-17"
VERSIONS = (CURRENT_VERSION, "2008-10-17")
TOP_LEVEL_KEYS = {"Version", "Statement"}

# Elements AWS only allows in resource-based policies (such as S3 bucket policies). Identity
# policies, permissions boundaries and SCPs can't use them. In a resource-based policy, every
# statement needs a Principal.
RESOURCE_POLICY_ELEMENTS = ("Principal", "NotPrincipal")
KNOWN_ELEMENTS = {
    "Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition",
    *RESOURCE_POLICY_ELEMENTS,
}

# IAM allows only ASCII letters and digits in a Sid. "" is treated as no Sid.
_SID = re.compile(r"[A-Za-z0-9]*")
# An action is "*" or starts with a service prefix: "s3:GetObject", "ec2:Describe*".
_ACTION = re.compile(r"\*|[A-Za-z0-9-]+:.+")


def load_policy_file(path: str | Path, *, kind: PolicyType = PolicyType.IDENTITY) -> Policy:
    """Load a policy from a JSON file. The policy is named after the file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyParseError(f"{path}: cannot read file: {exc.strerror}") from exc
    return load_policy(text, name=path.name, kind=kind)


def load_policy(text: str, name: str, *, kind: PolicyType = PolicyType.IDENTITY) -> Policy:
    """Load a policy from a JSON string."""
    document = _validation.load_json(text, name, error=PolicyParseError)
    return parse_policy(document, name=name, kind=kind)


def parse_policy(document: Any, name: str, *, kind: PolicyType = PolicyType.IDENTITY) -> Policy:
    """Build a Policy from an already-decoded JSON document.

    `kind` is PolicyType.RESOURCE_BASED for a resource-based policy, such as an S3 bucket policy,
    which may have an Id and whose statements need a Principal. Identity policies, permissions
    boundaries and SCPs (every other kind) can have neither.
    """
    resource_based = kind is PolicyType.RESOURCE_BASED
    if not isinstance(document, dict):
        raise PolicyParseError(f"{name}: policy must be a JSON object")
    if "Id" in document:
        if not resource_based:
            raise _resource_policy_only("Id", name)
        if not isinstance(document["Id"], str):
            raise PolicyParseError(f"{name}: 'Id' must be a string, got {document['Id']!r}")
    unknown = set(document) - TOP_LEVEL_KEYS - {"Id"}
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
        _parse_statement(raw, f"{name} statement {index}", version, resource_based)
        for index, raw in enumerate(raw_statements)
    )
    _check_unique_sids(statements, name)
    return Policy(name=name, statements=statements)


def _parse_statement(raw: Any, where: str, version: str | None, resource_based: bool) -> Statement:
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

    if not resource_based:
        for element in RESOURCE_POLICY_ELEMENTS:
            if element in raw:
                raise _resource_policy_only(element, where)
    unknown = set(raw) - KNOWN_ELEMENTS
    if unknown:
        raise PolicyParseError(f"{where}: unknown element(s): {', '.join(sorted(unknown))}")

    try:
        effect = Effect(raw.get("Effect"))
    except ValueError:
        raise PolicyParseError(
            f"{where}: 'Effect' must be \"Allow\" or \"Deny\", got {raw.get('Effect')!r}"
        ) from None
    statement_principals = _principals(raw, effect, where) if resource_based else None

    actions, not_action = _patterns(raw, "Action", "NotAction", where)
    action_key = "NotAction" if not_action else "Action"
    _check_actions(actions, action_key, where)
    resources, not_resource = _patterns(raw, "Resource", "NotResource", where)
    policy_variables = version == CURRENT_VERSION
    if policy_variables:
        _check_no_variables(actions, action_key, where)
        _check_variables(resources, "NotResource" if not_resource else "Resource", where)
    parsed_conditions = ()
    if "Condition" in raw:
        parsed_conditions = _parse_conditions(raw["Condition"], where, policy_variables)
    return Statement(
        effect=effect,
        actions=actions,
        resources=resources,
        sid=sid,
        not_action=not_action,
        not_resource=not_resource,
        policy_variables=policy_variables,
        conditions=parsed_conditions,
        principals=statement_principals,
    )


def _principals(raw: dict, effect: Effect, where: str) -> tuple[Principal, ...]:
    """Read the Principal that a resource-based policy's statement needs. NotPrincipal is
    refused."""
    if "Principal" in raw and "NotPrincipal" in raw:
        raise PolicyParseError(f"{where}: cannot have both 'Principal' and 'NotPrincipal'")
    if "NotPrincipal" in raw:
        if effect is Effect.ALLOW:
            raise PolicyParseError(
                f"{where}: AWS only allows 'NotPrincipal' with \"Effect\": \"Deny\""
            )
        raise UnsupportedPolicyFeature(
            f"{where}: 'NotPrincipal' isn't supported yet: AWS says which principals it checks "
            "depends on the service, and recommends aws:PrincipalArn conditions instead"
        )
    if "Principal" not in raw:
        raise PolicyParseError(f"{where}: a resource-based policy's statement needs a 'Principal'")
    return principals.parse(raw["Principal"], where)


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


def _check_variables(resources: tuple[str, ...], key: str, where: str) -> None:
    """Check the policy variables in a Resource or NotResource list (Version 2012-10-17).

    AWS only allows them in the resource part of an ARN, after the fifth colon, so a variable
    can't stand for the service or the account.
    """
    for resource in resources:
        if "${" not in resource:
            continue
        try:
            variables.parse(resource)
        except PolicyError as exc:
            raise type(exc)(f"{where}: '{key}': {exc}") from None
        before = resource[: resource.index("${")]
        if not (before.startswith("arn:") and before.count(":") >= 5):
            raise PolicyParseError(
                f"{where}: '{key}' entry {resource!r}: policy variables can only be used in the "
                "resource part of an ARN, after the fifth colon"
            )


def _check_no_variables(actions: tuple[str, ...], key: str, where: str) -> None:
    """AWS only fills in policy variables in resources and condition values, never in actions."""
    for action in actions:
        if "${" in action:
            raise PolicyParseError(
                f"{where}: '{key}' entry {action!r}: policy variables can't be used in actions"
            )


def _parse_conditions(raw: Any, where: str, policy_variables: bool) -> tuple[Condition, ...]:
    """Read a Condition block: {operator: {condition key: value or [values]}}."""
    if not isinstance(raw, dict) or not raw:
        raise PolicyParseError(f"{where}: 'Condition' must be a non-empty JSON object of operators")
    found = []
    for name, block in raw.items():
        try:
            set_operator, operator, if_exists = conditions.parse_operator(name)
        except PolicyError as exc:
            raise type(exc)(f"{where}: {exc}") from None
        if not isinstance(block, dict) or not block:
            raise PolicyParseError(
                f"{where}: condition {name!r} must be a non-empty JSON object of condition keys"
            )
        seen = set()
        for key, value in block.items():
            if not CONDITION_KEY.fullmatch(key) or "${" in key:
                raise PolicyParseError(
                    f"{where}: condition {name!r}: {key!r} is not a condition key such as "
                    "'aws:SourceIp'"
                )
            if key.casefold() in seen:
                raise PolicyParseError(
                    f"{where}: condition {name!r} names {key!r} twice (keys ignore case)"
                )
            seen.add(key.casefold())
            values = _condition_values(value, f"{where}: condition {name!r} on {key!r}")
            condition = Condition(operator, key, values, set_operator, if_exists)
            try:
                conditions.check(condition, policy_variables)
            except PolicyError as exc:
                raise type(exc)(f"{where}: {exc}") from None
            found.append(condition)
    return tuple(found)


def _condition_values(raw: Any, where: str) -> tuple[str, ...]:
    """A condition's values as text. AWS lets numbers and booleans go unquoted."""
    values = []
    for value in _as_list(raw):
        if isinstance(value, bool):
            values.append("true" if value else "false")
        elif isinstance(value, (str, int, float)):
            values.append(str(value))
        else:
            raise PolicyParseError(
                f"{where}: values must be strings, numbers or booleans, got {value!r}"
            )
    if not values:
        raise PolicyParseError(f"{where}: needs at least one value")
    return tuple(values)


def _check_unique_sids(statements: tuple[Statement, ...], name: str) -> None:
    """IAM requires each Sid to be unique within a policy."""
    seen = set()
    for statement in statements:
        if statement.sid in seen:
            raise PolicyParseError(f"{name}: Sid {statement.sid!r} is used more than once")
        if statement.sid is not None:
            seen.add(statement.sid)


def _resource_policy_only(element: str, where: str) -> PolicyParseError:
    return PolicyParseError(f"{where}: '{element}' is only allowed in resource-based policies")


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]
