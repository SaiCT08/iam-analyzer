"""A framework file: compliance checks, and the requirements they map to.

    {
      "Framework": {"Id": "district-student-records", "Title": "Student records"},
      "Requirements": {
        "NIST AC-6": {"Framework": "NIST SP 800-53 Rev. 5", "Id": "AC-6",
                      "Title": "Least Privilege", "Link": "https://csrc.nist.gov/..."}
      },
      "Checks": [{
        "Id": "counseling-notes", "Title": "Only counselors can read counseling notes",
        "Severity": "high", "Type": "only", "Principals": ["user/kwong"],
        "Actions": ["s3:GetObject"], "Resources": ["arn:aws:s3:::records/counseling/notes.pdf"],
        "Fix": "...", "MapsTo": ["NIST AC-6"]
      }]
    }

A framework is data, so adding one never changes the engine. Each check asks the engine
questions and states the answer it expects (see `compliance`):
  - "only": no one outside `Principals` can do it. `[]` means no one at all.
  - "requires": no one can do it unless `Key` has `Value`, such as aws:MultiFactorAuthPresent
    true. The key must be one whose every value AWS documents (`condition_keys`). `Except` leaves
    principals out.
  - "can": each of `Principals` can do it.
Principals are named as `user/NAME`, `role/NAME` or `group/NAME`, where a group stands for its
members. `Context` gives condition keys the check's question fixes, such as
{"aws:SourceIp": "203.0.113.5"}. A list gives a key several values in one request, and null says
the request doesn't include it.

A requirement gives only an ID, a short title and a link: never the framework's own text. The
title's length limit keeps it to a name.
"""

import re
from dataclasses import dataclass
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Any

from iam_analyzer import _validation, condition_keys, resources
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import FrameworkError, RequestError, UnsupportedPolicyFeature
from iam_analyzer.models import Request

TOP_LEVEL_KEYS = {"Framework", "Requirements", "Checks"}
CHECK_KEYS = {"Id", "Title", "Severity", "Type", "Actions", "Resources", "Context", "Fix", "MapsTo"}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
_PRINCIPAL = re.compile(r"(user|role|group)/.+")
# Short enough for a name, too short for pasted framework text.
_TITLE_LENGTH, _REQUIREMENT_ID_LENGTH, _CHECK_TITLE_LENGTH = 60, 40, 80

# The shared checks, reporting problems as FrameworkError.
_load_json = partial(_validation.load_json, error=FrameworkError)
_section = partial(_validation.section, error=FrameworkError)
_entry = partial(_validation.entry, error=FrameworkError)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """0 for the most severe, for sorting."""
        return list(Severity).index(self)


class CheckType(str, Enum):
    ONLY = "only"  # no one outside these principals can
    REQUIRES = "requires"  # no one can unless a key has a value
    CAN = "can"  # these principals can

    @property
    def forbids(self) -> bool:
        """Whether the check expects access to be denied."""
        return self is not CheckType.CAN


@dataclass(frozen=True)
class Requirement:
    """A framework requirement a check maps to: its ID, a short title and a link, never its text."""

    framework: str  # such as "NIST SP 800-53 Rev. 5"
    id: str  # such as "AC-6"
    title: str
    link: str


@dataclass(frozen=True)
class Check:
    """One compliance check: the questions it asks, and the answer it expects.

    `principals` are the principals an "only" check allows, or that a "can" check asks about.
    `exempt` are the principals a "requires" check leaves out, and `key` and `value` are what it
    requires. `context` holds the condition keys the check's question fixes.
    """

    id: str
    title: str
    severity: Severity
    type: CheckType
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    fix: str
    principals: tuple[str, ...] = ()
    exempt: tuple[str, ...] = ()
    key: str | None = None
    value: str | None = None
    context: RequestContext = RequestContext()
    maps_to: tuple[Requirement, ...] = ()


@dataclass(frozen=True)
class Framework:
    name: str  # the file name, used in messages
    id: str
    title: str
    checks: tuple[Check, ...]


def load_framework_file(path: str | Path) -> Framework:
    """Load a framework from a JSON file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FrameworkError(f"{path}: cannot read file: {exc.strerror}") from exc
    return parse_framework(_load_json(text, path.name), name=path.name)


def parse_framework(document: Any, name: str) -> Framework:
    """Build a Framework from an already-decoded JSON document."""
    if not isinstance(document, dict):
        raise FrameworkError(f"{name}: framework must be a JSON object")
    unknown = set(document) - TOP_LEVEL_KEYS
    if unknown:
        raise FrameworkError(f"{name}: unknown key(s): {', '.join(sorted(unknown))}")
    for key in ("Framework", "Checks"):
        if key not in document:
            raise FrameworkError(f"{name}: framework has no {key!r}")
    about = _entry(document["Framework"], {"Id", "Title"}, f"{name} 'Framework'")
    framework_id = _id(about, f"{name} 'Framework'")
    title = _text(about, "Title", _CHECK_TITLE_LENGTH, f"{name} 'Framework'")

    requirements = {
        key: _requirement(raw, f"{name} requirement {key!r}")
        for key, raw in _section(document, "Requirements", name).items()
    }

    raw_checks = document["Checks"]
    if not isinstance(raw_checks, list) or not raw_checks:
        raise FrameworkError(f"{name}: 'Checks' must be a non-empty list of checks")
    checks = []
    seen = set()
    for index, raw in enumerate(raw_checks):
        check = _check(raw, requirements, f"{name} check {index}")
        if check.id in seen:
            raise FrameworkError(f"{name}: check Id {check.id!r} is used more than once")
        seen.add(check.id)
        checks.append(check)
    return Framework(name=name, id=framework_id, title=title, checks=tuple(checks))


def _requirement(raw: Any, where: str) -> Requirement:
    fields = _entry(raw, {"Framework", "Id", "Title", "Link"}, where)
    link = fields.get("Link")
    if not (isinstance(link, str) and link.startswith("https://") and not re.search(r"\s", link)):
        raise FrameworkError(f"{where}: 'Link' must be an https:// URL, got {link!r}")
    return Requirement(
        framework=_text(fields, "Framework", _TITLE_LENGTH, where),
        id=_text(fields, "Id", _REQUIREMENT_ID_LENGTH, where),
        title=_text(fields, "Title", _TITLE_LENGTH, where),
        link=link,
    )


def _check(raw: Any, requirements: dict[str, Requirement], where: str) -> Check:
    if not isinstance(raw, dict):
        raise FrameworkError(f"{where}: must be a JSON object")
    check_id = _id(raw, where)
    where = f"{where} ({check_id})"
    try:
        check_type = CheckType(raw.get("Type"))
    except ValueError:
        raise FrameworkError(
            f"{where}: 'Type' must be \"only\", \"requires\" or \"can\", got {raw.get('Type')!r}"
        ) from None
    allowed = CHECK_KEYS | (
        {"Key", "Value", "Except"} if check_type is CheckType.REQUIRES else {"Principals"}
    )
    fields = _entry(raw, allowed, where)
    try:
        severity = Severity(fields.get("Severity"))
    except ValueError:
        raise FrameworkError(
            f"{where}: 'Severity' must be critical, high, medium or low, got "
            f"{fields.get('Severity')!r}"
        ) from None
    actions = _strings(fields, "Actions", where)
    check_resources = _strings(fields, "Resources", where)
    _check_requests(actions, check_resources, where)
    fix = fields.get("Fix")
    if not (isinstance(fix, str) and fix.strip()):
        raise FrameworkError(f"{where}: 'Fix' must say how to fix a failure")

    principals: tuple[str, ...] = ()
    exempt: tuple[str, ...] = ()
    key = value = None
    if check_type is CheckType.REQUIRES:
        key, value = _required(fields, where)
        exempt = _principals(fields, "Except", where, required=False)
    else:
        principals = _principals(fields, "Principals", where, required=True)
        if check_type is CheckType.CAN and not principals:
            raise FrameworkError(f"{where}: a \"can\" check needs at least one principal to ask")

    context = _context(fields, where)
    if key is not None and context.knows(key):
        raise FrameworkError(f"{where}: 'Context' can't give {key!r}, which the check requires")

    maps_to = _strings(fields, "MapsTo", where, required=False)
    for reference in maps_to:
        if reference not in requirements:
            raise FrameworkError(f"{where}: 'MapsTo' names unknown requirement {reference!r}")
    return Check(
        id=check_id,
        title=_text(fields, "Title", _CHECK_TITLE_LENGTH, where),
        severity=severity,
        type=check_type,
        actions=actions,
        resources=check_resources,
        fix=fix.strip(),
        principals=principals,
        exempt=exempt,
        key=key,
        value=value,
        context=context,
        maps_to=tuple(requirements[reference] for reference in maps_to),
    )


def _check_requests(actions: tuple[str, ...], check_resources: tuple[str, ...], where: str) -> None:
    """Refuse requests AWS couldn't receive, as `check` does: an action with a wildcard, or a
    resource that isn't "*" or one full ARN. A resource the analyzer can't evaluate yet, such as a
    KMS key, is the report's to call CAN'T TELL."""
    for action in actions:
        for resource in check_resources:
            try:
                Request(action=action, resource=resource)
                resources.governing_arn(resource, action)
            except RequestError as exc:
                raise FrameworkError(f"{where}: {exc}") from None
            except UnsupportedPolicyFeature:
                pass
    for resource in check_resources:
        if "*" in resource.removeprefix("*") or "?" in resource:
            raise FrameworkError(
                f"{where}: {resource!r}: a check asks about one resource, so it can't have "
                "wildcards"
            )


def _required(fields: dict, where: str) -> tuple[str, str]:
    """A "requires" check's key and the value it must have."""
    key, value = fields.get("Key"), fields.get("Value")
    known = condition_keys.values_of(key) if isinstance(key, str) else None
    if known is None:
        names = ", ".join(entry.key for entry in condition_keys.KNOWN)
        raise FrameworkError(
            f"{where}: 'Key' must be a key whose every value AWS documents ({names}), got {key!r}"
        )
    choices = [option for option in known.values if option is not None]
    if value not in choices:
        raise FrameworkError(
            f"{where}: 'Value' for {known.key} must be one of {', '.join(choices)}, got {value!r}"
        )
    return known.key, value


def _principals(fields: dict, key: str, where: str, *, required: bool) -> tuple[str, ...]:
    if required and key not in fields:
        raise FrameworkError(f"{where}: missing {key!r}")
    names = fields.get(key, [])
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise FrameworkError(f"{where}: {key!r} must be a list of user/, role/ or group/ names")
    for name in names:
        if not _PRINCIPAL.fullmatch(name):
            raise FrameworkError(
                f"{where}: {key!r} entry {name!r} must be user/NAME, role/NAME or group/NAME"
            )
    if len(set(names)) != len(names):
        raise FrameworkError(f"{where}: {key!r} names someone more than once")
    return tuple(names)


def _context(fields: dict, where: str) -> RequestContext:
    """The condition keys the check fixes: a value, a list of values, or null for absent."""
    raw = fields.get("Context", {})
    if not isinstance(raw, dict):
        raise FrameworkError(f"{where}: 'Context' must be a JSON object of condition keys")
    values: list[tuple[str, str]] = []
    absent: list[str] = []
    for key, value in raw.items():
        if value is None:
            absent.append(key)
        elif isinstance(value, str):
            values.append((key, value))
        elif isinstance(value, list) and value and all(isinstance(v, str) for v in value):
            values += [(key, v) for v in value]
        else:
            raise FrameworkError(
                f"{where}: 'Context' value for {key!r} must be a string, a non-empty list of "
                f"strings, or null for absent, got {value!r}"
            )
    try:
        return RequestContext.of(values, absent, source=f"{where} 'Context'")
    except RequestError as exc:
        raise FrameworkError(f"{where}: 'Context': {exc}") from None


def _strings(fields: dict, key: str, where: str, *, required: bool = True) -> tuple[str, ...]:
    if key not in fields:
        if required:
            raise FrameworkError(f"{where}: missing {key!r}")
        return ()
    values = fields[key]
    if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
        raise FrameworkError(f"{where}: {key!r} must be a list of non-empty strings")
    if required and not values:
        raise FrameworkError(f"{where}: {key!r} must not be empty")
    if len(set(values)) != len(values):
        raise FrameworkError(f"{where}: {key!r} lists something more than once")
    return tuple(values)


def _id(fields: dict, where: str) -> str:
    value = fields.get("Id")
    if not (isinstance(value, str) and _ID.fullmatch(value)):
        raise FrameworkError(
            f"{where}: 'Id' must be letters, digits and hyphens, such as \"counseling-notes\", "
            f"got {value!r}"
        )
    return value


def _text(fields: dict, key: str, longest: int, where: str) -> str:
    """A short, one-line name."""
    value = fields.get(key)
    if not (isinstance(value, str) and value.strip() and len(value) <= longest):
        raise FrameworkError(f"{where}: {key!r} must be a string of 1 to {longest} characters")
    if "\n" in value:
        raise FrameworkError(f"{where}: {key!r} must be one line")
    return value
