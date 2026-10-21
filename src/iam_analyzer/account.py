"""A local "account" file: named policies plus the users, groups and roles they attach to.

    {
      "Policies": {"TeacherReadGrades": {"Statement": [...]}},
      "Groups":   {"Teachers": {"Policies": ["TeacherReadGrades"]}},
      "Users":    {"jsmith":   {"Groups": ["Teachers"], "Policies": []}},
      "Roles":    {"ITAdmin":  {"Policies": [...], "PermissionsBoundary": "..."}}
    }

Policies are defined once and attached by name, like AWS managed policies. Users can be
in groups; roles cannot (same as AWS). Users and roles can also name one policy as their
permissions boundary; groups cannot. Principals are named `user/NAME` or `role/NAME`,
so a user and a role may share a name.
"""

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from iam_analyzer.errors import AccountError
from iam_analyzer.loader import parse_policy
from iam_analyzer.models import Policy

TOP_LEVEL_KEYS = {"Policies", "Groups", "Users", "Roles"}


@dataclass(frozen=True)
class Group:
    policies: tuple[str, ...] = ()


@dataclass(frozen=True)
class User:
    policies: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    boundary: str | None = None


@dataclass(frozen=True)
class Role:
    policies: tuple[str, ...] = ()
    boundary: str | None = None


@dataclass(frozen=True)
class Account:
    name: str
    policies: dict[str, Policy]
    groups: dict[str, Group]
    users: dict[str, User]
    roles: dict[str, Role]

    def policies_for(self, principal: str) -> list[Policy]:
        """Every identity policy that applies to `principal` (`user/NAME` or `role/NAME`).

        For a user: their own policies, then each group's policies. Policies inherited
        through a group have `via_group` set; the policy name itself is unchanged.
        """
        entity = self._principal(principal)
        result = [self.policies[p] for p in entity.policies]
        if isinstance(entity, User):
            for group in entity.groups:
                result += [
                    replace(self.policies[p], via_group=group)
                    for p in self.groups[group].policies
                ]
        return result

    def boundary_for(self, principal: str) -> Policy | None:
        """The permissions boundary set on `principal`, or None if it has none."""
        entity = self._principal(principal)
        return self.policies[entity.boundary] if entity.boundary is not None else None

    def _principal(self, principal: str) -> User | Role:
        kind, _, name = principal.partition("/")
        if kind == "user" and name in self.users:
            return self.users[name]
        if kind == "role" and name in self.roles:
            return self.roles[name]
        if kind not in ("user", "role") or not name:
            raise AccountError(
                f"{self.name}: principal must be 'user/NAME' or 'role/NAME', got {principal!r}"
            )
        raise AccountError(f"{self.name}: no {kind} named {name!r}")


def load_account_file(path: str | Path) -> Account:
    """Load an account from a JSON file."""
    path = Path(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AccountError(f"{path}: cannot read file: {exc.strerror}") from exc
    except json.JSONDecodeError as exc:
        raise AccountError(f"{path.name}: invalid JSON: {exc}") from exc
    return parse_account(document, name=path.name)


def parse_account(document: Any, name: str) -> Account:
    """Build an Account from an already-decoded JSON document."""
    if not isinstance(document, dict):
        raise AccountError(f"{name}: account must be a JSON object")
    unknown = set(document) - TOP_LEVEL_KEYS
    if unknown:
        raise AccountError(f"{name}: unknown key(s): {', '.join(sorted(unknown))}")
    if "Policies" not in document:
        raise AccountError(f"{name}: account has no 'Policies'")

    policies = {
        policy_name: parse_policy(doc, name=policy_name)
        for policy_name, doc in _section(document, "Policies", name).items()
    }

    groups = {}
    for group_name, raw in _section(document, "Groups", name).items():
        where = f"{name} group {group_name!r}"
        fields = _entry(raw, {"Policies"}, where)
        groups[group_name] = Group(policies=_refs(fields, "Policies", policies, "policy", where))

    users = {}
    for user_name, raw in _section(document, "Users", name).items():
        where = f"{name} user {user_name!r}"
        fields = _entry(raw, {"Policies", "Groups", "PermissionsBoundary"}, where)
        users[user_name] = User(
            policies=_refs(fields, "Policies", policies, "policy", where),
            groups=_refs(fields, "Groups", groups, "group", where),
            boundary=_ref(fields, "PermissionsBoundary", policies, "policy", where),
        )

    roles = {}
    for role_name, raw in _section(document, "Roles", name).items():
        where = f"{name} role {role_name!r}"
        fields = _entry(raw, {"Policies", "PermissionsBoundary"}, where)
        roles[role_name] = Role(
            policies=_refs(fields, "Policies", policies, "policy", where),
            boundary=_ref(fields, "PermissionsBoundary", policies, "policy", where),
        )

    return Account(name=name, policies=policies, groups=groups, users=users, roles=roles)


def _section(document: dict, key: str, name: str) -> dict:
    section = document.get(key, {})
    if not isinstance(section, dict):
        raise AccountError(f"{name}: '{key}' must be a JSON object keyed by name")
    return section


def _entry(raw: Any, allowed: set[str], where: str) -> dict:
    if not isinstance(raw, dict):
        raise AccountError(f"{where}: must be a JSON object")
    unknown = set(raw) - allowed
    if unknown:
        raise AccountError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    return raw


def _refs(fields: dict, key: str, defined: dict, kind: str, where: str) -> tuple[str, ...]:
    """Read a list of names under `key` and check each one is defined."""
    values = fields.get(key, [])
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise AccountError(f"{where}: '{key}' must be a list of names")
    for value in values:
        if value not in defined:
            raise AccountError(f"{where}: unknown {kind} {value!r}")
    return tuple(values)


def _ref(fields: dict, key: str, defined: dict, kind: str, where: str) -> str | None:
    """Read an optional single name under `key` and check it is defined."""
    if key not in fields:
        return None
    value = fields[key]
    if not isinstance(value, str):
        raise AccountError(f"{where}: '{key}' must be a {kind} name")
    if value not in defined:
        raise AccountError(f"{where}: unknown {kind} {value!r}")
    return value
