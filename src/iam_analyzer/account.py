"""A local "account" file: named policies plus the users, groups and roles they attach to.

    {
      "Policies": {"TeacherReadGrades": {"Statement": [...]}},
      "Groups":   {"Teachers": {"Policies": ["TeacherReadGrades"]}},
      "Users":    {"jsmith":   {"Groups": ["Teachers"], "Policies": []}},
      "Roles":    {"ITAdmin":  {"Policies": [...]}}
    }

Policies are defined once and attached by name, like AWS managed policies. Users can be
in groups; roles cannot (same as AWS). Principals are named `user/NAME` or `role/NAME`,
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


@dataclass(frozen=True)
class Role:
    policies: tuple[str, ...] = ()


@dataclass(frozen=True)
class Account:
    name: str
    policies: dict[str, Policy]
    groups: dict[str, Group]
    users: dict[str, User]
    roles: dict[str, Role]

    def policies_for(self, principal: str) -> list[Policy]:
        """Every policy that applies to `principal` (`user/NAME` or `role/NAME`).

        For a user: their own policies, then each group's policies. Policies inherited
        through a group have `via_group` set; the policy name itself is unchanged.
        """
        kind, _, name = principal.partition("/")
        if kind == "user" and name in self.users:
            user = self.users[name]
            result = [self.policies[p] for p in user.policies]
            for group in user.groups:
                result += [
                    replace(self.policies[p], via_group=group)
                    for p in self.groups[group].policies
                ]
            return result
        if kind == "role" and name in self.roles:
            return [self.policies[p] for p in self.roles[name].policies]
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
        fields = _entry(raw, {"Policies", "Groups"}, where)
        users[user_name] = User(
            policies=_refs(fields, "Policies", policies, "policy", where),
            groups=_refs(fields, "Groups", groups, "group", where),
        )

    roles = {}
    for role_name, raw in _section(document, "Roles", name).items():
        where = f"{name} role {role_name!r}"
        fields = _entry(raw, {"Policies"}, where)
        roles[role_name] = Role(policies=_refs(fields, "Policies", policies, "policy", where))

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
