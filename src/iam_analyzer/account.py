"""A local "account" file: named policies plus the users, groups and roles they attach to.

    {
      "AccountId": "111122223333",
      "Policies": {"TeacherReadGrades": {"Statement": [...]}},
      "Groups":   {"Teachers": {"Policies": ["TeacherReadGrades"]}},
      "Users":    {"jsmith":   {"Groups": ["Teachers"], "Policies": []}},
      "Roles":    {"ITAdmin":  {"Policies": [...], "PermissionsBoundary": "..."}}
    }

Policies are defined once and attached by name, like AWS managed policies. Users can be
in groups; roles cannot (same as AWS). Users and roles can also name one policy as their
permissions boundary; groups cannot. Principals are named `user/NAME` or `role/NAME`,
so a user and a role may share a name. `AccountId` is optional; it is only needed to
look up the account's SCPs in an organization file.

Roles can have a `Path`, as in AWS (default "/"). AWS creates service-linked roles for its
own services under "/aws-service-role/", and SCPs never apply to them.
"""

from dataclasses import dataclass, replace
from functools import partial
from pathlib import Path
from typing import Any

from iam_analyzer import _validation
from iam_analyzer.errors import AccountError
from iam_analyzer.loader import parse_policy
from iam_analyzer.models import Policy

TOP_LEVEL_KEYS = {"AccountId", "Policies", "Groups", "Users", "Roles"}
# The path AWS gives every service-linked role, e.g. "/aws-service-role/support.amazonaws.com/".
SERVICE_LINKED_PATH = "/aws-service-role/"

# The shared checks, reporting problems as AccountError.
_load_json = partial(_validation.load_json, error=AccountError)
_section = partial(_validation.section, error=AccountError)
_entry = partial(_validation.entry, error=AccountError)
_refs = partial(_validation.refs, error=AccountError)
_ref = partial(_validation.ref, error=AccountError)
_account_id = partial(_validation.account_id, error=AccountError)


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
    path: str = "/"

    @property
    def service_linked(self) -> bool:
        return self.path.startswith(SERVICE_LINKED_PATH)


@dataclass(frozen=True)
class Account:
    name: str
    policies: dict[str, Policy]
    groups: dict[str, Group]
    users: dict[str, User]
    roles: dict[str, Role]
    account_id: str | None = None

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

    def is_service_linked(self, principal: str) -> bool:
        """Whether `principal` is a service-linked role, which SCPs never restrict."""
        entity = self._principal(principal)
        return isinstance(entity, Role) and entity.service_linked

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
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AccountError(f"{path}: cannot read file: {exc.strerror}") from exc
    return parse_account(_load_json(text, path.name), name=path.name)


def parse_account(document: Any, name: str) -> Account:
    """Build an Account from an already-decoded JSON document."""
    if not isinstance(document, dict):
        raise AccountError(f"{name}: account must be a JSON object")
    unknown = set(document) - TOP_LEVEL_KEYS
    if unknown:
        raise AccountError(f"{name}: unknown key(s): {', '.join(sorted(unknown))}")
    if "Policies" not in document:
        raise AccountError(f"{name}: account has no 'Policies'")
    account_id = None
    if "AccountId" in document:
        account_id = _account_id(document["AccountId"], f"{name} 'AccountId'")

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
        fields = _entry(raw, {"Policies", "PermissionsBoundary", "Path"}, where)
        roles[role_name] = Role(
            policies=_refs(fields, "Policies", policies, "policy", where),
            boundary=_ref(fields, "PermissionsBoundary", policies, "policy", where),
            path=_path(fields, where),
        )

    return Account(
        name=name,
        policies=policies,
        groups=groups,
        users=users,
        roles=roles,
        account_id=account_id,
    )


def _path(fields: dict, where: str) -> str:
    """Read an optional role `Path`. As in AWS, it starts and ends with "/"."""
    value = fields.get("Path", "/")
    if not isinstance(value, str) or not (value.startswith("/") and value.endswith("/")):
        raise AccountError(
            f"{where}: 'Path' must be a string that starts and ends with '/', got {value!r}"
        )
    return value
