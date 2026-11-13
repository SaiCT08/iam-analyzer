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

Users and roles can have a `Path`, as in AWS (default "/"). AWS creates service-linked roles
for its own services under "/aws-service-role/", and SCPs never apply to them.

Users and roles can also have `Tags`, in AWS's shape: [{"Key": "campus", "Value": "campus-01"}].
Policies read them as aws:PrincipalTag/campus. Groups can't be tagged, as in IAM.

`Resources` describes the account's resources by ARN, which a request on a specific resource
needs (see `resources`): {"arn:aws:s3:::district-staff-files": {}} says the bucket is in this
account and has no resource-based policy, and {"Policy": {...}} gives a bucket its bucket policy.
Describing a bucket also says its ACLs are disabled (Object Ownership "Bucket owner enforced").
For an S3 object, its bucket is described.

A role's `AssumeRolePolicyDocument` is its trust policy, which the STS actions on the role, such
as sts:AssumeRole, need. Bucket and trust policies' Principal elements name ARNs, so a file with
either needs an `AccountId`.

`Account.request` and `Account.evaluate` ask a question about one of the file's principals with
everything the file says, so every caller, the CLI and compliance reports alike, gets the same
AWS rules.
"""

import re
from dataclasses import dataclass, field, replace
from functools import partial
from pathlib import Path
from typing import Any

from iam_analyzer import _validation, evaluator, resources
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import AccountError, UnsupportedPolicyFeature
from iam_analyzer.loader import parse_policy
from iam_analyzer.models import EvaluationResult, Policy, PolicyType, Request, Resource
from iam_analyzer.organization import Organization

TOP_LEVEL_KEYS = {"AccountId", "Policies", "Groups", "Users", "Roles", "Resources"}
# The path AWS gives every service-linked role, e.g. "/aws-service-role/support.amazonaws.com/".
SERVICE_LINKED_PATH = "/aws-service-role/"
TAG_PREFIX = "aws:PrincipalTag/"
# IAM's rules for tag keys and values: these characters only, and limited lengths.
_TAG_TEXT = re.compile(r"[\w .:/=+\-@]*")
_TAG_KEY_LENGTH, _TAG_VALUE_LENGTH = 128, 256

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
    path: str = "/"
    tags: tuple[tuple[str, str], ...] = ()  # (key, value) pairs, in file order


@dataclass(frozen=True)
class Role:
    policies: tuple[str, ...] = ()
    boundary: str | None = None
    path: str = "/"
    tags: tuple[tuple[str, str], ...] = ()
    trust_policy: Policy | None = None  # None when the file doesn't give it

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
    # The described resources, keyed by ARN.
    resources: dict[str, Resource] = field(default_factory=dict)

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

    def principal_context(self, principal: str, *, session_tags: bool = True) -> RequestContext:
        """The condition keys AWS fills in for `principal`, as far as this file knows them.

        - aws:username is a user's name. Roles have none, so for them it is absent.
        - aws:PrincipalType is "User" for a user and "AssumedRole" for a role.
        - aws:PrincipalArn and aws:PrincipalAccount need the file's AccountId. For a role, the
          ARN is the role's own, not the session's.
        - aws:PrincipalTag/KEY comes from Tags, and a user's tags are all there is. A role's
          session can carry session tags, which override the role's tags and can add new
          ones, so a role's tag keys are unknown unless `session_tags` is False, or its trust
          policy rules session tags out (see `resources.session_tags_possible`). A session
          tag can't remove a role's tag, though, so the role's own keys are always present.

        Other keys, such as aws:userid, aren't in the file, so the caller has to give them.
        """
        entity = self._principal(principal)
        if isinstance(entity, Role) and entity.trust_policy is not None:
            session_tags = session_tags and resources.session_tags_possible(entity.trust_policy)
        kind, _, name = principal.partition("/")
        source = f"{self.name} {principal}"
        values: list[tuple[str, str]] = []
        absent: list[str] = []
        if isinstance(entity, User):
            values += [("aws:username", name), ("aws:PrincipalType", "User")]
        else:
            absent.append("aws:username")
            values.append(("aws:PrincipalType", "AssumedRole"))
        if self.account_id is not None:
            arn = f"arn:aws:iam::{self.account_id}:{kind}{entity.path}{name}"
            values += [("aws:PrincipalArn", arn), ("aws:PrincipalAccount", self.account_id)]
        tags = [(f"{TAG_PREFIX}{key}", value) for key, value in entity.tags]
        if isinstance(entity, User) or not session_tags:
            return RequestContext.of(
                [*values, *tags], absent, absent_prefixes=[TAG_PREFIX], source=source
            )
        reason = (
            f"{principal} has this tag, and session tags can override a role's tags "
            "but not remove them"
        )
        return RequestContext.of(
            values, absent, present={key: reason for key, _ in tags}, source=source
        )

    def resource_for(self, resource: str, action: str) -> Resource | None:
        """What this file says about the resource that a request for `action` on `resource`
        needs described: for an S3 object, its bucket, and for the STS actions on a role, the
        role with its trust policy.

        None when the request needs no description, or when the file doesn't describe it.
        """
        governing = resources.governing_arn(resource, action)
        if governing is None:
            return None
        if resources.is_role_arn(governing):
            return self._role_resource(governing)
        return self.resources.get(governing)

    def request(
        self,
        principal: str,
        action: str,
        resource: str,
        *,
        context: RequestContext = RequestContext(),
        session_tags: bool = True,
    ) -> Request:
        """A request by `principal`: the condition keys this file knows about the principal (see
        `principal_context`), plus `context` for the rest. A key both of them give is refused, so
        `context` can't change what the file says.
        """
        known = self.principal_context(principal, session_tags=session_tags)
        return Request(action=action, resource=resource, context=known.merged(context))

    def evaluate(
        self, principal: str, request: Request, *, organization: Organization | None
    ) -> EvaluationResult:
        """Evaluate `request` by `principal` with everything this file says about it: its identity
        policies, its permissions boundary, and the resource the request needs described.

        With `organization`, the SCPs that apply to the principal are evaluated too. They need the
        file's AccountId, and they never apply to a service-linked role. None says the account
        isn't in an organization, so no SCPs apply. Callers have to say which, because leaving
        SCPs out can allow what they would deny.
        """
        scps = ()
        if organization is not None:
            if self.account_id is None:
                raise AccountError(f"{self.name}: needs an 'AccountId' to look up its SCPs")
            scps = organization.scp_levels_for(
                self.account_id, service_linked=self.is_service_linked(principal)
            )
        return evaluator.evaluate(
            request,
            self.policies_for(principal),
            boundary=self.boundary_for(principal),
            scps=scps,
            resource=self.resource_for(request.resource, request.action),
        )

    def _role_resource(self, arn: str) -> Resource | None:
        """The role `arn` names, with its trust policy. None when the role is in another account,
        which the evaluator refuses, or when the file doesn't give its trust policy."""
        _, _, _, _, account, resource = arn.split(":", 5)
        if account != self.account_id:
            return None
        path, _, name = resource.removeprefix("role").rpartition("/")
        path += "/"
        if name not in self.roles:
            same = [role for role in self.roles if role.casefold() == name.casefold()]
            if same:
                raise UnsupportedPolicyFeature(
                    f"{self.name}: {arn} names role {name!r}, and the file has {same[0]!r}: IAM "
                    "role names ignore case, and AWS doesn't say whether a role ARN does too"
                )
            raise AccountError(f"{self.name}: no role named {name!r}, which {arn} names")
        role = self.roles[name]
        if role.path != path:
            raise AccountError(
                f"{self.name}: role {name!r} has the path {role.path!r}, not {path!r} as {arn} says"
            )
        return None if role.trust_policy is None else Resource(arn, role.trust_policy)

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
        fields = _entry(raw, {"Policies", "Groups", "PermissionsBoundary", "Path", "Tags"}, where)
        users[user_name] = User(
            policies=_refs(fields, "Policies", policies, "policy", where),
            groups=_refs(fields, "Groups", groups, "group", where),
            boundary=_ref(fields, "PermissionsBoundary", policies, "policy", where),
            path=_path(fields, where),
            tags=_tags(fields, where),
        )

    roles = {}
    for role_name, raw in _section(document, "Roles", name).items():
        where = f"{name} role {role_name!r}"
        allowed = {"Policies", "PermissionsBoundary", "Path", "Tags", "AssumeRolePolicyDocument"}
        fields = _entry(raw, allowed, where)
        path = _path(fields, where)
        trust_policy = None
        if "AssumeRolePolicyDocument" in fields:
            if account_id is None:
                raise AccountError(
                    f"{where}: a trust policy names principals by ARN, so the account file needs "
                    "an 'AccountId' to know which ARNs are its users' and roles'"
                )
            arn = f"arn:aws:iam::{account_id}:role{path}{role_name}"
            trust_policy = parse_policy(
                fields["AssumeRolePolicyDocument"], name=arn, kind=PolicyType.TRUST
            )
        roles[role_name] = Role(
            policies=_refs(fields, "Policies", policies, "policy", where),
            boundary=_ref(fields, "PermissionsBoundary", policies, "policy", where),
            path=path,
            tags=_tags(fields, where),
            trust_policy=trust_policy,
        )

    described = {
        arn: _resource(arn, raw, account_id, f"{name} resource {arn!r}")
        for arn, raw in _section(document, "Resources", name).items()
    }
    if account_id is None and any(r.policy is not None for r in described.values()):
        raise AccountError(
            f"{name}: a bucket policy's Principal elements name ARNs, so the account file needs "
            "an 'AccountId' to know which ARNs are its users' and roles'"
        )

    return Account(
        name=name,
        policies=policies,
        groups=groups,
        users=users,
        roles=roles,
        account_id=account_id,
        resources=described,
    )


def _resource(text: str, raw: Any, account_id: str | None, where: str) -> Resource:
    """Read one `Resources` entry: a resource in this account, and its resource-based policy.

    The ARN must name one resource that a request can need described: not an IAM or STS
    resource, not a KMS key, and for S3, a bucket rather than an object.
    """
    fields = _entry(raw, {"Policy"}, where)
    arn = resources.Arn.parse(text)
    if arn is None or "*" in text or "?" in text:
        raise AccountError(
            f"{where}: must be the full ARN of one resource, such as "
            "arn:aws:s3:::amzn-s3-demo-bucket"
        )
    if arn.service in resources.EXEMPT_SERVICES:
        raise AccountError(
            f"{where}: IAM and STS resources aren't described here; AWS says the only IAM "
            "resource-based policy is a role's trust policy, which belongs to the role"
        )
    reason = resources.unsupported(arn)
    if reason is not None:
        raise UnsupportedPolicyFeature(f"{where}: {reason}")
    if arn.service == "s3" and resources.bucket_arn(arn) != text:
        raise AccountError(
            f"{where}: describe the bucket, not an object in it; a bucket's policy covers its "
            "objects"
        )
    if arn.account:
        if arn.account_id is None:
            raise AccountError(f"{where}: the account field must be empty or a 12-digit account ID")
        if account_id is None:
            raise AccountError(
                f"{where}: names account {arn.account}, so the account file needs an 'AccountId'"
            )
        if arn.account != account_id:
            raise AccountError(
                f"{where}: is in account {arn.account}, not this file's account {account_id}; "
                "cross-account requests aren't supported yet"
            )
    if "Policy" not in fields:
        return Resource(text)
    resources.check_policy_support(text, where=where)
    return Resource(text, parse_policy(fields["Policy"], name=text, kind=PolicyType.RESOURCE_BASED))


def _tags(fields: dict, where: str) -> tuple[tuple[str, str], ...]:
    """Read optional `Tags`, in AWS's shape: [{"Key": "campus", "Value": "campus-01"}].

    IAM's rules apply: only letters, numbers, spaces and _ . : / = + - @, nothing that starts
    with "aws:", and keys unique ignoring case (IAM treats Campus and campus as one tag).
    """
    raw = fields.get("Tags", [])
    if not isinstance(raw, list):
        raise AccountError(f"{where}: 'Tags' must be a list of {{\"Key\": ..., \"Value\": ...}}")
    tags = []
    seen = set()
    for index, tag in enumerate(raw):
        tag_where = f"{where} tag {index}"
        entry = _entry(tag, {"Key", "Value"}, tag_where)
        key, value = entry.get("Key"), entry.get("Value")
        _tag_text(key, "Key", 1, _TAG_KEY_LENGTH, tag_where)
        _tag_text(value, "Value", 0, _TAG_VALUE_LENGTH, tag_where)
        if key.casefold() in seen:
            raise AccountError(
                f"{tag_where}: tag key {key!r} is used more than once (IAM ignores its case)"
            )
        seen.add(key.casefold())
        tags.append((key, value))
    return tuple(tags)


def _tag_text(text: Any, field: str, shortest: int, longest: int, where: str) -> None:
    fits = isinstance(text, str) and shortest <= len(text) <= longest
    if not (fits and _TAG_TEXT.fullmatch(text)):
        raise AccountError(
            f"{where}: '{field}' must be a string of {shortest} to {longest} letters, numbers, "
            f"spaces or _ . : / = + - @, got {text!r}"
        )
    if text.casefold().startswith("aws:"):
        raise AccountError(f"{where}: '{field}' can't start with 'aws:', which AWS reserves")


def _path(fields: dict, where: str) -> str:
    """Read an optional user or role `Path`. As in AWS, it starts and ends with "/"."""
    value = fields.get("Path", "/")
    if not isinstance(value, str) or not (value.startswith("/") and value.endswith("/")):
        raise AccountError(
            f"{where}: 'Path' must be a string that starts and ends with '/', got {value!r}"
        )
    return value
