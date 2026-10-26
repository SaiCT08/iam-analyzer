"""An organization file: SCPs, and the tree of OUs and accounts they are attached to.

    {
      "ManagementAccountId": "999988887777",
      "ServiceControlPolicies": {"FullAWSAccess": {"Statement": [...]}},
      "Root": {
        "ServiceControlPolicies": ["FullAWSAccess"],
        "OrganizationalUnits": {
          "Schools": {
            "ServiceControlPolicies": ["FullAWSAccess"],
            "Accounts": {"111122223333": {"ServiceControlPolicies": ["FullAWSAccess"]}}
          }
        },
        "Accounts": {"999988887777": {"ServiceControlPolicies": ["FullAWSAccess"]}}
      }
    }

SCPs are defined once and attached by name to the root, OUs and accounts, and OUs can
hold more OUs. The rules follow AWS:
  - every root, OU and account has at least one SCP (AWS attaches FullAWSAccess by default);
  - a request must be allowed at every level from the root down to the account;
  - SCPs never apply to the management account, or to service-linked roles in any account.
SCPs are loaded as SCPs, so a short ARN such as arn:aws:s3 is refused in them: AWS documents
completing one only in identity-based policies.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

from iam_analyzer import _validation
from iam_analyzer.errors import OrganizationError
from iam_analyzer.loader import parse_policy
from iam_analyzer.models import OrgTarget, Policy, PolicyType, ScpLevel, TargetType

SCPS = "ServiceControlPolicies"
TOP_LEVEL_KEYS = {"ManagementAccountId", SCPS, "Root"}

# The shared checks, reporting problems as OrganizationError.
_load_json = partial(_validation.load_json, error=OrganizationError)
_section = partial(_validation.section, error=OrganizationError)
_entry = partial(_validation.entry, error=OrganizationError)
_refs = partial(_validation.refs, error=OrganizationError)
_account_id = partial(_validation.account_id, error=OrganizationError)


@dataclass(frozen=True)
class Organization:
    name: str
    management_account_id: str
    policies: dict[str, Policy]
    # Each account's SCP levels, from the root down to the account itself.
    account_paths: dict[str, tuple[ScpLevel, ...]]

    def scp_levels_for(
        self, account_id: str, *, service_linked: bool = False
    ) -> tuple[ScpLevel, ...]:
        """The SCP levels that apply to a principal in `account_id`, root first.

        Empty for the principals SCPs never restrict: everyone in the management account,
        and service-linked roles (`service_linked=True`) in any account.
        """
        if account_id not in self.account_paths:
            raise OrganizationError(f"{self.name}: no account {account_id!r} in the organization")
        if account_id == self.management_account_id or service_linked:
            return ()
        return self.account_paths[account_id]


def load_organization_file(path: str | Path) -> Organization:
    """Load an organization from a JSON file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OrganizationError(f"{path}: cannot read file: {exc.strerror}") from exc
    return parse_organization(_load_json(text, path.name), name=path.name)


def parse_organization(document: Any, name: str) -> Organization:
    """Build an Organization from an already-decoded JSON document."""
    if not isinstance(document, dict):
        raise OrganizationError(f"{name}: organization must be a JSON object")
    unknown = set(document) - TOP_LEVEL_KEYS
    if unknown:
        raise OrganizationError(f"{name}: unknown key(s): {', '.join(sorted(unknown))}")
    missing = TOP_LEVEL_KEYS - set(document)
    if missing:
        raise OrganizationError(f"{name}: missing key(s): {', '.join(sorted(missing))}")

    management = _account_id(document["ManagementAccountId"], f"{name} 'ManagementAccountId'")
    policies = {
        policy_name: parse_policy(doc, name=policy_name, kind=PolicyType.SCP)
        for policy_name, doc in _section(document, SCPS, name).items()
    }

    root = OrgTarget(TargetType.ROOT, "Root")
    account_paths: dict[str, tuple[ScpLevel, ...]] = {}
    for account_id, path in _account_paths(document["Root"], root, (), policies, f"{name} root"):
        if account_id in account_paths:
            raise OrganizationError(f"{name}: account {account_id!r} appears more than once")
        account_paths[account_id] = path
    if management not in account_paths:
        raise OrganizationError(f"{name}: management account {management!r} is not in the tree")

    return Organization(
        name=name,
        management_account_id=management,
        policies=policies,
        account_paths=account_paths,
    )


def _account_paths(
    raw: Any,
    target: OrgTarget,
    parents: tuple[ScpLevel, ...],
    policies: dict[str, Policy],
    where: str,
) -> Iterator[tuple[str, tuple[ScpLevel, ...]]]:
    """Yield (account ID, SCP levels from the root down) for each account at or below `target`."""
    is_account = target.type is TargetType.ACCOUNT
    allowed = {SCPS} if is_account else {SCPS, "OrganizationalUnits", "Accounts"}
    fields = _entry(raw, allowed, where)
    names = _refs(fields, SCPS, policies, "SCP", where)
    if not names:
        raise OrganizationError(
            f"{where}: needs at least one SCP (AWS attaches FullAWSAccess by default)"
        )
    path = (*parents, ScpLevel(target, tuple(policies[n] for n in names)))

    if is_account:
        yield target.name, path
        return
    for ou_name, ou in _section(fields, "OrganizationalUnits", where).items():
        ou_target = OrgTarget(TargetType.ORGANIZATIONAL_UNIT, ou_name)
        yield from _account_paths(ou, ou_target, path, policies, f"{where} OU {ou_name!r}")
    for account_id, account in _section(fields, "Accounts", where).items():
        account_where = f"{where} account {account_id!r}"
        _account_id(account_id, account_where)
        account_target = OrgTarget(TargetType.ACCOUNT, account_id)
        yield from _account_paths(account, account_target, path, policies, account_where)
