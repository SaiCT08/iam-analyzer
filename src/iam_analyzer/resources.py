"""Which resource a request needs described, because of the resource-based policies AWS consults.

AWS also consults the resource-based policy attached to the resource a request is on, such as an
S3 bucket policy. The analyzer can't tell from an ARN whether a resource has one, or which account
it is in (an S3 ARN names no account), so a request on a specific resource needs that resource
described (`models.Resource`). There are three exceptions:
  - "*", which names no resource;
  - IAM resources, except a role for the STS actions on it. AWS: "The IAM resource-based policy
    type is a role trust policy."
  - STS resources, which AWS's table of services that work with IAM lists with no resource-based
    policies.
For an S3 object, it is the bucket that is described, because a bucket policy covers its objects.

That table isn't used to exempt more services: it rates services, not ARN namespaces (EC2 says
No, but VPC, which also uses ec2: ARNs, says Partial), and it never defines Partial.

Requests on KMS keys are refused, because every key has a key policy that must allow them and the
analyzer doesn't evaluate key policies yet. So are requests on S3 resources other than buckets and
objects, such as access points.

Only S3 bucket policies and role trust policies are evaluated so far. AWS: "Resource-based
policies for services other than IAM and AWS KMS may also require an explicit Allow statement
within the same account", so another service's resource can be described only as having none.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iam_analyzer import _validation
from iam_analyzer.errors import PolicyParseError, RequestError, UnsupportedPolicyFeature
from iam_analyzer.loader import parse_policy
from iam_analyzer.matching import match_action
from iam_analyzer.models import Effect, Policy, PolicyType, PrincipalType, Resource, Statement

# The actions that start a session of a role.
ASSUME_ACTIONS = ("sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity")
# The STS actions whose resource type is "role" in the STS page of the Service Authorization
# Reference. A role's trust policy covers them.
ROLE_ACTIONS = (*ASSUME_ACTIONS, "sts:SetContext", "sts:SetSourceIdentity", "sts:TagSession")
# Services whose resources have no resource-based policies of their own. IAM's one kind, a role's
# trust policy, is handled separately.
EXEMPT_SERVICES = ("iam", "sts")

_ROLE_ACTIONS = {action.casefold() for action in ROLE_ACTIONS}
_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_USER_ARN = re.compile(r"arn:[a-z-]+:iam::[0-9]{12}:user/.+")


@dataclass(frozen=True)
class Arn:
    """An ARN's six fields: arn:partition:service:region:account:resource."""

    partition: str
    service: str
    region: str
    account: str
    resource: str

    @classmethod
    def parse(cls, text: str) -> "Arn | None":
        """Split `text` into its fields, or return None when it isn't a full ARN."""
        fields = text.split(":", 5)
        if len(fields) != 6 or fields[0] != "arn":
            return None
        arn = cls(*fields[1:])
        return arn if arn.partition and arn.service and arn.resource else None

    @property
    def account_id(self) -> str | None:
        """The account the ARN names, or None when it names none, as S3 ARNs don't."""
        return self.account if _ACCOUNT_ID.fullmatch(self.account) else None


def governing_arn(resource: str, action: str) -> str | None:
    """The ARN that a request for `action` on `resource` needs described, or None when no
    resource-based policy can apply to it.

    Raises UnsupportedPolicyFeature for a resource the analyzer can't evaluate yet, and
    RequestError for a resource that isn't "*" or one full ARN.
    """
    arn = Arn.parse(resource)
    if action.casefold() in _ROLE_ACTIONS and not _role_or_self(arn, action):
        raise RequestError(
            f"{action} is a request on a role, so the resource must be the role's ARN, such as "
            f"arn:aws:iam::111122223333:role/ITAdmin; got {resource!r}"
        )
    if resource == "*":
        return None
    if arn is None:
        raise RequestError(
            f'the resource must be "*" or a full ARN such as arn:aws:s3:::bucket/key, got '
            f"{resource!r}"
        )
    if arn.service == "sts" or (arn.service == "iam" and not _role_action(arn, action)):
        return None
    reason = unsupported(arn)
    if reason is not None:
        raise UnsupportedPolicyFeature(f"{resource}: {reason}")
    governing = resource
    if arn.service == "s3":
        governing = bucket_arn(arn)
        if governing.endswith(":::"):
            raise RequestError(f"the resource {resource!r} names no bucket")
    if "*" in governing or "?" in governing:
        raise RequestError(
            "the request must name one resource, because its resource-based policy depends on "
            f"which one; got {resource!r}"
        )
    return governing


def unsupported(arn: Arn) -> str | None:
    """Why the analyzer can't evaluate requests on `arn` yet, or None when it can."""
    if arn.service == "kms" and arn.resource.startswith("key/"):
        return (
            "KMS isn't supported yet: every KMS key has a key policy that must allow the request, "
            "and the analyzer doesn't evaluate key policies"
        )
    if arn.service == "s3" and (arn.region or arn.account):
        return (
            "S3 resources other than buckets and objects, such as access points, aren't "
            "supported yet"
        )
    return None


def bucket_arn(arn: Arn) -> str:
    """The ARN of the bucket that an S3 bucket or object ARN is in."""
    bucket = arn.resource.split("/", 1)[0]
    return f"arn:{arn.partition}:s3:::{bucket}"


def is_role_arn(text: str) -> bool:
    arn = Arn.parse(text)
    return arn is not None and arn.service == "iam" and arn.resource.startswith("role/")


def account_of(resource: str) -> str | None:
    """The account that `resource`'s ARN names, or None when it names none."""
    arn = Arn.parse(resource)
    return arn.account_id if arn is not None else None


def describe(
    resource: str, action: str, document: Any = None, *, name: str = "resource policy"
) -> Resource | None:
    """Describe the resource a request needs: in the principal's account, with the resource-based
    policy in `document`, or with none when `document` is None. For an S3 bucket, its ACLs are
    disabled. This is what --resource-policy and --no-resource-policy say.

    None when the request needs no description and `document` is None.
    """
    governing = governing_arn(resource, action)
    if governing is None:
        if document is not None:
            raise RequestError(f"no resource-based policy applies to {action} on {resource}")
        return None
    if document is None:
        return Resource(governing)
    check_policy_support(governing, where=name)
    return Resource(governing, parse_policy(document, name=name, kind=policy_kind(governing)))


def load_resource_policy_file(path: str | Path, resource: str, action: str) -> Resource:
    """Describe the resource a request needs with the resource-based policy in a JSON file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyParseError(f"{path}: cannot read file: {exc.strerror}") from exc
    document = _validation.load_json(text, path.name, error=PolicyParseError)
    described = describe(resource, action, document, name=path.name)
    assert described is not None  # describe() refuses a policy for a request that needs none
    return described


def check_policy_support(governing: str, *, where: str) -> None:
    """Refuse a resource-based policy on a resource whose service's rules aren't settled yet."""
    arn = Arn.parse(governing)
    if arn is None or not (arn.service == "s3" or is_role_arn(governing)):
        raise UnsupportedPolicyFeature(
            f"{where}: only S3 bucket policies and role trust policies are evaluated so far, and "
            f"{governing} is neither a bucket nor a role. AWS says resource-based policies for "
            "services other than IAM and AWS KMS \"may also require an explicit Allow statement "
            "within the same account\""
        )


def policy_kind(governing: str) -> PolicyType:
    """The kind of resource-based policy `governing` has: a role's is its trust policy."""
    return PolicyType.TRUST if is_role_arn(governing) else PolicyType.RESOURCE_BASED


def session_tags_possible(trust_policy: Policy) -> bool:
    """Whether a session of a role with `trust_policy` could carry session tags.

    Passing session tags needs sts:TagSession in the trust policy: "For roles without this
    permission in the trust policy, the AssumeRole operation fails". But a chained session
    "inherits any transitive session tags from the calling session", and AWS doesn't say whether
    that needs sts:TagSession too. So session tags are ruled out only when no Allow covers
    sts:TagSession, and every Allow that lets someone assume the role names only IAM users and
    SAML or OIDC providers. Those start a session without a calling session.
    """
    for statement in trust_policy.statements:
        if statement.effect is not Effect.ALLOW:
            continue
        if _covers(statement, "sts:TagSession"):
            return True
        if any(_covers(statement, action) for action in ASSUME_ACTIONS):
            if not all(_starts_a_session(p.type, p.value) for p in statement.principals or ()):
                return True
    return False


def _covers(statement: Statement, action: str) -> bool:
    # NotAction covers every action it doesn't list.
    return any(match_action(p, action) for p in statement.actions) != statement.not_action


def _starts_a_session(kind: PrincipalType, value: str) -> bool:
    """Whether a principal can only assume a role without a calling session: an IAM user, or a
    SAML or OIDC identity provider."""
    return kind is PrincipalType.FEDERATED or (
        kind is PrincipalType.AWS and _USER_ARN.fullmatch(value) is not None
    )


def _role_or_self(arn: Arn | None, action: str) -> bool:
    """Whether `arn` is a role, or for sts:SetContext, the caller's own session (`sts::ID:self`),
    the two resource types the STS actions on roles take."""
    if arn is None:
        return False
    if arn.service == "iam":
        return arn.resource.startswith("role/")
    return action.casefold() == "sts:setcontext" and arn.service == "sts" and arn.resource == "self"


def _role_action(arn: Arn, action: str) -> bool:
    return arn.resource.startswith("role/") and action.casefold() in _ROLE_ACTIONS
