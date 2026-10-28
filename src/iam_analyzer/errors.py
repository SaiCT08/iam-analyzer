"""Exceptions raised while loading or evaluating policies."""

from collections.abc import Iterable


class PolicyError(Exception):
    """Base class for all policy-related errors."""


class PolicyParseError(PolicyError):
    """The policy is not valid JSON or does not have the shape of an IAM policy."""


class UnsupportedPolicyFeature(PolicyError):
    """The policy uses an element this version of the analyzer cannot evaluate yet.

    The analyzer refuses rather than ignores: silently skipping, say, a conditional Deny would
    make it report access as allowed when AWS might deny it.
    """


class AccountError(PolicyError):
    """The account file is malformed, or a principal, group or policy it names does not exist."""


class OrganizationError(PolicyError):
    """The organization file is malformed, or an account or SCP it names does not exist."""


class FrameworkError(PolicyError):
    """The framework file is malformed, or a check asks something the account file can't answer,
    such as a principal it doesn't define."""


class RequestError(PolicyError):
    """The request is not one AWS could receive, such as an action with a wildcard in it."""


class MissingContextError(RequestError):
    """A statement that matches the request uses a condition key the request says nothing about.

    Treating the key as missing could switch a Deny off, so the analyzer refuses instead.
    `keys` lists the keys, spelled as the policies spell them.
    """

    def __init__(self, message: str, keys: Iterable[str]) -> None:
        super().__init__(message)
        self.keys = tuple(keys)


class MissingResourceError(RequestError):
    """The request is on a resource that can have a resource-based policy, and nothing describes it.

    Treating it as having none, in the principal's own account, could leave out a bucket policy's
    Deny or Allow, so the analyzer refuses instead. `resource` is the ARN that needs describing:
    for an S3 object, its bucket.
    """

    def __init__(self, message: str, resource: str) -> None:
        super().__init__(message)
        self.resource = resource
