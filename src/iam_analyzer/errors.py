"""Exceptions raised while loading or evaluating policies."""


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
