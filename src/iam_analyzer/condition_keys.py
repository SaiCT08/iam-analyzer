"""Condition keys whose every value AWS documents, so a report can try each one.

A compliance check states only what its question fixes. When a statement needs a key that the
check doesn't give, the report can still answer if AWS's global condition keys page lists every
value the key can have: it asks the engine once with each of them. Any other key can have too
many values to try, so the report can't tell until the check gives it one.

Each entry quotes the "Availability" line that says whether a request can leave the key out.

aws:MultiFactorAuthPresent can be absent for every principal. AWS says it is missing for
long-term access keys and for federated identities. Its "Secure API access with MFA" page also says
"The temporary credentials returned by AssumeRole do not include MFA information in the context",
so a role's own requests never show MFA. Every principal is still tried with true, false and
absent, roles included. For a role, true is a value AWS says its requests don't have, and trying it
can only make a report find more access, never less. Whether to stop trying it for roles is an
open question.
"""

from dataclasses import dataclass

GLOBAL_KEYS_PAGE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"
)


@dataclass(frozen=True)
class KeyValues:
    """Every value a key can have in a request. None means the request doesn't include it."""

    key: str  # spelled as AWS documents it
    values: tuple[str | None, ...]
    quote: str  # AWS's "Availability" line
    link: str


KNOWN = (
    KeyValues(
        "aws:MultiFactorAuthPresent",
        ("true", "false", None),
        "This key is included in the request context only when the principal uses temporary "
        "credentials to make the request.",
        f"{GLOBAL_KEYS_PAGE}#condition-keys-multifactorauthpresent",
    ),
    KeyValues(
        "aws:SecureTransport",
        ("true", "false"),
        "This key is always included in the request context.",
        f"{GLOBAL_KEYS_PAGE}#condition-keys-securetransport",
    ),
    KeyValues(
        "aws:ViaAWSService",
        ("true", "false"),
        "This key is always included in the request context.",
        f"{GLOBAL_KEYS_PAGE}#condition-keys-viaawsservice",
    ),
)

_BY_KEY = {known.key.casefold(): known for known in KNOWN}


def values_of(key: str) -> KeyValues | None:
    """Every value `key` can have, or None when AWS doesn't list them all. Keys ignore case."""
    return _BY_KEY.get(key.casefold())
