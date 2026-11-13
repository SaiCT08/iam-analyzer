"""Condition keys whose every value AWS documents, so a report can try each one.

A compliance check states only what its question fixes. When a statement needs a key that the
check doesn't give, the report can still answer if AWS's global condition keys page lists every
value the key can have: it asks the engine once with each of them. Any other key can have too
many values to try, so the report can't tell until the check gives it one.

Each entry quotes the "Availability" line that says whether a request can leave the key out.

aws:MultiFactorAuthPresent can be absent for every principal. AWS says it is missing for
long-term access keys and for federated identities. Every principal is still tried with true, false
and absent, roles included: when it's unsure whether a value can happen, the analyzer tries it.
If AWS's page below is right, true for a role can only add a false alarm. If it's wrong, skipping
true could let a check that forbids access PASS when it should FAIL. docs/design-decisions.md
records this judgment call with AWS's quotes.

AWS also checks MFA for a role when the role is assumed, not on the role's own requests: its
"Secure API access with MFA" page says "The temporary credentials returned by AssumeRole do not
include MFA information in the context, so you cannot check individual API operations for MFA".
The MFA entry keeps that quote (`role_quote`), and a report reads it: a role allowed to do
something without MFA is protected only if no one can assume the role without MFA (`compliance`).
"""

from dataclasses import dataclass

GLOBAL_KEYS_PAGE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"
)
MFA_PAGE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html"
)


@dataclass(frozen=True)
class KeyValues:
    """Every value a key can have in a request. None means the request doesn't include it.

    `role_quote` and `role_link` are for a key AWS checks when a role is assumed, not on the
    role's own requests: AWS's words saying so, and where they are. `role_term` is what the key
    checks, in a word a report can use: "MFA". All three are None for other keys.
    """

    key: str  # spelled as AWS documents it
    values: tuple[str | None, ...]
    quote: str  # AWS's "Availability" line
    link: str
    role_quote: str | None = None
    role_link: str | None = None
    role_term: str | None = None

    @property
    def checked_when_assumed(self) -> bool:
        """Whether AWS checks this key for a role when it's assumed, not on its requests."""
        return self.role_quote is not None


KNOWN = (
    KeyValues(
        "aws:MultiFactorAuthPresent",
        ("true", "false", None),
        "This key is included in the request context only when the principal uses temporary "
        "credentials to make the request.",
        f"{GLOBAL_KEYS_PAGE}#condition-keys-multifactorauthpresent",
        role_quote="The temporary credentials returned by AssumeRole do not include MFA "
        "information in the context, so you cannot check individual API operations for MFA.",
        role_link=f"{MFA_PAGE}#scenarios",
        role_term="MFA",
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
