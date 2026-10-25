"""Check the analyzer against AWS's IAM policy simulator (iam:SimulateCustomPolicy).

This is a dev tool, kept outside src/ so that the iam_analyzer package still has no dependencies.
Only `record` needs boto3, and running it calls AWS:

    pip install -e ".[dev,simulator]"
    python -m simulator_check.record --dry-run      # the requests and the analyzer's answers, without AWS
    python -m simulator_check.record --only GROUP   # record fixtures through the iam-simulator profile
    python -m simulator_check.report                # the results tables for docs/simulator-check.md

`record` saves each request and AWS's raw response under tests/simulator_fixtures, and
tests/test_simulator_fixtures.py replays them against the analyzer without AWS. See
docs/simulator-check.md.

The repository is public. Every account ID in a case must be one of AWS's example IDs, and
`safety_problems` checks each request before it is sent and each fixture before it is saved.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from iam_analyzer.account import SERVICE_LINKED_PATH

REPO = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO / "tests" / "simulator_fixtures"

# AWS's example account IDs, the only ones the cases may use.
EXAMPLE_ACCOUNTS = frozenset({"111122223333", "444455556666", "999988887777", "123456789012"})

# AWS request IDs are UUIDs, whose last group of 12 hex digits can happen to be all digits.
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_TWELVE_DIGITS = re.compile(r"(?<!\d)\d{12}(?!\d)")
_ACCESS_KEY_ID = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
# The callers the simulator accepts: "the ARN of the IAM user, group, or role".
_CALLER = re.compile(r"arn:aws:iam::([0-9]{12}):(user|role)(/(?:.*/)?)([^/]+)")


def safety_problems(text: str) -> list[str]:
    """Why `text` can't go into the public repository: an account ID that isn't one of AWS's
    examples, or an access key ID. Empty when it can.

    UUID-shaped request IDs are ignored. The problems never repeat what was found, so printing
    them can't leak it.
    """
    text = _UUID.sub(" ", text)
    problems = []
    others = {found for found in _TWELVE_DIGITS.findall(text) if found not in EXAMPLE_ACCOUNTS}
    if others:
        problems.append(f"{len(others)} account ID(s) that aren't AWS's examples")
    if _ACCESS_KEY_ID.search(text):
        problems.append("an access key ID")
    return problems


@dataclass(frozen=True)
class Caller:
    """The simulated caller: an IAM user or role, as SimulateCustomPolicy's CallerArn."""

    arn: str
    account: str
    kind: str  # "user" or "role"
    path: str  # such as "/" or "/aws-service-role/support.amazonaws.com/"
    name: str

    @classmethod
    def parse(cls, arn: str) -> "Caller | None":
        """The caller `arn` names, or None when it isn't a user or role ARN."""
        match = _CALLER.fullmatch(arn)
        if match is None:
            return None
        account, kind, path, name = match.groups()
        return cls(arn, account, kind, path, name)

    @property
    def service_linked(self) -> bool:
        """A service-linked role, which SCPs never restrict. As in an account file, its path
        decides it, not its name."""
        return self.kind == "role" and self.path.startswith(SERVICE_LINKED_PATH)
