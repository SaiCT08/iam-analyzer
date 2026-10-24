"""The request context: the condition keys a request carries, such as aws:SourceIp.

AWS builds the request context from the caller, the network and the request itself. Here it
comes from the account file, which knows about the principal (see
`Account.principal_context`), and from whoever asks the question, for everything else.

Each key is in one of three states:
  - it has values. Most keys have one; a key such as aws:TagKeys can have several.
  - it is absent: the request really doesn't include it, as aws:username for a role.
  - it is unknown: nobody said.
AWS's rules for missing keys apply to absent keys. A statement that needs an unknown key is
refused instead (`MissingContextError`), because treating the key as missing could switch a
Deny off.

Key names are case-insensitive, as in AWS: aws:SourceIp and AWS:sourceip are the same key.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from iam_analyzer.errors import MissingContextError, RequestError

# A condition key starts with a service prefix: "aws:SourceIp", "s3:prefix",
# "aws:PrincipalTag/team".
CONDITION_KEY = re.compile(r"[A-Za-z0-9-]+:.+")


@dataclass(frozen=True)
class RequestContext:
    """The condition keys of one request. Build one with `RequestContext.of`.

    Keys are stored in lowercase, because AWS ignores their case. `spellings` keeps each key as
    it was first written, for messages.
    """

    values: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    absent: frozenset[str] = frozenset()
    # Key prefixes such as "aws:principaltag/": every key under one that has no values is absent.
    absent_prefixes: frozenset[str] = frozenset()
    # Keys that are certainly in the request although their values aren't known, each with the
    # reason. They can't be marked absent.
    present: Mapping[str, str] = field(default_factory=dict)
    spellings: Mapping[str, str] = field(default_factory=dict)
    # Where these keys come from, for messages: "the request", "district.json user/jsmith".
    source: str = "the request"

    @classmethod
    def of(
        cls,
        values: Iterable[tuple[str, str]] = (),
        absent: Iterable[str] = (),
        *,
        absent_prefixes: Iterable[str] = (),
        present: Mapping[str, str] | None = None,
        source: str = "the request",
    ) -> "RequestContext":
        """Build a context from (key, value) pairs and a list of absent keys.

        Giving a key twice gives it two values, which is how a multivalued key such as
        aws:TagKeys gets more than one.
        """
        collected: dict[str, list[str]] = {}
        spellings: dict[str, str] = {}
        for key, value in values:
            _check_key(key)
            if not isinstance(value, str):
                raise RequestError(f"condition key {key!r}: values must be strings, got {value!r}")
            collected.setdefault(key.casefold(), []).append(value)
            spellings.setdefault(key.casefold(), key)
        absent_keys = set()
        for key in absent:
            _check_key(key)
            if key.casefold() in collected:
                raise RequestError(f"condition key {key!r} can't both have a value and be absent")
            absent_keys.add(key.casefold())
            spellings.setdefault(key.casefold(), key)
        present = present or {}
        for key in present:
            _check_key(key)
            spellings.setdefault(key.casefold(), key)
        return cls(
            values={key: tuple(found) for key, found in collected.items()},
            absent=frozenset(absent_keys),
            absent_prefixes=frozenset(prefix.casefold() for prefix in absent_prefixes),
            present={key.casefold(): reason for key, reason in present.items()},
            spellings=spellings,
            source=source,
        )

    def get(self, key: str) -> tuple[str, ...] | None:
        """The request's values for `key`, or None when the request doesn't include it.

        Raises MissingContextError when the context says nothing about `key`.
        """
        folded = key.casefold()
        if folded in self.values:
            return self.values[folded]
        if self._is_absent(folded):
            return None
        raise MissingContextError(f"the request context says nothing about {key!r}", [key])

    def knows(self, key: str) -> bool:
        """Whether the context gives `key` values or says it is absent."""
        folded = key.casefold()
        return folded in self.values or self._is_absent(folded)

    def merged(self, other: "RequestContext") -> "RequestContext":
        """This context plus `other`, which must be about different keys.

        The CLI uses it to add the caller's keys to the principal's keys from the account file.
        A key that both know about is refused, so the caller can't change what the account file
        decides, and neither can a key marked present be made absent.
        """
        for key in [*other.values, *other.absent]:
            name = other.spellings.get(key, key)
            if self.knows(key):
                raise RequestError(
                    f"condition key {name!r} comes from {self.source}, so it can't also be given"
                )
            if key in other.absent and key in self.present:
                raise RequestError(f"condition key {name!r} can't be absent: {self.present[key]}")
        return RequestContext(
            values={**self.values, **other.values},
            absent=self.absent | other.absent,
            absent_prefixes=self.absent_prefixes | other.absent_prefixes,
            present={**self.present, **other.present},
            spellings={**other.spellings, **self.spellings},
            source=self.source,
        )

    def _is_absent(self, folded: str) -> bool:
        return folded in self.absent or folded.startswith(tuple(self.absent_prefixes))


def _check_key(key: str) -> None:
    if not (isinstance(key, str) and CONDITION_KEY.fullmatch(key)):
        raise RequestError(
            f"{key!r} is not a condition key: it needs a service prefix, such as 'aws:SourceIp'"
        )
