"""Wildcard matching for IAM actions and resources.

IAM patterns support two wildcards:
  *  matches any sequence of characters, including none
  ?  matches exactly one character
Every other character is literal. (Python's `fnmatch` is not used because it treats
`[...]` as a character class, which IAM does not.)

Actions are case-insensitive ("S3:getobject" == "s3:GetObject"); resource ARNs are
case-sensitive.

Resource ARNs follow two more rules:
  - Wildcards match colons too, anywhere in the ARN. So "function:*-prod" covers the Lambda
    alias "function:billing:canary-prod", and "us-*3" in the region field runs on into the
    account ID. AWS's Resource page only implies that wildcards stay inside one colon-separated
    segment, and AWS's IAM policy simulator matched across colons with both wildcards, in every
    field (tests/simulator_fixtures/wildcards_and_colons).
  - An ARN with fewer than the standard six fields is completed with `*` fields:
    "arn:aws:s3" means "arn:aws:s3:*:*:*".
The ARN condition operators, such as ArnLike, compare an ARN's six fields one by one instead
(see `conditions`).

Once policy variables are filled in, a pattern can also be *pieces*: (text, literal) pairs. In
a literal piece, such as the `*` that `${*}` stands for, `*` and `?` are ordinary characters.
"""

import re
from functools import lru_cache

Pieces = tuple[tuple[str, bool], ...]
Pattern = str | Pieces


@lru_cache(maxsize=1024)
def _compile(pieces: Pieces, ignore_case: bool) -> re.Pattern[str]:
    parts = []
    for text, literal in pieces:
        for char in text:
            if literal or char not in "*?":
                parts.append(re.escape(char))
            else:
                parts.append(".*" if char == "*" else ".")
    flags = re.DOTALL | (re.IGNORECASE if ignore_case else 0)
    return re.compile("".join(parts), flags)


def wildcard_match(pattern: Pattern, value: str, *, ignore_case: bool = False) -> bool:
    """Return True if `value` matches the IAM wildcard `pattern` in full."""
    return _compile(_pieces(pattern), ignore_case).fullmatch(value) is not None


def match_action(pattern: str, action: str) -> bool:
    return wildcard_match(pattern, action, ignore_case=True)


def match_resource(pattern: Pattern, resource: str) -> bool:
    return wildcard_match(_complete_arn(_pieces(pattern)), resource)


def _pieces(pattern: Pattern) -> Pieces:
    return ((pattern, False),) if isinstance(pattern, str) else pattern


def _complete_arn(pieces: Pieces) -> Pieces:
    """Give an ARN with fewer than six fields `*` fields: "arn:aws:s3" -> "arn:aws:s3:*:*:*".

    A full ARN has five colons, so this adds nothing to one.
    """
    text = "".join(text for text, _ in pieces)
    missing = 5 - text.count(":")
    if not text.startswith("arn:") or missing <= 0:
        return pieces
    return (*pieces, (":*" * missing, False))
