"""Wildcard matching for IAM actions and resources.

IAM patterns support two wildcards:
  *  matches any sequence of characters, including none
  ?  matches exactly one character
Every other character is literal. (Python's `fnmatch` is not used because it treats
`[...]` as a character class, which IAM does not.)

Actions are case-insensitive ("S3:getobject" == "s3:GetObject"); resource ARNs are
case-sensitive.

Resource ARNs follow two more rules from AWS's documentation:
  - Wildcards stay inside one colon-separated segment of the ARN. The exception is a `*`
    that ends a segment, which can run on past colons. So "function:*" covers the Lambda
    alias "function:billing:canary", but "function:*-prod" does not cover
    "function:billing:canary-prod", and `?` never matches a colon.
  - An ARN with fewer than the standard six fields is completed with `*` fields:
    "arn:aws:s3" means "arn:aws:s3:*:*:*".

Once policy variables are filled in, a pattern can also be *pieces*: (text, literal) pairs. In
a literal piece, such as the `*` that `${*}` stands for, `*` and `?` are ordinary characters.
"""

import re
from functools import lru_cache

Pieces = tuple[tuple[str, bool], ...]
Pattern = str | Pieces


@lru_cache(maxsize=1024)
def _compile(pieces: Pieces, ignore_case: bool, segmented: bool) -> re.Pattern[str]:
    chars = [(char, literal) for text, literal in pieces for char in text]
    parts = []
    for index, (char, literal) in enumerate(chars):
        if literal or char not in "*?":
            parts.append(re.escape(char))
        elif char == "*":
            # The pattern ends here, or a colon comes next.
            following = chars[index + 1][0] if index + 1 < len(chars) else ""
            parts.append(".*" if following in ("", ":") or not segmented else "[^:]*")
        else:
            parts.append("[^:]" if segmented else ".")
    flags = re.DOTALL | (re.IGNORECASE if ignore_case else 0)
    return re.compile("".join(parts), flags)


def wildcard_match(
    pattern: Pattern, value: str, *, ignore_case: bool = False, segmented: bool = False
) -> bool:
    """Return True if `value` matches the IAM wildcard `pattern` in full.

    With `segmented`, wildcards stay inside one colon-separated segment, except a `*` that
    ends a segment.
    """
    return _compile(_pieces(pattern), ignore_case, segmented).fullmatch(value) is not None


def match_action(pattern: str, action: str) -> bool:
    return wildcard_match(pattern, action, ignore_case=True)


def match_resource(pattern: Pattern, resource: str) -> bool:
    return wildcard_match(_complete_arn(_pieces(pattern)), resource, segmented=True)


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
