"""Wildcard matching for IAM actions and resources.

IAM patterns support two wildcards:
  *  matches any sequence of characters, including none
  ?  matches exactly one character
Every other character is literal. (Python's `fnmatch` is not used because it treats
`[...]` as a character class, which IAM does not.)

Actions are case-insensitive ("S3:getobject" == "s3:GetObject"); resource ARNs are
case-sensitive.
"""

import re
from functools import lru_cache


@lru_cache(maxsize=1024)
def _compile(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    parts = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    flags = re.DOTALL | (re.IGNORECASE if ignore_case else 0)
    return re.compile("".join(parts), flags)


def wildcard_match(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    """Return True if `value` matches the IAM wildcard `pattern` in full."""
    return _compile(pattern, ignore_case).fullmatch(value) is not None


def match_action(pattern: str, action: str) -> bool:
    return wildcard_match(pattern, action, ignore_case=True)


def match_resource(pattern: str, resource: str) -> bool:
    return wildcard_match(pattern, resource, ignore_case=False)
