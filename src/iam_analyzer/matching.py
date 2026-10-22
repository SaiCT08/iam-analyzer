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
"""

import re
from functools import lru_cache


@lru_cache(maxsize=1024)
def _compile(pattern: str, ignore_case: bool, segmented: bool) -> re.Pattern[str]:
    parts = []
    for index, char in enumerate(pattern):
        if char == "*":
            # The pattern ends here, or a colon comes next.
            ends_segment = pattern[index + 1 : index + 2] in ("", ":")
            parts.append(".*" if ends_segment or not segmented else "[^:]*")
        elif char == "?":
            parts.append("[^:]" if segmented else ".")
        else:
            parts.append(re.escape(char))
    flags = re.DOTALL | (re.IGNORECASE if ignore_case else 0)
    return re.compile("".join(parts), flags)


def wildcard_match(
    pattern: str, value: str, *, ignore_case: bool = False, segmented: bool = False
) -> bool:
    """Return True if `value` matches the IAM wildcard `pattern` in full.

    With `segmented`, wildcards stay inside one colon-separated segment, except a `*` that
    ends a segment.
    """
    return _compile(pattern, ignore_case, segmented).fullmatch(value) is not None


def match_action(pattern: str, action: str) -> bool:
    return wildcard_match(pattern, action, ignore_case=True)


def match_resource(pattern: str, resource: str) -> bool:
    return wildcard_match(_complete_arn(pattern), resource, segmented=True)


def _complete_arn(pattern: str) -> str:
    """Give an ARN with fewer than six fields `*` fields: "arn:aws:s3" -> "arn:aws:s3:*:*:*".

    A full ARN has five colons, so this adds nothing to one.
    """
    if not pattern.startswith("arn:"):
        return pattern
    return pattern + ":*" * (5 - pattern.count(":"))
