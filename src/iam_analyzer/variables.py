"""Policy variables: placeholders such as ${aws:username} that AWS fills in from the request.

They only exist in policies with "Version": "2012-10-17"; in older policies the text is literal.

    ${key}              the request's value for the condition key `key`
    ${key, 'default'}   the same, or `default` when the request doesn't include the key
    ${*} ${?} ${$}      a literal *, ? or $ (a plain * or ? would be a wildcard)

Variable names are case-insensitive, like all condition keys. A filled-in value is plain text: a *
or ? in a value or default is literal, as AWS's IAM policy simulator showed in Resource and in a
StringLike value (tests/simulator_fixtures/variables_with_wildcards).

A variable has no value when the request doesn't include its key and it has no default. Then the
pattern it is in matches nothing (`resolve` gives None). AWS's "Policy variables with no value"
section says so for both places variables go: in Resource or NotResource, "the resource that
includes a policy variable with no value will not match any resource", and in a condition,
"StringEquals or StringLike do not match" while "Inverted condition operators like StringNotEquals
or StringNotLike do match against a null value". A note on the same page says it "might cause the
entire statement to be invalid", but the simulator matched as the section says
(variables_without_a_value).

A variable whose key has several values matches nothing too, as the simulator showed in Resource,
NotResource and condition values (variables_with_several_values). AWS only says "You can't use a
multivalued condition key as a variable". The analyzer refuses the one case nothing settles: such a
variable with a default. AWS may treat several values as no value, and then use the default.
"""

import re
from dataclasses import dataclass
from functools import lru_cache

from iam_analyzer.context import CONDITION_KEY, RequestContext
from iam_analyzer.errors import PolicyParseError, UnsupportedPolicyFeature
from iam_analyzer.matching import Pieces

# The characters that ${*}, ${?} and ${$} stand for.
SPECIAL = {"${*}": "*", "${?}": "?", "${$}": "$"}
# ${key} or ${key, 'default'}, with the comma, space and single quotes AWS documents.
_VARIABLE = re.compile(r"\$\{([^{}',]+?)(?:, '([^']*)')?\}")


@dataclass(frozen=True)
class Variable:
    key: str  # as written, such as "aws:PrincipalTag/team"
    default: str | None = None


@dataclass(frozen=True)
class Literal:
    """A character that `${*}`, `${?}` or `${$}` stands for. It never acts as a wildcard."""

    text: str


# A parsed pattern: plain text (where * and ? are wildcards), variables and literals.
Template = tuple[str | Variable | Literal, ...]


@lru_cache(maxsize=1024)
def parse(text: str) -> Template:
    """Split `text` into plain text, variables and literal characters.

    Raises PolicyParseError for a malformed variable.
    """
    parts: list[str | Variable | Literal] = []
    position = 0
    while (start := text.find("${", position)) != -1:
        if start > position:
            parts.append(text[position:start])
        special = next((s for s in SPECIAL if text.startswith(s, start)), None)
        if special is not None:
            parts.append(Literal(SPECIAL[special]))
            position = start + len(special)
            continue
        match = _VARIABLE.match(text, start)
        if match is None or not CONDITION_KEY.fullmatch(match.group(1)):
            raise PolicyParseError(
                f"malformed policy variable in {text!r}: use ${{key}} or ${{key, 'default'}} "
                "with a key such as aws:username"
            )
        key, default = match.groups()
        parts.append(Variable(key, default))
        position = match.end()
    if position < len(text):
        parts.append(text[position:])
    return tuple(parts)


def keys(template: Template) -> list[str]:
    """The condition keys that `template`'s variables read."""
    return [part.key for part in template if isinstance(part, Variable)]


def resolve(template: Template, context: RequestContext) -> Pieces | None:
    """Fill in `template`'s variables from `context`, as pieces for the wildcard matcher.

    None when the pattern matches nothing: a variable has no value, or its key has several values.
    Raises MissingContextError when the context says nothing about a variable's key, and
    UnsupportedPolicyFeature for a variable with a default whose key has several values.
    """
    pieces = []
    for part in template:
        if isinstance(part, str):
            pieces.append((part, False))
        elif isinstance(part, Literal):
            pieces.append((part.text, True))
        else:
            value = _value(part, context)
            if value is None:
                return None
            pieces.append((value, True))
    return tuple(pieces)


def _value(variable: Variable, context: RequestContext) -> str | None:
    """The text `variable` stands for, or None when it has none."""
    values = context.get(variable.key)
    if values is None:
        return variable.default
    if len(values) > 1:
        if variable.default is not None:
            raise UnsupportedPolicyFeature(
                f"policy variable ${{{variable.key}, '{variable.default}'}}: the request gives "
                f"{variable.key!r} several values, and AWS doesn't say whether the default is "
                "used then"
            )
        return None
    return values[0]
