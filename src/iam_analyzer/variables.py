"""Policy variables: placeholders such as ${aws:username} that AWS fills in from the request.

They only exist in policies with "Version": "2012-10-17"; in older policies the text is literal.

    ${key}              the request's value for the condition key `key`
    ${key, 'default'}   the same, or `default` when the request doesn't include the key
    ${*} ${?} ${$}      a literal *, ? or $ (a plain * or ? would be a wildcard)

Variable names are case-insensitive, like all condition keys. A filled-in value is plain text.

The analyzer refuses three cases AWS's documentation doesn't settle:
  - a variable with no value and no default. One note says the statement "might" become
    invalid, while the section on variables with no value says the value matches nothing;
  - a key with several values (AWS says multivalued keys can't be variables);
  - a value or default containing * or ?, which AWS doesn't say whether it treats as a wildcard.
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

    Raises PolicyParseError for a malformed variable, and UnsupportedPolicyFeature for a
    default containing * or ?.
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
        if default is not None and ("*" in default or "?" in default):
            raise UnsupportedPolicyFeature(
                f"the default in {match.group()!r} contains * or ?, and AWS doesn't say whether "
                "it would act as a wildcard"
            )
        parts.append(Variable(key, default))
        position = match.end()
    if position < len(text):
        parts.append(text[position:])
    return tuple(parts)


def keys(template: Template) -> list[str]:
    """The condition keys that `template`'s variables read."""
    return [part.key for part in template if isinstance(part, Variable)]


def resolve(template: Template, context: RequestContext) -> Pieces:
    """Fill in `template`'s variables from `context`, as pieces for the wildcard matcher.

    Raises MissingContextError when the context says nothing about a variable's key, and
    UnsupportedPolicyFeature for the cases described at the top of this module.
    """
    pieces = []
    for part in template:
        if isinstance(part, str):
            pieces.append((part, False))
        elif isinstance(part, Literal):
            pieces.append((part.text, True))
        else:
            pieces.append((_value(part, context), True))
    return tuple(pieces)


def _value(variable: Variable, context: RequestContext) -> str:
    name = f"${{{variable.key}}}"
    values = context.get(variable.key)
    if values is None:
        if variable.default is None:
            raise UnsupportedPolicyFeature(
                f"policy variable {name!r} has no value in this request, and AWS's documentation "
                "disagrees on what happens then"
            )
        return variable.default
    if len(values) > 1:
        raise UnsupportedPolicyFeature(
            f"policy variable {name!r}: the request gives {variable.key!r} several values, but a "
            "multivalued key can't be a policy variable"
        )
    [value] = values
    if "*" in value or "?" in value:
        raise UnsupportedPolicyFeature(
            f"policy variable {name!r}: the value {value!r} contains * or ?, and AWS doesn't say "
            "whether it would act as a wildcard"
        )
    return value
