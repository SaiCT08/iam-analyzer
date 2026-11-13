"""Command-line interface.

    iam-analyzer check --policy FILE [--policy FILE ...] [--boundary FILE]
                       [--resource-policy FILE | --no-resource-policy]
                       --action ACTION --resource ARN [CONTEXT]
    iam-analyzer check --account FILE --principal user/NAME [--org FILE] [--no-session-tags]
                       --action ACTION --resource ARN [CONTEXT]
    iam-analyzer report --account FILE (--org FILE | --no-org) --framework FILE [--json FILE]

CONTEXT describes the request's condition keys:
    --context KEY=VALUE   a key's value (repeat for more keys, or for more values of one key)
    --absent KEY          a key the request doesn't include

A request on a specific resource also needs the resource described. With --account, the
account file's Resources describe it. With --policy, --resource-policy FILE gives its
resource-based policy, such as its bucket's policy, and --no-resource-policy says it has none.
Either flag says the resource is in the same account, and for an S3 bucket, that its ACLs are
disabled.

Exit codes for check: 0 = allowed, 1 = denied, 2 = input error.

`report` prints a framework's checks, graded against the account file, as Markdown, and writes
JSON too with --json. --org gives the SCPs, and --no-org says the account isn't in an
organization: one of them is required, since leaving SCPs out could allow what they deny.
Exit codes for report: 0 = every check passed, 1 = a check failed, 2 = input error,
3 = nothing failed, but some check is DEPENDS or CAN'T TELL.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from iam_analyzer import report, resources
from iam_analyzer.account import load_account_file
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import MissingContextError, MissingResourceError, PolicyError
from iam_analyzer.evaluator import evaluate
from iam_analyzer.framework import load_framework_file
from iam_analyzer.loader import load_policy_file
from iam_analyzer.models import (
    Condition,
    Decision,
    EvaluationResult,
    Layer,
    MatchedStatement,
    OrgTarget,
    PolicyType,
    PrincipalMatch,
    Request,
    TargetType,
)
from iam_analyzer.organization import load_organization_file

EXIT_ALLOWED = 0
EXIT_DENIED = 1
EXIT_INPUT_ERROR = 2
# For report: every check passed, a check failed, or nothing failed but something is unsettled.
EXIT_PASSED = 0
EXIT_FAILED = 1
EXIT_UNSETTLED = 3
MISSING_CONTEXT_HINT = (
    "hint: give each key a value with --context KEY=VALUE, "
    "or use --absent KEY if the request doesn't include it"
)
MISSING_RESOURCE_HINT = {
    "account": "hint: describe it in the account file's Resources, as {} if it has no "
    "resource-based policy",
    "role": "hint: give the role its trust policy as AssumeRolePolicyDocument in the account file",
    "policy": "hint: give its resource-based policy with --resource-policy FILE, or "
    "--no-resource-policy if it has none; either says it is in the same account",
}
# How a resource-based policy's statement named the caller.
NAMES = {
    PrincipalMatch.EVERYONE: "everyone",
    PrincipalMatch.USER: "the user",
    PrincipalMatch.ROLE: "the role",
    PrincipalMatch.ACCOUNT: "the account",
}


class _StoreOnce(argparse.Action):
    """Store an option's value, but make giving the option twice a usage error.

    argparse normally keeps the last value, so `--boundary A --boundary B` would silently
    evaluate only B.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} can only be given once")
        setattr(namespace, self.dest, values)


def _key_value(text: str) -> tuple[str, str]:
    """Split a --context argument at its first "=", so values may contain "=" themselves."""
    key, equals, value = text.partition("=")
    if not equals or not key:
        raise argparse.ArgumentTypeError(f"expected KEY=VALUE, got {text!r}")
    return key, value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-analyzer", description="Evaluate AWS IAM policies locally."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    check = subcommands.add_parser(
        "check", help="Can these policies perform ACTION on RESOURCE?"
    )
    source = check.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--policy",
        action="append",
        metavar="FILE",
        help="identity policy JSON file (repeat for multiple policies)",
    )
    source.add_argument(
        "--account",
        action=_StoreOnce,
        metavar="FILE",
        help="account JSON file with users, groups and roles (use with --principal)",
    )
    check.add_argument(
        "--principal", action=_StoreOnce, help="user/NAME or role/NAME from the --account file"
    )
    check.add_argument(
        "--boundary",
        action=_StoreOnce,
        metavar="FILE",
        help="permissions boundary policy JSON file (with --policy; account files set "
        "PermissionsBoundary on the user or role instead)",
    )
    check.add_argument(
        "--org",
        action=_StoreOnce,
        metavar="FILE",
        help="organization JSON file with SCPs (with --account; the account file needs an "
        "AccountId)",
    )
    check.add_argument(
        "--resource-policy",
        action=_StoreOnce,
        metavar="FILE",
        help="with --policy: the resource-based policy on the request's resource, such as its "
        "bucket's policy. It also says the resource is in the same account, and for an S3 "
        "bucket, that its ACLs are disabled (Object Ownership: Bucket owner enforced)",
    )
    check.add_argument(
        "--no-resource-policy",
        action="store_true",
        help="with --policy: the request's resource is in the same account and has no "
        "resource-based policy; for an S3 bucket, also that its ACLs are disabled (Object "
        "Ownership: Bucket owner enforced). With --account, describe resources in the account "
        "file's Resources instead",
    )
    check.add_argument(
        "--no-session-tags",
        action="store_true",
        help="with --account: a role's session has no session tags, so the role's own tags are "
        "its only aws:PrincipalTag keys. Not needed for a role whose trust policy rules session "
        "tags out",
    )
    check.add_argument("--action", action=_StoreOnce, required=True, help="e.g. s3:GetObject")
    check.add_argument(
        "--resource", action=_StoreOnce, required=True, help="e.g. arn:aws:s3:::bucket/key"
    )
    check.add_argument(
        "--context",
        action="append",
        type=_key_value,
        metavar="KEY=VALUE",
        help="a condition key's value in the request, e.g. aws:SourceIp=203.0.113.5 (repeat for more "
        "keys, or for more values of one key)",
    )
    check.add_argument(
        "--absent",
        action="append",
        metavar="KEY",
        help="a condition key the request doesn't include, e.g. aws:MultiFactorAuthPresent",
    )

    graded = subcommands.add_parser(
        "report", help="Grade a framework's checks against an account file"
    )
    graded.add_argument(
        "--account", action=_StoreOnce, required=True, metavar="FILE",
        help="account JSON file with users, groups, roles and resources",
    )
    scps = graded.add_mutually_exclusive_group(required=True)
    scps.add_argument(
        "--org", action=_StoreOnce, metavar="FILE",
        help="organization JSON file with the SCPs that apply to the account",
    )
    scps.add_argument(
        "--no-org", action="store_true",
        help="the account isn't in an AWS organization, so no SCPs apply",
    )
    graded.add_argument(
        "--framework", action=_StoreOnce, required=True, metavar="FILE",
        help="framework JSON file with the checks to grade",
    )
    graded.add_argument(
        "--json", action=_StoreOnce, metavar="FILE", help="also write the report as JSON to FILE"
    )
    return parser


def format_result(result: EvaluationResult, context: RequestContext = RequestContext()) -> str:
    """The decision, then each statement behind it. For an explicit Deny, also the Allows it
    overrides, and what the request would get without it. `context` is the request's context,
    used to show the values each condition was checked against."""
    lines = [result.decision.value]
    lines += [f"  {_not_allowed_message(layer)}" for layer in result.not_allowed_by]
    lines += _statement_lines(result.reasons, context)
    if result.overridden:
        lines.append("  The Deny overrides:" if len(result.reasons) == 1 else
                     "  The Denies override:")
        lines += _statement_lines(result.overridden, context)
    if result.without_denies is not None:
        lines += _without_denies_lines(result)
    return "\n".join(lines)


def _without_denies_lines(result: EvaluationResult) -> list[str]:
    """What an explicitly denied request would get if no Deny applied."""
    without = result.without_denies
    deny = "this Deny" if len(result.reasons) == 1 else "these Denies"
    if without.decision is None:
        return [f"  Without {deny}, the analyzer can't tell whether the request would be allowed: "
                f"{without.refusal}."]
    if without.decision is Decision.ALLOW:
        return [f"  Without {deny}, the request would be allowed."]
    return [f"  Without {deny}, the request would still be denied:",
            *(f"    {_not_allowed_message(layer)}" for layer in without.not_allowed_by)]


def _statement_lines(statements: Sequence[MatchedStatement], context: RequestContext) -> list[str]:
    lines = []
    for matched in statements:
        sid = matched.statement.sid or "(no Sid)"
        lines.append(f"  {matched.statement.effect.value:<6} {_source(matched)}  Sid={sid}")
        lines += [f"         {_condition(c, context)}" for c in matched.statement.conditions]
    return lines


def _condition(condition: Condition, context: RequestContext) -> str:
    """A condition with the request's value for its key: "Bool aws:SecureTransport: true
    (request: true)"."""
    found = context.get(condition.key)
    request = "not present" if found is None else _values(found)
    return f"{condition.name} {condition.key}: {_values(condition.values)} (request: {request})"


def _values(values: Sequence[str]) -> str:
    return ", ".join(value or '""' for value in values)


def _source(reason: MatchedStatement) -> str:
    """The policy a statement came from, plus how that policy applies to the principal."""
    source = reason.policy_name
    if reason.via_group:
        source += f" (via group {reason.via_group})"
    if reason.layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        source += " (permissions boundary)"
    elif reason.layer.policy_type is PolicyType.SCP:
        source += f" (SCP on {_target(reason.layer.org_target)})"
    elif reason.layer.policy_type is PolicyType.RESOURCE_BASED:
        resource = reason.layer.resource
        on = "" if reason.policy_name == resource else f" on {resource}"
        source += f" (resource-based policy{on}, names {NAMES[reason.principal_match]})"
    elif reason.layer.policy_type is PolicyType.TRUST:
        role = reason.layer.resource
        of = "" if reason.policy_name == role else f" of {role}"
        source += f" (trust policy{of}, names {NAMES[reason.principal_match]})"
    return source


def _not_allowed_message(layer: Layer) -> str:
    if layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        return "The permissions boundary does not allow this."
    if layer.policy_type is PolicyType.SCP:
        return f"No SCP attached to {_target(layer.org_target)} allows this."
    if layer.policy_type is PolicyType.RESOURCE_BASED:
        return f"The resource-based policy on {layer.resource} does not allow this either."
    if layer.policy_type is PolicyType.TRUST:
        return f"The trust policy of {layer.resource} does not allow this."
    return "No identity policy allows this; access is denied by default."


def _target(target: OrgTarget) -> str:
    if target.type is TargetType.ROOT:
        return "the root"
    if target.type is TargetType.ORGANIZATIONAL_UNIT:
        return f"OU {target.name}"
    return f"account {target.name}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "report":
        return _report(args)
    if bool(args.account) != bool(args.principal):
        parser.error("--account and --principal must be used together")
    if args.account and args.boundary:
        parser.error(
            "--boundary only works with --policy; in an account file, "
            "set PermissionsBoundary on the user or role"
        )
    if args.org and not args.account:
        parser.error("--org only works with --account")
    if args.no_session_tags and not args.account:
        parser.error("--no-session-tags only works with --account")
    for flag, given in (("--resource-policy", args.resource_policy),
                        ("--no-resource-policy", args.no_resource_policy)):
        if given and args.account:
            parser.error(
                f"{flag} only works with --policy; in an account file, describe the resource in "
                "Resources"
            )
    if args.resource_policy and args.no_resource_policy:
        parser.error("--resource-policy and --no-resource-policy can't be used together")

    try:
        context = RequestContext.of(args.context or (), args.absent or ())
        if args.account:
            account = load_account_file(args.account)
            organization = load_organization_file(args.org) if args.org else None
            request = account.request(
                args.principal, args.action, args.resource,
                context=context, session_tags=not args.no_session_tags,
            )
            result = account.evaluate(args.principal, request, organization=organization)
        else:
            policies = [load_policy_file(path) for path in args.policy]
            boundary = load_policy_file(args.boundary) if args.boundary else None
            resource = None
            if args.resource_policy:
                resource = resources.load_resource_policy_file(
                    args.resource_policy, args.resource, args.action
                )
            elif args.no_resource_policy:
                resource = resources.describe(args.resource, args.action)
            request = Request(action=args.action, resource=args.resource, context=context)
            result = evaluate(request, policies, boundary=boundary, resource=resource)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if isinstance(exc, MissingContextError):
            print(MISSING_CONTEXT_HINT, file=sys.stderr)
        elif isinstance(exc, MissingResourceError):
            mode = "policy"
            if args.account:
                mode = "role" if resources.is_role_arn(exc.resource) else "account"
            print(MISSING_RESOURCE_HINT[mode], file=sys.stderr)
        return EXIT_INPUT_ERROR

    print(format_result(result, request.context))
    return EXIT_ALLOWED if result.allowed else EXIT_DENIED


def _report(args: argparse.Namespace) -> int:
    try:
        account = load_account_file(args.account)
        organization = load_organization_file(args.org) if args.org else None
        framework = load_framework_file(args.framework)
        graded = report.build(framework, account, organization=organization)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    if args.json:
        data = json.dumps(report.to_json(graded), indent=2) + "\n"
        try:
            Path(args.json).write_text(data, encoding="utf-8")
        except OSError as exc:
            print(f"error: {args.json}: cannot write file: {exc.strerror}", file=sys.stderr)
            return EXIT_INPUT_ERROR
    print(report.to_markdown(graded), end="")
    if graded.failed:
        return EXIT_FAILED
    return EXIT_UNSETTLED if graded.unsettled else EXIT_PASSED



if __name__ == "__main__":
    sys.exit(main())
