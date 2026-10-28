"""A compliance report: a framework's checks, run against an account file, as Markdown or JSON.

Results, statements and refusals stay typed until here, where they become text. The Markdown is
plain enough to read on screen: headings, short bullets wrapped at 100 columns, and one small
table. Checks that need attention come first. The JSON keeps every typed field, such as
`via_group` and each statement's layer, so other tools can group results without parsing text.
"""

import textwrap
from collections.abc import Sequence
from dataclasses import dataclass

from iam_analyzer import compliance, condition_keys, findings, resources
from iam_analyzer.account import Account
from iam_analyzer.compliance import (
    Answer,
    CheckResult,
    Item,
    Outside,
    Refusal,
    Result,
    RoleMfaNote,
)
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import MissingContextError, MissingResourceError
from iam_analyzer.findings import Finding, Use
from iam_analyzer.framework import Check, CheckType, Framework, Severity
from iam_analyzer.models import (
    Condition,
    Decision,
    Layer,
    MatchedStatement,
    OrgTarget,
    PolicyType,
    Principal,
    PrincipalMatch,
    PrincipalType,
    Statement,
    TargetType,
)
from iam_analyzer.organization import Organization

SCHEMA = 1
WIDTH = 100
LABELS = {
    Result.FAIL: "FAIL",
    Result.DEPENDS: "DEPENDS",
    Result.CANT_TELL: "CAN'T TELL",
    Result.PASS: "PASS",
}
# Statements in these layers grant access. Boundaries and SCPs only limit it.
GRANTING = (PolicyType.IDENTITY, PolicyType.RESOURCE_BASED, PolicyType.TRUST)
NAMES = {
    PrincipalMatch.EVERYONE: "everyone",
    PrincipalMatch.USER: "the user",
    PrincipalMatch.ROLE: "the role",
    PrincipalMatch.ACCOUNT: "the account",
}


# Findings this severe count as failures, as a FAIL does.
FAILING = (Severity.CRITICAL, Severity.HIGH)


@dataclass(frozen=True)
class Report:
    framework: Framework
    account: Account
    organization: Organization | None  # None: the account isn't in one, so no SCPs apply
    checks: tuple[CheckResult, ...]
    findings: tuple[Finding, ...] = ()

    @property
    def failed(self) -> bool:
        """Whether a check failed, or a finding is high or critical."""
        return any(check.result is Result.FAIL for check in self.checks) or any(
            finding.severity in FAILING for finding in self.findings
        )

    @property
    def unsettled(self) -> bool:
        """Whether some check is DEPENDS or CAN'T TELL."""
        return any(check.result in (Result.DEPENDS, Result.CANT_TELL) for check in self.checks)


def build(framework: Framework, account: Account, *, organization: Organization | None) -> Report:
    checks = compliance.run(framework, account, organization=organization)
    found = findings.scan(account, organization=organization)
    return Report(framework, account, organization, checks, found)


# --- Markdown --------------------------------------------------------------------------


def to_markdown(report: Report) -> str:
    """The report as Markdown, for reading on screen."""
    account = report.account
    org = report.organization
    lines = [
        f"# Compliance report: {report.framework.title}",
        "",
        _bullet(f"Framework: {report.framework.name} ({report.framework.id}), "
                f"{_count(len(report.checks), 'check')}."),
        _bullet(f"Account: {account.name}"
                + (f" ({account.account_id})" if account.account_id else "")
                + f", {_count(len(account.users), 'user')} and "
                f"{_count(len(account.roles), 'role')}."),
        _bullet(f"Organization: {org.name}, whose SCPs are applied." if org else
                "Organization: none (--no-org), so no SCPs apply."),
        "",
        "| Result | Checks |",
        "|---|---|",
    ]
    lines += [f"| {LABELS[result]} | {sum(c.result is result for c in report.checks)} |"
              for result in Result]
    lines += ["", f"Findings: {_severities(report.findings)}."]
    order = sorted(range(len(report.checks)), key=lambda i: (
        report.checks[i].result.rank, report.checks[i].check.severity.rank, i))
    for index in order:
        lines += ["", *_check_markdown(report.checks[index], account)]
    lines += ["", "## Findings", ""]
    if not report.findings:
        lines.append("No findings.")
    for finding in report.findings:
        lines += [*_finding_markdown(finding), ""]
    if report.findings:
        lines.pop()
    lines += ["", "## Scope and limits", "", *_scope(report)]
    return "\n".join(lines) + "\n"


def _severities(found: Sequence[Finding]) -> str:
    """How many findings there are of each severity: "1 high, 1 low", or "none"."""
    counts = [(severity, sum(f.severity is severity for f in found)) for severity in Severity]
    return ", ".join(f"{count} {severity.value}" for severity, count in counts if count) or "none"


def _finding_markdown(finding: Finding) -> list[str]:
    found = finding.type
    lines = [f"### {finding.severity.value.upper()}: {found.title}", "",
             _bullet(f"In: {_where(finding)}.")]
    if finding.condition is not None:
        lines.append(_bullet(f"Condition: {_condition(finding.condition)}."))
    lines += [_bullet(f"Why: {found.why}"), _bullet(f"Evidence: {_evidence(found)}"),
              _bullet(f"Fix: {found.fix}")]
    return lines


def _where(finding: Finding) -> str:
    """The statement, and where its policy is used: "SummerSchoolRecords, Sid Read: an identity
    policy attached to group/SummerSchool"."""
    statement = _sid(finding.statement, finding.index)
    if finding.kind is PolicyType.RESOURCE_BASED:
        return f"the resource policy on {finding.uses[0].resource}, {statement}"
    if finding.kind is PolicyType.TRUST:
        return f"the trust policy of {finding.uses[0].resource}, {statement}"
    if finding.kind is PolicyType.SCP:
        targets = " and ".join(_target(use.org_target) for use in finding.uses)
        return f"{finding.policy.name}, {statement}: an SCP on {targets or 'nothing'}"
    return f"{finding.policy.name}, {statement}: an identity policy {_attached(finding.uses)}"


def _attached(uses: Sequence[Use]) -> str:
    attached = [use.principal for use in uses if use.policy_type is PolicyType.IDENTITY]
    bounds = [use.principal for use in uses if use.policy_type is PolicyType.PERMISSIONS_BOUNDARY]
    parts = [f"attached to {', '.join(attached)}"] if attached else []
    if bounds:
        parts.append(f"the permissions boundary of {', '.join(bounds)}")
    return "; and ".join(parts) or "that isn't attached to anyone"


def _condition(condition: Condition) -> str:
    return f"{condition.name} {condition.key}: {', '.join(condition.values)}"


def _evidence(found: findings.FindingType) -> str:
    parts = []
    answers: dict[str, list[str]] = {}
    for fixture in found.fixtures:
        answers.setdefault(fixture.aws, []).append(fixture.case)
    if answers:
        said = "; ".join(f"{aws} in {', '.join(cases)}" for aws, cases in answers.items())
        parts.append(f"AWS's IAM policy simulator answered {said} ({findings.SIMULATOR_FIXTURES}).")
    parts += [f'AWS: "{doc.quote}" {doc.link}' for doc in found.docs]
    return " ".join(parts)


def _check_markdown(result: CheckResult, account: Account) -> list[str]:
    check = result.check
    lines = [f"## {LABELS[result.result]}: {check.title} ({check.severity.value})", "",
             _wrap(f"Asked: {_question(check)}"), ""]
    lines += _items_markdown(result, account)
    lines += ["", _wrap(f"Fix: {check.fix}")]
    if check.maps_to:
        lines += ["", "Maps to:"]
        lines += [_bullet(f"{r.framework} {r.id}: {r.title}. {r.link}") for r in check.maps_to]
    return lines


def _question(check: Check) -> str:
    actions = " or ".join(check.actions)
    resources = " or ".join(check.resources)
    if check.type is CheckType.CAN:
        who = f"Can {', '.join(check.principals)}"
    else:
        named = check.exempt if check.type is CheckType.REQUIRES else check.principals
        who = f"Can anyone but {', '.join(named)}" if named else "Can anyone"
    question = f"{who} do {actions} on {resources}"
    if check.type is CheckType.REQUIRES:
        known = condition_keys.values_of(check.key)
        others = [_value(v) for v in known.values if v != check.value]
        question += f" when {known.key} is {' or '.join(others)}"
    question += "?"
    given = _given(check.context)
    return f"{question} The check gives {given}." if given else question


def _given(context: RequestContext) -> str:
    parts = [f"{context.spellings[key]} {', '.join(values)}" for key, values in
             context.values.items()]
    parts += [f"{context.spellings[key]} absent" for key in sorted(context.absent)]
    return "; ".join(parts)


def _items_markdown(result: CheckResult, account: Account) -> list[str]:
    check = result.check
    # A principal whose every item passed is listed once, by name.
    unpassed = {item.principal for item in result.items if item.result is not Result.PASS}
    lines: list[str] = []
    passed: list[str] = []
    refused: dict[str, list[str]] = {}  # message: the items that got only that refusal
    for item in result.items:
        if item.principal not in unpassed:
            if item.principal not in passed:
                passed.append(item.principal)
            continue
        label = _label(item, check)
        reasons = {_refusal(answer.refusal) for answer in item.answers if answer.refusal}
        if item.result is Result.PASS:
            passed.append(label)
        elif item.result is Result.CANT_TELL and len(reasons) == 1 and all(
                answer.refusal for answer in item.answers):
            refused.setdefault(reasons.pop(), []).append(label)
        else:
            lines += _item_markdown(item, label)
    for message, labels in refused.items():
        who = "everyone asked" if len(labels) == len(result.items) else ", ".join(labels)
        lines.append(_bullet(f"Can't tell for {who}: {message}"))
    lines += [_bullet(_outside_markdown(outside, account)) for outside in result.outside]
    if passed:
        lines.append(_bullet(("Can: " if check.type is CheckType.CAN else "Can't: ")
                             + ", ".join(passed) + "."))
    if result.not_asked:
        lines.append(_bullet(f"Not asked: {', '.join(result.not_asked)}."))
    if not result.items and not result.outside:
        lines.append(_bullet("No one else to ask."))
    return lines


def _label(item: Item, check: Check) -> str:
    """The item's principal, plus whichever of its action and resource the check has several of."""
    parts = [item.action] if len(check.actions) > 1 else []
    if len(check.resources) > 1:
        parts.append(f"on {item.resource}")
    return f"{item.principal} ({' '.join(parts)})" if parts else item.principal


def _item_markdown(item: Item, label: str) -> list[str]:
    """One item: a line when all its answers read the same, or a line per group of values."""
    groups: dict[str, list[Answer]] = {}
    for answer in item.answers:
        groups.setdefault(_outcome(answer), []).append(answer)
    if len(groups) == 1:
        [text] = groups
        lines = [_bullet(f"{label} {text}")]
    else:
        keys = item.turns_on or tuple(key for key, _ in item.answers[0].values)
        lines = [_bullet(f"{label}, depending on {', '.join(keys)}:")]
        lines += [_bullet(f"{_values(answers, keys)}: {text}", depth=1)
                  for text, answers in groups.items()]
    if item.note is not None and item.result is not Result.PASS:
        lines.append(_bullet(f"Note: {_note(item.note)}", depth=1))
    return lines


def _outcome(answer: Answer) -> str:
    """What one answer says, such as "can. Granted by Read, Sid R, attached directly."."""
    if answer.refusal is not None:
        return f"can't tell: {_refusal(answer.refusal)}"
    result = answer.result
    if result.allowed:
        grants = [m for m in result.reasons if m.layer.policy_type in GRANTING]
        return f"can. Granted by {'; '.join(_statement(m) for m in grants)}."
    if result.decision is Decision.EXPLICIT_DENY:
        return f"can't. Denied by {'; '.join(_statement(m) for m in result.reasons)}."
    return f"can't: {'; '.join(_not_allowed(layer) for layer in result.not_allowed_by)}."


def _refusal(refusal: Refusal) -> str:
    """The engine's reason, and what would settle it."""
    text = refusal.message.rstrip(".") + "."
    if refusal.kind == MissingContextError.__name__:
        return (f"{text} Give each key a value in the check's Context, or null if the request "
                "doesn't include it.")
    if refusal.kind == MissingResourceError.__name__:
        if resources.is_role_arn(refusal.resource):
            return f"{text} Give the role its trust policy as AssumeRolePolicyDocument."
        return (f"{text} Describe it in the account file's Resources, as {{}} if it has no "
                "resource-based policy.")
    return text


def _values(answers: Sequence[Answer], keys: Sequence[str]) -> str:
    """The values of `keys` in `answers`: "false, absent" for one key."""
    labels: list[str] = []
    for answer in answers:
        found = dict(answer.values)
        if len(keys) == 1:
            label = _value(found[keys[0]])
        else:
            label = ", ".join(f"{key} {_value(found[key])}" for key in keys)
        if label not in labels:
            labels.append(label)
    return (", " if len(keys) == 1 else "; ").join(labels)


def _value(value: str | None) -> str:
    return "absent" if value is None else value


def _statement(matched: MatchedStatement) -> str:
    """A statement and how it reaches the principal, such as "TeacherReadGrades, Sid
    ReadStudentRecords, through group Teachers"."""
    layer = matched.layer
    name = _name(matched.policy_name, matched.statement, matched.index)
    if layer.policy_type is PolicyType.IDENTITY:
        how = f"through group {matched.via_group}" if matched.via_group else "attached directly"
        return f"{name}, {how}"
    if layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        return f"{name}, the permissions boundary"
    if layer.policy_type is PolicyType.SCP:
        return f"{name}, an SCP on {_target(layer.org_target)}"
    kind = "trust policy of" if layer.policy_type is PolicyType.TRUST else "resource policy on"
    names = f", which names {NAMES[matched.principal_match]}" if matched.principal_match else ""
    return f"the {kind} {layer.resource}, {_sid(matched.statement, matched.index)}{names}"


def _name(policy_name: str, statement: Statement, index: int | None) -> str:
    return f"{policy_name}, {_sid(statement, index)}"


def _sid(statement: Statement, index: int | None) -> str:
    if statement.sid:
        return f"Sid {statement.sid}"
    return f"statement {index}" if index is not None else "(no Sid)"


def _not_allowed(layer: Layer) -> str:
    if layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        return "the permissions boundary doesn't allow it"
    if layer.policy_type is PolicyType.SCP:
        return f"no SCP on {_target(layer.org_target)} allows it"
    if layer.policy_type is PolicyType.RESOURCE_BASED:
        return f"the resource policy on {layer.resource} doesn't either"
    if layer.policy_type is PolicyType.TRUST:
        return f"the trust policy of {layer.resource} doesn't allow it"
    return "no identity policy allows it"


def _target(target: OrgTarget) -> str:
    if target.type is TargetType.ROOT:
        return "the root"
    if target.type is TargetType.ORGANIZATIONAL_UNIT:
        return f"OU {target.name}"
    return f"account {target.name}"


def _note(note: RoleMfaNote) -> str:
    """Where AWS checks MFA for a role, and what the role's trust policy says."""
    role = note.role
    if note.trust_policy is None:
        trust = f"The account file doesn't give {role}'s trust policy."
    elif not note.statements:
        trust = f"{role}'s trust policy lets no one assume it."
    else:
        ways = []
        for index in note.statements:
            statement = note.trust_policy.statements[index]
            checks = [f"{c.name} {c.key} is {', '.join(c.values)}" for c in statement.conditions
                      if c.key.casefold() == compliance.MFA_KEY.casefold()]
            when = f"when {' and '.join(checks)}" if checks else "without checking MFA"
            ways.append(f"in {_sid(statement, index)}, {when}")
        trust = f"{role}'s trust policy lets someone assume it {'; and '.join(ways)}."
    return (f"MFA for a role is checked when it's assumed. {trust} AWS's docs disagree on whether "
            "a role's requests carry MFA after that, so this check asks about them without MFA, "
            "as for anyone.")


def _outside_markdown(outside: Outside, account: Account) -> str:
    statement = outside.policy.statements[outside.index]
    kind = "trust policy of" if outside.layer.policy_type is PolicyType.TRUST else (
        "resource policy on")
    whom = ", ".join(_principal(p) for p in outside.principals)
    return (f"Can't tell for principals outside {account.name}: the {kind} "
            f"{outside.layer.resource}, {_sid(statement, outside.index)}, allows "
            f"{outside.action} for {whom}, and the analyzer doesn't evaluate requests from "
            "outside the account file yet.")


def _principal(principal: Principal) -> str:
    value = principal.value
    if principal.type is PrincipalType.AWS:
        if value == "*":
            return 'everyone ("*")'
        return f"account {value}" if value.isdigit() else value
    kind = {PrincipalType.SERVICE: "service", PrincipalType.FEDERATED: "identity provider",
            PrincipalType.CANONICAL_USER: "canonical user"}[principal.type]
    return f"{kind} {value}"


def _scope(report: Report) -> list[str]:
    account = report.account
    tried = "; ".join(f"{known.key} ({', '.join(_value(v) for v in known.values)})"
                      for known in condition_keys.KNOWN)
    scps = (f"SCPs come from {report.organization.name}." if report.organization else
            "No SCPs apply: --no-org says the account isn't in an AWS organization.")
    return [
        _bullet(f"A PASS covers only the {_count(len(account.users), 'user')} and "
                f"{_count(len(account.roles), 'role')} in {account.name}. Requests from other "
                "accounts, anonymous requests and federated users aren't evaluated; a policy "
                "that lets them in makes a check CAN'T TELL."),
        _bullet("Each check covers exactly the requests it lists: its actions, its resources, "
                "and the condition keys it gives."),
        _bullet(f"Keys whose every value AWS documents are tried with each one: {tried}. Any "
                "other key a statement needs is CAN'T TELL until a check gives it a value."),
        _bullet(scps),
        _bullet("Not modeled: session policies, resource control policies and VPC endpoint "
                "policies, which can only take access away, so a PASS of a \"can\" check means "
                "the files allow it; S3 Block Public Access; and ACLs, which described buckets "
                "have disabled."),
        _bullet("A role's requests are asked about as they are; the analyzer doesn't follow how "
                "a session was created."),
    ]


def _bullet(text: str, depth: int = 0) -> str:
    indent = "  " * depth
    return _wrap(text, f"{indent}- ", f"{indent}  ")


def _wrap(text: str, first: str = "", rest: str = "") -> str:
    return textwrap.fill(text, width=WIDTH, initial_indent=first, subsequent_indent=rest,
                         break_long_words=False, break_on_hyphens=False)


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" + ("" if number == 1 else "s")


# --- JSON ------------------------------------------------------------------------------


def to_json(report: Report) -> dict:
    """The report as JSON-ready data. Every typed field is kept; absent keys are null."""
    org = report.organization
    return {
        "schema": SCHEMA,
        "framework": {"file": report.framework.name, "id": report.framework.id,
                      "title": report.framework.title},
        "account": {"file": report.account.name, "account_id": report.account.account_id},
        "organization": None if org is None else {"file": org.name},
        "summary": {
            "checks": {result.value: sum(c.result is result for c in report.checks)
                       for result in Result},
            "findings": {severity.value: sum(f.severity is severity for f in report.findings)
                         for severity in Severity},
        },
        "checks": [_check_json(result) for result in report.checks],
        "findings": [_finding_json(finding) for finding in report.findings],
    }


def _finding_json(finding: Finding) -> dict:
    found = finding.type
    condition = finding.condition
    return {
        "id": found.id,
        "title": found.title,
        "severity": finding.severity.value,
        "policy": finding.policy.name,
        "policy_type": finding.kind.value,
        **_statement_ref(finding.statement, finding.index),
        "uses": [_use_json(use) for use in finding.uses],
        "condition": None if condition is None else {
            "operator": condition.name, "key": condition.key, "values": list(condition.values)},
        "why": found.why,
        "fix": found.fix,
        "evidence": {
            "fixtures": [{"case": f.case, "aws": f.aws} for f in found.fixtures],
            "docs": [{"link": d.link, "quote": d.quote} for d in found.docs],
        },
    }


def _use_json(use: Use) -> dict:
    target = use.org_target
    return {
        "policy_type": use.policy_type.value,
        "principal": use.principal,
        "resource": use.resource,
        "org_target": None if target is None else {"type": target.type.value,
                                                   "name": target.name},
    }


def _check_json(result: CheckResult) -> dict:
    check = result.check
    return {
        "id": check.id,
        "title": check.title,
        "type": check.type.value,
        "severity": check.severity.value,
        "result": result.result.value,
        "actions": list(check.actions),
        "resources": list(check.resources),
        "principals": list(check.principals),
        "except": list(check.exempt),
        "key": check.key,
        "value": check.value,
        "context": {
            "values": {check.context.spellings[k]: list(v) for k, v in
                       check.context.values.items()},
            "absent": sorted(check.context.spellings[k] for k in check.context.absent),
        },
        "fix": check.fix,
        "maps_to": [{"framework": r.framework, "id": r.id, "title": r.title, "link": r.link}
                    for r in check.maps_to],
        "not_asked": list(result.not_asked),
        "items": [_item_json(item) for item in result.items],
        "outside": [_outside_json(outside) for outside in result.outside],
    }


def _item_json(item: Item) -> dict:
    note = item.note
    return {
        "principal": item.principal,
        "action": item.action,
        "resource": item.resource,
        "result": item.result.value,
        "turns_on": list(item.turns_on),
        "answers": [_answer_json(answer) for answer in item.answers],
        "note": None if note is None else {
            "role": note.role,
            "trust_policy": None if note.trust_policy is None else note.trust_policy.name,
            "statements": [_statement_ref(note.trust_policy.statements[i], i)
                           for i in note.statements],
        },
    }


def _answer_json(answer: Answer) -> dict:
    result = answer.result
    refusal = answer.refusal
    return {
        "values": dict(answer.values),
        "decision": None if result is None else result.decision.value,
        "statements": [] if result is None else [_matched_json(m) for m in result.reasons],
        "not_allowed_by": [] if result is None else [
            _layer_json(layer) for layer in result.not_allowed_by
        ],
        "refusal": None if refusal is None else {
            "kind": refusal.kind, "message": refusal.message, "keys": list(refusal.keys),
            "resource": refusal.resource,
        },
    }


def _matched_json(matched: MatchedStatement) -> dict:
    return {
        "policy": matched.policy_name,
        **_statement_ref(matched.statement, matched.index),
        "effect": matched.statement.effect.value,
        "layer": _layer_json(matched.layer),
        "via_group": matched.via_group,
        "principal_match": None if matched.principal_match is None else
        matched.principal_match.value,
    }


def _statement_ref(statement: Statement, index: int | None) -> dict:
    conditions = [{"operator": c.name, "key": c.key, "values": list(c.values)}
                  for c in statement.conditions]
    return {"sid": statement.sid, "index": index, "conditions": conditions}


def _layer_json(layer: Layer) -> dict:
    target = layer.org_target
    return {
        "type": layer.policy_type.value,
        "org_target": None if target is None else {"type": target.type.value,
                                                   "name": target.name},
        "resource": layer.resource,
    }


def _outside_json(outside: Outside) -> dict:
    return {
        "policy": outside.policy.name,
        **_statement_ref(outside.policy.statements[outside.index], outside.index),
        "layer": _layer_json(outside.layer),
        "principals": [{"type": p.type.value, "value": p.value} for p in outside.principals],
        "action": outside.action,
        "resource": outside.resource,
    }
