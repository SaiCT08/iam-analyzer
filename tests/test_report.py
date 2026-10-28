from pathlib import Path

import pytest

from iam_analyzer.account import load_account_file, parse_account
from iam_analyzer.compliance import Result
from iam_analyzer.framework import load_framework_file, parse_framework
from iam_analyzer.organization import load_organization_file
from iam_analyzer.report import WIDTH, build, to_json, to_markdown

EXAMPLES = Path(__file__).parent.parent / "examples"
GOLDEN = Path(__file__).parent / "golden" / "district_report.md"

BUCKET = "arn:aws:s3:::district-student-records"
OBJECT = f"{BUCKET}/campus-02/transcript.pdf"
LESSONS = "arn:aws:s3:::district-lesson-plans/week1.pdf"
MFA = "aws:MultiFactorAuthPresent"
AC_6 = {"Framework": "NIST SP 800-53 Rev. 5", "Id": "AC-6", "Title": "Least Privilege",
        "Link": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"}
ADMIN_TRUST = {"Statement": [{"Sid": "AccountWithMfa", "Effect": "Allow",
                              "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                              "Action": "sts:AssumeRole", "Condition": {"Bool": {MFA: "true"}}}]}


def account(bucket_policy=None, clerk=True):
    """A small account. The clerk's policy has an MFA Deny that skips access keys, a high
    finding, so reports about other things can leave the clerk out."""
    bucket = {} if bucket_policy is None else {"Policy": bucket_policy}
    read = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"}
    document = {
        "AccountId": "111122223333",
        "Policies": {
            "Read": {"Statement": [{**read, "Sid": "Read"}]},
            "Unnamed": {"Statement": [read]},
            "Write": {"Version": "2012-10-17", "Statement": [
                {"Sid": "Write", "Effect": "Allow", "Action": "s3:PutObject",
                 "Resource": f"{BUCKET}/*"},
                {"Sid": "NeedsMfa", "Effect": "Deny", "Action": "s3:PutObject",
                 "Resource": f"{BUCKET}/*", "Condition": {"BoolIfExists": {MFA: "false"}}},
            ]},
            "SkipsAccessKeys": {"Statement": [
                {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"{BUCKET}/*"},
                {"Effect": "Deny", "Action": "s3:PutObject", "Resource": f"{BUCKET}/*",
                 "Condition": {"Bool": {MFA: "false"}}},
            ]},
        },
        "Groups": {"Teachers": {"Policies": ["Read"]}},
        "Users": {"teacher": {"Groups": ["Teachers"]}, "reader": {"Policies": ["Unnamed"]},
                  "registrar": {"Policies": ["Write"]},
                  **({"clerk": {"Policies": ["SkipsAccessKeys"]}} if clerk else {})},
        "Roles": {"Admin": {"Policies": ["Unnamed"], "AssumeRolePolicyDocument": ADMIN_TRUST}},
        "Resources": {BUCKET: bucket},
    }
    if not clerk:
        del document["Policies"]["SkipsAccessKeys"]
    return parse_account(document, name="acct.json")


def check(check_id, check_type, severity="high", **fields):
    names = {"requires": {"Key": MFA, "Value": "true"}}.get(check_type, {"Principals": []})
    return {"Id": check_id, "Title": f"Check {check_id}", "Severity": severity,
            "Type": check_type, "Actions": ["s3:GetObject"], "Resources": [OBJECT],
            "Fix": f"Fix {check_id}.", **names, **fields}


def report(*checks, bucket_policy=None, clerk=True):
    framework = parse_framework({"Framework": {"Id": "fw", "Title": "Student records"},
                                 "Requirements": {"NIST AC-6": AC_6}, "Checks": list(checks)},
                                name="fw.json")
    return build(framework, account(bucket_policy, clerk), organization=None)


def markdown(*checks, **kwargs):
    return to_markdown(report(*checks, **kwargs))


def section(text, title):
    """The lines of the check headed `title`."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("## ") and title in line)
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return lines[start:end]


def has_block(lines, block):
    """Whether `block` appears in `lines` as consecutive lines."""
    return "\n".join(block) in "\n".join(lines)


def flat(text):
    """The text with its line wrapping undone."""
    return " ".join(text.split())


def test_the_summary_always_shows_all_four_results():
    text = markdown(check("a", "only", Principals=["group/Teachers", "user/reader",
                                                    "role/Admin"]))
    assert "| FAIL | 0 |\n| DEPENDS | 0 |\n| CAN'T TELL | 0 |\n| PASS | 1 |" in text
    assert "- Organization: none (--no-org), so no SCPs apply." in text


def test_checks_that_need_attention_come_first():
    text = markdown(
        check("pass", "only", Principals=["group/Teachers", "user/reader", "role/Admin"]),
        check("cant", "only", Resources=[LESSONS]),
        check("low", "only", severity="low"),
        check("depends", "can", Principals=["user/registrar"], Actions=["s3:PutObject"]),
        check("high", "only"),
    )
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings == [
        "## FAIL: Check high (high)",
        "## FAIL: Check low (low)",
        "## DEPENDS: Check depends (high)",
        "## CAN'T TELL: Check cant (high)",
        "## PASS: Check pass (high)",
        "## Findings",
        "## Scope and limits",
    ]


def test_a_fail_cites_each_grant_and_how_the_principal_gets_it():
    lines = section(markdown(check("a", "only", MapsTo=["NIST AC-6"])), "Check a")
    assert lines[2] == f"Asked: Can anyone do s3:GetObject on {OBJECT}?"
    assert ("- user/teacher can. Granted by Read, Sid Read, through group Teachers." in lines)
    # A statement without a Sid is named by its place in its policy.
    assert ("- user/reader, role/Admin can. Granted by Unnamed, statement 0, attached "
            "directly.") in lines
    assert "- Can't: user/registrar, user/clerk." in lines
    assert "Fix: Fix a." in lines
    assert ("- NIST SP 800-53 Rev. 5 AC-6: Least Privilege. "
            "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final") in lines


def test_a_depends_lists_the_values_with_each_answer():
    lines = section(markdown(check("a", "can", Principals=["user/registrar"],
                                   Actions=["s3:PutObject"])), "Check a")
    assert has_block(lines, [
        f"- user/registrar, depending on {MFA}:",
        "  - true: can. Granted by Write, Sid Write, attached directly.",
        "  - false, absent: can't. Denied by Write, Sid NeedsMfa, attached directly.",
    ])


def test_a_prohibition_lists_the_values_that_allow_it():
    text = markdown(check("a", "requires", Except=["role/Admin"], Actions=["s3:PutObject"]))
    lines = section(text, "Check a")
    assert lines[0] == "## FAIL: Check a (high)"
    assert (f"Asked: Can anyone but role/Admin do s3:PutObject on {OBJECT} when {MFA} is false "
            "or absent?") in flat("\n".join(lines))
    assert has_block(lines, [
        f"- user/clerk, depending on {MFA}:",
        "  - false: can't. Denied by SkipsAccessKeys, statement 1, attached directly.",
        "  - absent: can. Granted by SkipsAccessKeys, statement 0, attached directly.",
    ])
    assert "- Not asked: role/Admin." in lines


def test_refusals_are_grouped_and_say_what_would_settle_them():
    text = flat("\n".join(section(markdown(check("a", "only", Resources=[LESSONS])), "Check a")))
    assert ("- Can't tell for everyone asked: nothing describes "
            "arn:aws:s3:::district-lesson-plans: it can have a resource-based policy, and the "
            "analyzer can't tell whether it has one, or which account it is in. Describe it in "
            "the account file's Resources, as {} if it has no resource-based policy.") in text


def test_a_key_that_cant_be_tried_says_to_give_it():
    office = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "111122223333"},
                             "Action": "s3:GetObject", "Resource": f"{BUCKET}/*",
                             "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}]}
    text = flat(markdown(check("a", "only"), bucket_policy=office))
    assert ("- Can't tell for everyone asked: the request context says nothing about these "
            "condition keys: aws:SourceIp, used by arn:aws:s3:::district-student-records "
            "statement 0. Give each key a value in the check's Context") in text


def test_principals_outside_the_file_are_cited():
    public = {"Statement": [{"Sid": "Public", "Effect": "Allow", "Principal": "*",
                             "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"}]}
    text = flat(markdown(check("a", "only"), bucket_policy=public))
    # Principals whose answers read the same share a line.
    assert ("- user/registrar, user/clerk can. Granted by the resource policy on "
            "arn:aws:s3:::district-student-records, Sid Public, which names everyone.") in text
    assert ('Can\'t tell for principals outside acct.json: the resource policy on '
            'arn:aws:s3:::district-student-records, Sid Public, allows s3:GetObject for '
            'everyone ("*")') in text


PASSES = ("passes: its own policies allow the request, but AWS checks MFA for a role when it's "
          "assumed, and no one can assume it without MFA")
AWS_ON_ROLES = ('- AWS: "The temporary credentials returned by AssumeRole do not include MFA '
                "information in the context, so you cannot check individual API operations for "
                'MFA." https://docs.aws.amazon.com/IAM/latest/UserGuide/'
                "id_credentials_mfa_configure-api-require.html#scenarios")


def test_a_role_that_passes_leads_with_its_result():
    lines = section(markdown(check("a", "requires")), "Check a")
    # The role can read without MFA, but no one can assume it without MFA, so its item passes.
    # Its line says so first, with AWS's words under it, and it doesn't join the "Can't" list.
    admin = next(i for i, line in enumerate(lines) if line.startswith("- role/Admin"))
    quote = next(i for i, line in enumerate(lines) if line.startswith("  - AWS: "))
    end = next(i for i in range(quote, len(lines)) if lines[i].startswith("- "))
    assert flat("\n".join(lines[admin:quote])) == (
        f"- role/Admin {PASSES} (trust policy Sid AccountWithMfa).")
    assert flat("\n".join(lines[quote:end])) == AWS_ON_ROLES
    assert not any("role/Admin can" in line for line in lines)
    assert not any(line.startswith("- Can't:") and "role/Admin" in line for line in lines)


def role_report(trust, policies=("Read",), bucket_policy=None, **users):
    """A role with `policies`, and `trust` as its trust policy, `users` who may assume it, and
    `bucket_policy` on the bucket."""
    acct = parse_account({"AccountId": "111122223333", "Policies": {
        "Read": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                                "Resource": f"{BUCKET}/*"}]},
        "AssumeAdmin": {"Statement": [{"Sid": "AssumeAdmin", "Effect": "Allow",
                                       "Action": "sts:AssumeRole", "Resource": f"{ROLES}/Admin"}]},
    }, "Users": users,
        "Roles": {"Admin": {"Policies": list(policies), "AssumeRolePolicyDocument": trust}},
        "Resources": {BUCKET: {} if bucket_policy is None else {"Policy": bucket_policy}}},
        name="acct.json")
    framework = parse_framework({"Framework": {"Id": "fw", "Title": "F"},
                                 "Checks": [check("a", "requires")]}, name="fw.json")
    return build(framework, acct, organization=None)


MFA_ALLOW = ADMIN_TRUST["Statement"][0]
ACCOUNT_ALLOW = {"Sid": "Account", "Effect": "Allow", "Principal": {"AWS": "111122223333"},
                 "Action": "sts:AssumeRole"}


@pytest.mark.parametrize("statements, where", [
    ([MFA_ALLOW], "trust policy Sid AccountWithMfa"),
    ([ACCOUNT_ALLOW], "trust policy Sid Account doesn't check MFA"),
    ([MFA_ALLOW, ACCOUNT_ALLOW], "trust policy Sid AccountWithMfa; Sid Account doesn't check MFA"),
    ([{**ACCOUNT_ALLOW, "Action": "sts:TagSession"}], "its trust policy lets no one assume it"),
], ids=["checks-mfa", "doesnt-check-mfa", "both", "lets-no-one-assume"])
def test_a_passing_roles_line_says_where_its_trust_policy_checks_mfa(statements, where):
    # No one in the file may assume the role, so it passes whatever its trust policy says, and
    # its line says what that is.
    text = flat(to_markdown(role_report({"Statement": statements})))
    assert f"- role/Admin {PASSES} ({where})." in text


def test_a_passing_role_that_a_bucket_policy_names_says_which_policy_allows_it():
    bucket = {"Statement": [{"Sid": "AdminReads", "Effect": "Allow",
                             "Principal": {"AWS": f"{ROLES}/Admin"}, "Action": "s3:GetObject",
                             "Resource": f"{BUCKET}/*"}]}
    text = flat(to_markdown(role_report(ADMIN_TRUST, policies=(), bucket_policy=bucket)))
    assert (f"- role/Admin passes: the resource policy on {BUCKET} allows the request, but AWS "
            "checks MFA for a role when it's assumed, and no one can assume it without MFA (trust "
            "policy Sid AccountWithMfa).") in text


def test_a_role_someone_can_assume_without_mfa_lists_who():
    trust = {"Statement": [{"Sid": "Account", "Effect": "Allow",
                            "Principal": {"AWS": "111122223333"}, "Action": "sts:AssumeRole"}]}
    graded = role_report(trust, it={"Policies": ["AssumeAdmin"]})
    lines = section(to_markdown(graded), "Check a")
    assert has_block(lines, [
        "- role/Admin can. Granted by Read, statement 0, attached directly.",
        f"  - FAIL: AWS checks {MFA} for a role when it's assumed, and these can assume",
        f"    role/Admin when {MFA} is false or absent:",
        "    - user/it can. Granted by AssumeAdmin, Sid AssumeAdmin, attached directly; the trust "
        "policy of",
        f"      {ROLES}/Admin, Sid Account, which names the account.",
    ])
    [admin] = [i for i in to_json(graded)["checks"][0]["items"] if i["principal"] == "role/Admin"]
    assert admin["result"] == "FAIL"
    assert admin["note"]["assume"]["result"] == "FAIL"
    assert [i["principal"] for i in admin["note"]["assume"]["items"]
            if i["result"] == "FAIL"] == ["user/it"]


def test_an_outsider_who_can_assume_the_role_is_cant_tell():
    trust = {"Statement": [{"Sid": "Vendor", "Effect": "Allow",
                            "Principal": {"AWS": "444455556666"}, "Action": "sts:AssumeRole"}]}
    text = flat("\n".join(section(to_markdown(role_report(trust)), "Check a")))
    assert (f"- CAN'T TELL: AWS checks {MFA} for a role when it's assumed, and the analyzer can't "
            f"tell whether everyone who can assume role/Admin needs {MFA} true: - Can't tell for "
            f"principals outside acct.json: the trust policy of {ROLES}/Admin, Sid Vendor, allows "
            "sts:AssumeRole for account 444455556666") in text
    assert "## CAN'T TELL: Check a (high)" in to_markdown(role_report(trust))


def test_scope_says_what_a_pass_covers():
    text = flat(markdown(check("a", "only")).split("## Scope and limits")[1])
    assert "A PASS covers only the 4 users and 1 role in acct.json." in text
    assert "No SCPs apply: --no-org says the account isn't in an AWS organization." in text
    assert f"{MFA} (true, false, absent)" in text


def test_lines_fit_on_screen():
    text = markdown(check("a", "only"), check("b", "requires"),
                    check("c", "can", Principals=["user/registrar"], Actions=["s3:PutObject"]))
    for line in text.splitlines():
        # Only a single word too long to wrap, such as an ARN, may run past the width.
        assert len(line) <= WIDTH or len(line.split()) <= 2, line


def test_json_keeps_the_typed_fields():
    data = to_json(report(check("a", "only"), check("b", "requires", Actions=["s3:PutObject"]),
                          check("c", "only", Resources=[LESSONS])))
    assert data["schema"] == 1
    assert data["organization"] is None
    assert data["summary"]["checks"] == {"FAIL": 2, "DEPENDS": 0, "CANT_TELL": 1, "PASS": 0}
    only, requires, cant = data["checks"]
    teacher = next(i for i in only["items"] if i["principal"] == "user/teacher")
    [grant] = teacher["answers"][0]["statements"]
    assert grant == {"policy": "Read", "sid": "Read", "index": 0, "conditions": [],
                     "effect": "Allow", "via_group": "Teachers", "principal_match": None,
                     "layer": {"type": "identity", "org_target": None, "resource": None}}
    clerk = next(i for i in requires["items"] if i["principal"] == "user/clerk")
    assert [a["values"] for a in clerk["answers"]] == [{MFA: "false"}, {MFA: None}]
    assert clerk["turns_on"] == [MFA]
    admin = next(i for i in requires["items"] if i["principal"] == "role/Admin")
    assert admin["note"]["statements"][0]["conditions"] == [
        {"operator": "Bool", "key": MFA, "values": ["true"]}]
    refusal = cant["items"][0]["answers"][0]["refusal"]
    assert (refusal["kind"], refusal["resource"]) == (
        "MissingResourceError", "arn:aws:s3:::district-lesson-plans")


def test_failed_and_unsettled():
    passed = report(check("a", "only", Principals=["group/Teachers", "user/reader", "role/Admin"]),
                    clerk=False)
    assert (passed.failed, passed.unsettled) == (False, False)
    depends = report(check("a", "can", Principals=["user/registrar"], Actions=["s3:PutObject"]),
                     clerk=False)
    assert (depends.failed, depends.unsettled) == (False, True)
    failed = report(check("a", "only"), check("b", "only", Resources=[LESSONS]), clerk=False)
    assert (failed.failed, failed.unsettled) == (True, True)
    # With the clerk, a passing check still fails the report: its policy has a high finding.
    assert report(check("a", "only", Principals=["group/Teachers", "user/reader", "role/Admin",
                                                 "user/clerk"])).failed


def test_labels_show_only_what_varies_and_passing_principals_appear_once():
    lines = section(markdown(check("a", "only", Actions=["s3:GetObject", "s3:PutObject"])),
                    "Check a")
    # The registrar can write but not read; the clerk can write too. Both have their own lines.
    assert f"- user/registrar (s3:PutObject), depending on {MFA}:" in lines
    assert ("- user/teacher (s3:GetObject) can. Granted by Read, Sid Read, through group "
            "Teachers.") in lines
    assert ("- Can't: user/teacher (s3:PutObject), user/reader (s3:PutObject), user/registrar "
            "(s3:GetObject), user/clerk") in flat("\n".join(lines))
    # One resource, so it isn't repeated; with every item passing, a principal is just its name.
    assert OBJECT not in "\n".join(lines[5:])
    actions = ["s3:DeleteObject", "s3:PutBucketTagging"]
    passing = section(markdown(check("b", "only", Actions=actions)), "Check b")
    assert "- Can't: user/teacher, user/reader, user/registrar, user/clerk, role/Admin." in passing


# --- The district example --------------------------------------------------------------


def district_report():
    return build(load_framework_file(EXAMPLES / "frameworks" / "district.json"),
                 load_account_file(EXAMPLES / "accounts" / "district.json"),
                 organization=load_organization_file(EXAMPLES / "organizations" / "district.json"))


def test_the_district_framework_gives_every_result():
    assert {r.check.id: r.result for r in district_report().checks} == {
        "student-records-no-deletes": Result.PASS,
        "counseling-notes-counselors-only": Result.FAIL,
        "roster-exports-registrars-only": Result.FAIL,
        "record-changes-need-mfa": Result.FAIL,
        "admin-role-needs-mfa": Result.PASS,
        "registrars-update-own-campus": Result.DEPENDS,
        "lesson-plans-teachers-only": Result.CANT_TELL,
    }


def test_the_district_report_matches_its_golden_file():
    """After an intended change to the report, regenerate the golden file:

        iam-analyzer report --account examples/accounts/district.json \\
          --org examples/organizations/district.json \\
          --framework examples/frameworks/district.json > tests/golden/district_report.md
    """
    assert to_markdown(district_report()) == GOLDEN.read_text()


# --- Findings --------------------------------------------------------------------------


def findings_report():
    acct = parse_account({"AccountId": "111122223333", "Policies": {"Window": {"Statement": [
        {"Sid": "Late", "Effect": "Deny", "Action": "s3:GetObject", "Resource": f"{BUCKET}/*",
         "Condition": {"DateGreaterThan": {"aws:CurrentTime": "2027"}}},
        {"Effect": "Deny", "Action": "s3:PutObject", "Resource": f"{BUCKET}/*",
         "Condition": {"DateLessThan": {"aws:CurrentTime": "2026"}}},
    ]}}, "Groups": {"Staff": {"Policies": ["Window"]}}, "Resources": {BUCKET: {}}},
        name="acct.json")
    framework = parse_framework({"Framework": {"Id": "fw", "Title": "F"},
                                 "Checks": [check("a", "only")]}, name="fw.json")
    return build(framework, acct, organization=None)


def test_findings_are_listed_with_their_evidence():
    text = to_markdown(findings_report())
    assert "Findings: 1 high, 1 low." in text
    findings = text.split("## Findings")[1].split("## Scope and limits")[0]
    assert findings.splitlines()[2:5] == [
        "### HIGH: A four-digit date is read as epoch seconds",
        "",
        "- In: Window, statement 1: an identity policy attached to group/Staff.",
    ]
    assert "- Condition: DateLessThan aws:CurrentTime: 2026." in findings
    assert ("- Evidence: AWS's IAM policy simulator answered ALLOW in "
            "dates_without_a_time_zone/four_digits") in findings
    assert "### LOW: A four-digit date is read as epoch seconds" in findings
    assert "- In: Window, Sid Late: an identity policy attached to group/Staff." in findings


def test_a_high_finding_fails_the_report():
    graded = findings_report()
    assert all(check.result is Result.PASS for check in graded.checks)
    assert graded.failed


def test_no_findings_says_so():
    text = markdown(check("a", "only"), clerk=False)
    assert "## Findings\n\nNo findings.\n" in text
    assert "Findings: none." in text


def test_json_lists_the_findings():
    data = to_json(findings_report())
    assert data["summary"]["findings"] == {"critical": 0, "high": 1, "medium": 0, "low": 1}
    high, low = data["findings"]
    assert high == {
        "id": "date-number-is-epoch-seconds", "title": "A four-digit date is read as epoch seconds",
        "severity": "high", "policy": "Window", "policy_type": "identity", "sid": None, "index": 1,
        "conditions": [{"operator": "DateLessThan", "key": "aws:CurrentTime", "values": ["2026"]}],
        "uses": [{"policy_type": "identity", "principal": "group/Staff", "resource": None,
                  "org_target": None}],
        "condition": {"operator": "DateLessThan", "key": "aws:CurrentTime", "values": ["2026"]},
        "principal": None, "unsettled": [], "variable": None, "element": None, "subjects": [],
        "always": False,  # the Deny's DateLessThan 2026 never holds
        "why": high["why"], "fix": high["fix"],
        "evidence": {
            "fixtures": [{"case": "dates_without_a_time_zone/four_digits", "aws": "ALLOW"}],
            "docs": [],
        },
    }
    assert low["sid"] == "Late"


def test_a_variable_without_a_value_names_the_principals():
    acct = parse_account({"AccountId": "111122223333", "Policies": {"Home": {
        "Version": "2012-10-17", "Statement": [{
            "Sid": "OwnFolder", "Effect": "Allow", "Action": "s3:GetObject",
            "Resource": f"{BUCKET}/home/${{aws:username}}/*"}]}},
        "Roles": {"Reports": {"Policies": ["Home"]}}, "Resources": {BUCKET: {}}}, name="acct.json")
    framework = parse_framework({"Framework": {"Id": "fw", "Title": "F"},
                                 "Checks": [check("a", "only")]}, name="fw.json")
    text = flat(to_markdown(build(framework, acct, organization=None)))
    assert ("### LOW: A policy variable has no value for some principals - In: Home, Sid "
            "OwnFolder: an identity policy attached to role/Reports. - Variable: ${aws:username} "
            "in Resource, with no value for role/Reports.") in text


def test_a_finding_about_principals_lists_them():
    acct = parse_account({"AccountId": "111122223333", "Policies": {"Bound": {"Statement": [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}},
        "Users": {"kwong": {"PermissionsBoundary": "Bound"}},
        "Resources": {BUCKET: {"Policy": {"Statement": [{
            "Sid": "AllButKwong", "Effect": "Deny", "NotPrincipal": {"AWS": [
                "arn:aws:iam::111122223333:root", "arn:aws:iam::111122223333:user/kwong"]},
            "Action": "s3:PutObject", "Resource": f"{BUCKET}/*"}]}}}}, name="acct.json")
    framework = parse_framework({"Framework": {"Id": "fw", "Title": "F"},
                                 "Checks": [check("a", "only")]}, name="fw.json")
    text = flat(to_markdown(build(framework, acct, organization=None)))
    # The check reads, which the NotPrincipal Deny doesn't cover, so it's still answered: kwong
    # has the policy only as a boundary, so nothing grants the read.
    assert "## PASS: Check a (high)" in text
    assert ("### LOW: A NotPrincipal Deny always denies principals with a boundary - In: the "
            "resource policy on arn:aws:s3:::district-student-records, Sid AllButKwong. - "
            "Affects: user/kwong.") in text


def test_a_way_in_the_boundary_blocks_isnt_cited():
    # Both roles can read through the public bucket policy. Vendor's boundary blocks its identity
    # policy, so only Admin also gets in that way, and the two don't share a line.
    public = {"Statement": [{"Sid": "Public", "Effect": "Allow", "Principal": "*",
                             "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"}]}
    acct = parse_account({"AccountId": "111122223333", "Policies": {
        "Broad": {"Statement": [{"Sid": "Broad", "Effect": "Allow", "Action": "s3:*",
                                 "Resource": "*"}]},
        "Elsewhere": {"Statement": [{"Effect": "Allow", "Action": "s3:*",
                                     "Resource": "arn:aws:s3:::district-gradebook-app/*"}]},
    }, "Roles": {"Admin": {"Policies": ["Broad"]},
                 "Vendor": {"Policies": ["Broad"], "PermissionsBoundary": "Elsewhere"}},
        "Resources": {BUCKET: {"Policy": public}}}, name="acct.json")
    framework = parse_framework({"Framework": {"Id": "fw", "Title": "F"},
                                 "Checks": [check("a", "only")]}, name="fw.json")
    graded = build(framework, acct, organization=None)
    lines = section(to_markdown(graded), "Check a")
    text = flat("\n".join(lines))
    assert ("- role/Admin can. Granted by Broad, Sid Broad, attached directly; the resource policy "
            f"on {BUCKET}, Sid Public, which names everyone.") in text
    assert (f"- role/Vendor can. Granted by the resource policy on {BUCKET}, Sid Public, which "
            "names everyone.") in text
    vendor = next(item for item in to_json(graded)["checks"][0]["items"]
                  if item["principal"] == "role/Vendor")
    [answer] = vendor["answers"]
    assert [s["sid"] for s in answer["statements"]] == ["Broad", "Public"]  # both matched
    assert [s["sid"] for s in answer["grants"]] == ["Public"]  # one grants


def test_a_pass_says_what_to_keep_not_what_to_fix():
    everyone_allowed = ["group/Teachers", "user/reader", "role/Admin"]
    keep = markdown(check("a", "only", Principals=everyone_allowed, Keep="Keep this."),
                    clerk=False)
    assert "Keep: Keep this." in keep and "Fix: Fix a." not in keep
    # With no Keep, a PASS has neither line, and a check that doesn't pass shows its fix.
    plain = markdown(check("a", "only", Principals=everyone_allowed), clerk=False)
    assert "Keep:" not in plain and "Fix:" not in plain
    failing = markdown(check("b", "only", Keep="Keep this."), clerk=False)
    assert "Fix: Fix b." in failing and "Keep:" not in failing
    assert to_json(report(check("a", "only", Keep="Keep this.")))["checks"][0]["keep"] == (
        "Keep this.")


# --- What each finding does ------------------------------------------------------------

ROLES = "arn:aws:iam::111122223333:role"


def every_mistake():
    """An account with one of every finding type, and the principals that get each."""
    def p(sid, effect, action="s3:GetObject", resource=f"{BUCKET}/*", **condition):
        statement = {"Sid": sid, "Effect": effect, "Action": action, "Resource": resource}
        return {"Version": "2012-10-17",
                "Statement": [{**statement, **({"Condition": condition} if condition else {})}]}
    tags = "aws:TagKeys"
    policies = {
        "Window": p("Window", "Allow", DateLessThan={"aws:CurrentTime": "2027"}),
        "Closed": p("Closed", "Deny", DateGreaterThan={"aws:CurrentTime": "2026"}),
        "BoolVar": p("BoolVar", "Deny",
                     Bool={"aws:SecureTransport": "${aws:MultiFactorAuthPresent}"}),
        "MfaDeny": p("MfaDeny", "Deny", "s3:PutObject", Bool={MFA: "false"}),
        "AllTags": p("AllTags", "Allow", "s3:PutObject",
                     **{"ForAllValues:StringEquals": {tags: ["campus"]}}),
        "AnyTag": p("AnyTag", "Deny", "s3:PutObject",
                    **{"ForAnyValue:StringEqualsIfExists": {tags: "campus"}}),
        "NullSet": p("NullSet", "Allow", "s3:PutObject", **{"ForAllValues:Null": {tags: "false"}}),
        "Zoneless": p("Zoneless", "Allow", DateGreaterThan={"aws:CurrentTime": "2026-08-15"}),
        "HostBits": p("HostBits", "Allow", IpAddress={"aws:SourceIp": "203.0.113.5/24"}),
        "Home": p("Home", "Allow", resource=f"{BUCKET}/home/${{aws:username}}/*"),
        "Bound": p("Bound", "Allow", "s3:*", "*"),
    }
    bucket = {"Statement": [
        {"Sid": "Public", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": f"{BUCKET}/*"},
        {"Sid": "Gone", "Effect": "Deny", "Principal": {"AWS": "AIDAEXAMPLEEXAMPLE123"},
         "Action": "s3:DeleteObject", "Resource": f"{BUCKET}/*"},
        {"Sid": "AllButKwong", "Effect": "Deny", "NotPrincipal": {"AWS": [
            "arn:aws:iam::111122223333:root", "arn:aws:iam::111122223333:user/kwong"]},
         "Action": "s3:PutBucketPolicy", "Resource": BUCKET},
    ]}
    def trust(principal):
        return {"Statement": [{"Effect": "Allow", "Principal": principal,
                               "Action": "sts:AssumeRole"}]}
    return parse_account({
        "AccountId": "111122223333", "Policies": policies,
        "Groups": {"Staff": {"Policies": [n for n in policies if n not in ("Home", "Bound")]}},
        "Users": {"kwong": {"PermissionsBoundary": "Bound"}},
        "Roles": {"Reports": {"Policies": ["Home"]},
                  "Open": {"AssumeRolePolicyDocument": trust("*")},
                  "Vendor": {"AssumeRolePolicyDocument": trust({"AWS": "444455556666"})}},
        "Resources": {BUCKET: {"Policy": bucket}},
    }, name="acct.json")


def test_each_finding_says_what_its_mistake_does():
    from iam_analyzer.findings import scan
    from iam_analyzer.report import _impact
    impacts = {(f.type.id, f.statement.sid or f.policy.name): _impact(f)
               for f in scan(every_mistake(), organization=None)}
    on = f"on {BUCKET}/*"
    assert impacts == {
        ("date-number-is-epoch-seconds", "Window"):
            f"The Allow never applies, so it never lets group/Staff do s3:GetObject {on}.",
        ("date-number-is-epoch-seconds", "Closed"):
            f"The condition always holds, so the Deny stops group/Staff from doing s3:GetObject "
            f"{on} whatever the date.",
        ("bool-variable-never-matches", "BoolVar"):
            "The condition never holds in a request that includes aws:SecureTransport, so the "
            f"Deny never stops group/Staff from doing s3:GetObject {on} in one.",
        ("mfa-deny-skips-access-keys", "MfaDeny"):
            f"It doesn't stop group/Staff from doing s3:PutObject {on} in requests made with "
            "long-term access keys.",
        ("for-all-values-allow-without-null", "AllTags"):
            f"It also lets group/Staff do s3:PutObject {on} in requests that don't include "
            "aws:TagKeys.",
        ("for-any-value-ignores-if-exists", "AnyTag"):
            f"It never stops group/Staff from doing s3:PutObject {on} in a request that doesn't "
            "include aws:TagKeys.",
        ("set-operator-on-null", "NullSet"):
            f"The condition always holds, so the Allow lets group/Staff do s3:PutObject {on} "
            "whether or not the request includes aws:TagKeys.",
        ("date-without-a-time-zone", "Zoneless"):
            f"The Allow for group/Staff on s3:GetObject {on} switches at 2026-08-15T00:00:00 UTC, "
            "which may be hours from the local time meant.",
        ("ip-range-with-host-bits", "HostBits"):
            "The Allow applies to requests from all of 203.0.113.0/24, not only from 203.0.113.5, "
            f"so it lets group/Staff do s3:GetObject {on} from any of those addresses.",
        ("variable-without-a-value", "Home"):
            f"For role/Reports, {BUCKET}/home/${{aws:username}}/* matches nothing, so the Allow "
            "never lets them do s3:GetObject on it.",
        ("public-bucket-policy", "Public"):
            f"It lets anyone do s3:GetObject {on}, with credentials from any AWS account or with "
            "none.",
        ("principal-is-a-unique-id", "Gone"):
            f"The principal it names is gone, so it no longer stops anyone from doing "
            f"s3:DeleteObject {on}, even a new principal with the same name.",
        ("not-principal", "AllButKwong"):
            "It stops everyone but arn:aws:iam::111122223333:root and "
            f"arn:aws:iam::111122223333:user/kwong from doing s3:PutBucketPolicy on {BUCKET}, and "
            "which principals that spares depends on how each service reads NotPrincipal.",
        ("not-principal-deny-with-a-boundary", "AllButKwong"):
            f"It always stops user/kwong from doing s3:PutBucketPolicy on {BUCKET}, even if "
            "NotPrincipal names them.",
        ("trust-policy-names-everyone", f"{ROLES}/Open"):
            f"It lets any principal in any AWS account assume {ROLES}/Open.",
        ("cross-account-trust-without-external-id", f"{ROLES}/Vendor"):
            f"It lets account 444455556666 assume {ROLES}/Vendor without giving an external ID.",
    }


def test_every_finding_type_has_an_impact():
    from iam_analyzer.findings import TYPES
    from iam_analyzer.report import IMPACTS
    assert set(IMPACTS) == {t.id for t in TYPES}


def test_the_district_date_finding_says_whom_it_shuts_out():
    text = flat(to_markdown(district_report()))
    assert ("- Impact: The Allow never applies, so it never lets group/SummerSchool do "
            "s3:GetObject on arn:aws:s3:::district-student-records/campus-01/*.") in text
