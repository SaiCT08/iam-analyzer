from pathlib import Path

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


def test_a_roles_item_carries_the_mfa_note():
    text = markdown(check("a", "requires"))
    lines = section(text, "Check a")
    admin = lines.index("- role/Admin can. Granted by Unnamed, statement 0, attached directly.")
    note = " ".join(line.strip() for line in lines[admin + 1:admin + 5])
    assert note.startswith(
        "- Note: MFA for a role is checked when it's assumed. role/Admin's trust policy lets "
        f"someone assume it in Sid AccountWithMfa, when Bool {MFA} is true. AWS's docs disagree")


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
