from iam_analyzer.account import parse_account
from iam_analyzer.framework import parse_framework
from iam_analyzer.report import WIDTH, build, to_json, to_markdown

BUCKET = "arn:aws:s3:::district-student-records"
OBJECT = f"{BUCKET}/campus-02/transcript.pdf"
LESSONS = "arn:aws:s3:::district-lesson-plans/week1.pdf"
MFA = "aws:MultiFactorAuthPresent"
AC_6 = {"Framework": "NIST SP 800-53 Rev. 5", "Id": "AC-6", "Title": "Least Privilege",
        "Link": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"}
ADMIN_TRUST = {"Statement": [{"Sid": "AccountWithMfa", "Effect": "Allow",
                              "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                              "Action": "sts:AssumeRole", "Condition": {"Bool": {MFA: "true"}}}]}


def account(bucket_policy=None):
    bucket = {} if bucket_policy is None else {"Policy": bucket_policy}
    read = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"}
    return parse_account({
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
                  "registrar": {"Policies": ["Write"]}, "clerk": {"Policies": ["SkipsAccessKeys"]}},
        "Roles": {"Admin": {"Policies": ["Unnamed"], "AssumeRolePolicyDocument": ADMIN_TRUST}},
        "Resources": {BUCKET: bucket},
    }, name="acct.json")


def check(check_id, check_type, severity="high", **fields):
    names = {"requires": {"Key": MFA, "Value": "true"}}.get(check_type, {"Principals": []})
    return {"Id": check_id, "Title": f"Check {check_id}", "Severity": severity,
            "Type": check_type, "Actions": ["s3:GetObject"], "Resources": [OBJECT],
            "Fix": f"Fix {check_id}.", **names, **fields}


def report(*checks, bucket_policy=None):
    framework = parse_framework({"Framework": {"Id": "fw", "Title": "Student records"},
                                 "Requirements": {"NIST AC-6": AC_6}, "Checks": list(checks)},
                                name="fw.json")
    return build(framework, account(bucket_policy), organization=None)


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
        "## Scope and limits",
    ]


def test_a_fail_cites_each_grant_and_how_the_principal_gets_it():
    lines = section(markdown(check("a", "only", MapsTo=["NIST AC-6"])), "Check a")
    assert lines[2] == f"Asked: Can anyone do s3:GetObject on {OBJECT}?"
    assert ("- user/teacher can. Granted by Read, Sid Read, through group Teachers." in lines)
    # A statement without a Sid is named by its place in its policy.
    assert "- user/reader can. Granted by Unnamed, statement 0, attached directly." in lines
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
    assert ("- Can't tell for everyone asked: nothing describes arn:aws:s3:::district-lesson-plans: "
            "it can have a resource-based policy, and the analyzer can't tell whether it has one, "
            "or which account it is in. Describe it in the account file's Resources, as {} if it "
            "has no resource-based policy.") in text


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
    assert ("- user/registrar can. Granted by the resource policy on "
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
    passed = report(check("a", "only", Principals=["group/Teachers", "user/reader", "role/Admin"]))
    assert (passed.failed, passed.unsettled) == (False, False)
    depends = report(check("a", "can", Principals=["user/registrar"], Actions=["s3:PutObject"]))
    assert (depends.failed, depends.unsettled) == (False, True)
    failed = report(check("a", "only"), check("b", "only", Resources=[LESSONS]))
    assert (failed.failed, failed.unsettled) == (True, True)
