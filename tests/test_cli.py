from pathlib import Path

import pytest

from iam_analyzer.cli import EXIT_ALLOWED, EXIT_DENIED, EXIT_INPUT_ERROR, main

POLICIES = Path(__file__).parent.parent / "examples" / "policies"
TEACHER = str(POLICIES / "teacher_read_grades.json")
NO_DELETE = str(POLICIES / "deny_student_records_delete.json")
IT_ADMIN = str(POLICIES / "it_admin_full_s3.json")
VENDOR_BOUNDARY = str(POLICIES / "gradebook_vendor_boundary.json")
ROSTER = "arn:aws:s3:::district-student-records/2026/roster.csv"


def run(capsys, *args):
    code = main(["check", *args])
    out, err = capsys.readouterr()
    return code, out, err


def test_explicit_deny(capsys):
    code, out, _ = run(
        capsys, "--policy", TEACHER, "--policy", NO_DELETE,
        "--action", "s3:DeleteObject", "--resource", ROSTER,
    )
    assert code == EXIT_DENIED
    assert out.splitlines()[0] == "EXPLICIT_DENY"
    assert "deny_student_records_delete.json" in out
    assert "Sid=NoDeleteStudentRecords" in out


def test_allow(capsys):
    code, out, _ = run(
        capsys, "--policy", TEACHER, "--policy", NO_DELETE,
        "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_ALLOWED
    assert out.splitlines()[0] == "ALLOW"
    assert "Sid=ReadStudentRecords" in out


def test_implicit_deny(capsys):
    code, out, _ = run(
        capsys, "--policy", TEACHER, "--action", "iam:CreateUser", "--resource", "*",
    )
    assert code == EXIT_DENIED
    assert out.splitlines()[0] == "IMPLICIT_DENY"
    assert "denied by default" in out


def test_missing_policy_file(capsys, tmp_path):
    code, out, err = run(
        capsys, "--policy", str(tmp_path / "missing.json"),
        "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert "cannot read file" in err


def test_unsupported_policy(capsys, tmp_path):
    path = tmp_path / "conditional.json"
    path.write_text(
        '{"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*",'
        ' "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}'
    )
    code, _, err = run(
        capsys, "--policy", str(path), "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_INPUT_ERROR
    assert "'Condition' is not supported yet" in err


def test_missing_required_argument_exits_with_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["check", "--policy", TEACHER, "--action", "s3:GetObject"])
    assert exc.value.code == 2


# --- Account mode ----------------------------------------------------------------------

ACCOUNT = str(Path(__file__).parent.parent / "examples" / "accounts" / "district.json")
ORG = str(Path(__file__).parent.parent / "examples" / "organizations" / "district.json")


def test_account_allow_shows_group(capsys):
    code, out, _ = run(
        capsys, "--account", ACCOUNT, "--principal", "user/jsmith",
        "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_ALLOWED
    assert out.splitlines()[0] == "ALLOW"
    assert "TeacherReadGrades (via group Teachers)  Sid=ReadStudentRecords" in out


def test_account_explicit_deny_inherited_through_group(capsys):
    code, out, _ = run(
        capsys, "--account", ACCOUNT, "--principal", "user/jsmith",
        "--action", "s3:DeleteObject", "--resource", ROSTER,
    )
    assert code == EXIT_DENIED
    assert out.splitlines()[0] == "EXPLICIT_DENY"
    assert "DenyStudentRecordsDelete (via group Teachers)" in out


def test_account_direct_policy_has_no_group_suffix(capsys):
    code, out, _ = run(
        capsys, "--account", ACCOUNT, "--principal", "user/alee",
        "--action", "s3:PutObject", "--resource", ROSTER,
    )
    assert code == EXIT_ALLOWED
    assert "ITAdminFullS3  Sid=FullS3Access" in out
    assert "via group" not in out


def test_account_unknown_principal(capsys):
    code, out, err = run(
        capsys, "--account", ACCOUNT, "--principal", "user/nobody",
        "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert "no user named 'nobody'" in err


@pytest.mark.parametrize(
    "args",
    [
        ["--account", ACCOUNT],  # no --principal
        ["--policy", TEACHER, "--principal", "user/jsmith"],  # --principal without --account
        ["--policy", TEACHER, "--account", ACCOUNT, "--principal", "user/jsmith"],  # both sources
        ["--account", ACCOUNT, "--principal", "user/jsmith", "--boundary", VENDOR_BOUNDARY],
        ["--policy", TEACHER, "--org", ORG],  # --org needs --account
    ],
)
def test_account_argument_misuse_exits_with_usage_error(args):
    with pytest.raises(SystemExit) as exc:
        main(["check", *args, "--action", "s3:GetObject", "--resource", ROSTER])
    assert exc.value.code == 2


# --- Permissions boundaries ------------------------------------------------------------


def test_boundary_blocks_what_identity_allows(capsys):
    code, out, _ = run(
        capsys, "--policy", IT_ADMIN, "--boundary", VENDOR_BOUNDARY,
        "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_DENIED
    assert out.splitlines() == ["IMPLICIT_DENY", "  The permissions boundary does not allow this."]


def test_boundary_allow_lists_both_layers(capsys):
    code, out, _ = run(
        capsys, "--policy", IT_ADMIN, "--boundary", VENDOR_BOUNDARY,
        "--action", "s3:PutObject", "--resource", "arn:aws:s3:::district-gradebook-app/grades.csv",
    )
    assert code == EXIT_ALLOWED
    assert out.splitlines() == [
        "ALLOW",
        "  Allow  it_admin_full_s3.json  Sid=FullS3Access",
        "  Allow  gradebook_vendor_boundary.json (permissions boundary)  Sid=GradebookAppBucketOnly",
    ]


def test_boundary_deny_is_explicit(capsys):
    code, out, _ = run(
        capsys, "--policy", IT_ADMIN, "--boundary", VENDOR_BOUNDARY,
        "--action", "s3:DeleteBucket", "--resource", "arn:aws:s3:::district-gradebook-app",
    )
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "EXPLICIT_DENY",
        "  Deny   gradebook_vendor_boundary.json (permissions boundary)  Sid=NoBucketDeletion",
    ]


def test_account_boundary_limits_group_policies(capsys):
    campus = "arn:aws:s3:::district-student-records/{}/grades.csv"
    args = ["--account", ACCOUNT, "--principal", "user/dpatel", "--action", "s3:GetObject"]

    code, out, _ = run(capsys, *args, "--resource", campus.format("campus-01"))
    assert code == EXIT_ALLOWED
    assert "TeacherReadGrades (via group Teachers)  Sid=ReadStudentRecords" in out
    assert "StudentTeacherBoundary (permissions boundary)  Sid=Campus01RecordsOnly" in out

    code, out, _ = run(capsys, *args, "--resource", campus.format("campus-02"))
    assert code == EXIT_DENIED
    assert out.splitlines() == ["IMPLICIT_DENY", "  The permissions boundary does not allow this."]


# --- Organizations and SCPs ------------------------------------------------------------


def test_scp_deny_overrides_identity_allow(capsys):
    args = [
        "--account", ACCOUNT, "--principal", "role/ITAdmin",
        "--action", "s3:PutBucketPolicy", "--resource", "arn:aws:s3:::district-student-records",
    ]
    code, _, _ = run(capsys, *args)
    assert code == EXIT_ALLOWED  # IAM alone allows it
    code, out, _ = run(capsys, *args, "--org", ORG)
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "EXPLICIT_DENY",
        "  Deny   ProtectStudentRecords (SCP on OU Schools)  Sid=NoDeletesOrPolicyChanges",
    ]


def test_scp_allow_list_blocks_unlisted_service(capsys):
    args = [
        "--account", ACCOUNT, "--principal", "user/alee",
        "--action", "ec2:DescribeInstances", "--resource", "*",
    ]
    code, _, _ = run(capsys, *args)
    assert code == EXIT_ALLOWED
    code, out, _ = run(capsys, *args, "--org", ORG)
    assert code == EXIT_DENIED
    assert out.splitlines() == ["IMPLICIT_DENY", "  No SCP attached to OU Schools allows this."]


def test_scp_allows_are_listed_for_every_level(capsys):
    code, out, _ = run(
        capsys, "--account", ACCOUNT, "--org", ORG, "--principal", "user/jsmith",
        "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_ALLOWED
    assert out.splitlines() == [
        "ALLOW",
        "  Allow  TeacherReadGrades (via group Teachers)  Sid=ReadStudentRecords",
        "  Allow  FullAWSAccess (SCP on the root)  Sid=(no Sid)",
        "  Allow  SchoolServicesOnly (SCP on OU Schools)  Sid=AllowApprovedServices",
        "  Allow  FullAWSAccess (SCP on account 111122223333)  Sid=(no Sid)",
    ]


def test_org_needs_account_id(capsys, tmp_path):
    path = tmp_path / "no_id.json"
    path.write_text('{"Policies": {}, "Users": {"u": {}}}')
    code, out, err = run(
        capsys, "--account", str(path), "--org", ORG, "--principal", "user/u",
        "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert "needs an 'AccountId'" in err


def test_account_missing_from_org(capsys, tmp_path):
    path = tmp_path / "other.json"
    path.write_text('{"AccountId": "444455556666", "Policies": {}, "Users": {"u": {}}}')
    code, _, err = run(
        capsys, "--account", str(path), "--org", ORG, "--principal", "user/u",
        "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_INPUT_ERROR
    assert "no account '444455556666'" in err
