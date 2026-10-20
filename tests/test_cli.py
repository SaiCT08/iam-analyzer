from pathlib import Path

import pytest

from iam_analyzer.cli import EXIT_ALLOWED, EXIT_DENIED, EXIT_INPUT_ERROR, main

POLICIES = Path(__file__).parent.parent / "examples" / "policies"
TEACHER = str(POLICIES / "teacher_read_grades.json")
NO_DELETE = str(POLICIES / "deny_student_records_delete.json")
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
    ],
)
def test_account_argument_misuse_exits_with_usage_error(args):
    with pytest.raises(SystemExit) as exc:
        main(["check", *args, "--action", "s3:GetObject", "--resource", ROSTER])
    assert exc.value.code == 2
