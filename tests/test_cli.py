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
