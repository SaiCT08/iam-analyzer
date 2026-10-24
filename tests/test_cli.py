import json
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


def test_conditional_deny(capsys, tmp_path):
    path = tmp_path / "https_only.json"
    path.write_text(
        '{"Statement": [{"Sid": "HttpsOnly", "Effect": "Deny", "Action": "*", "Resource": "*",'
        ' "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}'
    )
    args = ["--policy", TEACHER, "--policy", str(path), "--action", "s3:GetObject",
            "--resource", ROSTER]
    code, out, _ = run(capsys, *args, "--context", "aws:SecureTransport=false")
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "EXPLICIT_DENY",
        "  Deny   https_only.json  Sid=HttpsOnly",
        "         Bool aws:SecureTransport: false (request: false)",
    ]
    code, _, _ = run(capsys, *args, "--context", "aws:SecureTransport=true")
    assert code == EXIT_ALLOWED


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


# --- Input the analyzer refuses --------------------------------------------------------


def account_file(tmp_path, document):
    path = tmp_path / "acct.json"
    path.write_text(json.dumps(document))
    return str(path)


OWN_PASSWORD = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Action": "iam:ChangePassword",
    "Resource": "arn:aws:iam::*:user/${aws:username}"}]}


def test_aws_username_is_replaced_by_the_callers_name(capsys, tmp_path):
    # Review finding F1: AWS fills in ${aws:username} with "jsmith" and allows this.
    path = account_file(tmp_path, {"Policies": {"ChangeOwnPassword": OWN_PASSWORD},
                                   "Users": {"jsmith": {"Policies": ["ChangeOwnPassword"]}}})
    args = ["--account", path, "--principal", "user/jsmith", "--action", "iam:ChangePassword"]
    code, _, _ = run(capsys, *args, "--resource", "arn:aws:iam::111122223333:user/jsmith")
    assert code == EXIT_ALLOWED
    code, _, _ = run(capsys, *args, "--resource", "arn:aws:iam::111122223333:user/alee")
    assert code == EXIT_DENIED


def test_deny_with_a_policy_variable_applies_to_the_caller(capsys, tmp_path):
    # Matched as literal text, this Deny would never apply and the request would be allowed.
    path = account_file(tmp_path, {
        "Policies": {
            "AdminAll": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            "NoSelfDelete": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Deny", "Action": "iam:DeleteUser",
                "Resource": "arn:aws:iam::*:user/${aws:username}"}]},
        },
        "Users": {"alee": {"Policies": ["AdminAll", "NoSelfDelete"]}},
    })
    code, out, _ = run(capsys, "--account", path, "--principal", "user/alee",
                       "--action", "iam:DeleteUser",
                       "--resource", "arn:aws:iam::111122223333:user/alee")
    assert code == EXIT_DENIED
    assert out.splitlines() == ["EXPLICIT_DENY", "  Deny   NoSelfDelete  Sid=(no Sid)"]


def test_a_role_has_no_user_name(capsys, tmp_path):
    # AWS's docs disagree on a variable with no value, so the analyzer refuses.
    path = account_file(tmp_path, {"Policies": {"ChangeOwnPassword": OWN_PASSWORD},
                                   "Roles": {"Helper": {"Policies": ["ChangeOwnPassword"]}}})
    code, out, err = run(capsys, "--account", path, "--principal", "role/Helper",
                         "--action", "iam:ChangePassword",
                         "--resource", "arn:aws:iam::111122223333:user/jsmith")
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert "ChangeOwnPassword statement 0: policy variable '${aws:username}' has no value" in err


def test_wildcard_action_is_refused(capsys):
    # s3:DeleteObject on the roster is an EXPLICIT_DENY, so "s3:*" must not come back ALLOW.
    code, out, err = run(
        capsys, "--policy", IT_ADMIN, "--policy", NO_DELETE,
        "--action", "s3:*", "--resource", ROSTER,
    )
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert "the action must be one AWS action such as 's3:GetObject'" in err


@pytest.mark.parametrize(
    "args",
    [
        ["--policy", IT_ADMIN, "--boundary", VENDOR_BOUNDARY, "--boundary", IT_ADMIN],
        ["--policy", IT_ADMIN, "--resource", ROSTER],  # --resource is given again below
        ["--account", ACCOUNT, "--account", ACCOUNT, "--principal", "user/jsmith"],
        ["--account", ACCOUNT, "--principal", "user/jsmith", "--principal", "user/alee"],
    ],
)
def test_single_value_options_cannot_be_repeated(args, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["check", *args, "--action", "s3:GetObject", "--resource", ROSTER])
    assert exc.value.code == 2
    assert "can only be given once" in capsys.readouterr().err


# --- Service-linked roles --------------------------------------------------------------


def support_role_account(tmp_path, role):
    """An account in the example organization's Schools OU, whose allow-list SCP leaves out EC2."""
    return account_file(tmp_path, {
        "AccountId": "111122223333",
        "Policies": {"SupportPermissions": {"Statement": [
            {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}},
        "Roles": {"AWSServiceRoleForSupport": {"Policies": ["SupportPermissions"], **role}},
    })


def test_scps_do_not_apply_to_service_linked_roles(capsys, tmp_path):
    path = support_role_account(tmp_path, {"Path": "/aws-service-role/support.amazonaws.com/"})
    code, out, _ = run(capsys, "--account", path, "--org", ORG,
                       "--principal", "role/AWSServiceRoleForSupport",
                       "--action", "ec2:DescribeInstances", "--resource", "*")
    assert code == EXIT_ALLOWED
    assert out.splitlines() == ["ALLOW", "  Allow  SupportPermissions  Sid=(no Sid)"]


def test_a_service_linked_name_without_the_path_still_gets_scps(capsys, tmp_path):
    path = support_role_account(tmp_path, {})
    code, out, _ = run(capsys, "--account", path, "--org", ORG,
                       "--principal", "role/AWSServiceRoleForSupport",
                       "--action", "ec2:DescribeInstances", "--resource", "*")
    assert code == EXIT_DENIED
    assert out.splitlines() == ["IMPLICIT_DENY", "  No SCP attached to OU Schools allows this."]


# --- The request context ---------------------------------------------------------------

HOME_FOLDER = str(POLICIES / "staff_home_folder.json")
LESSON = "arn:aws:s3:::district-staff-files/home/jsmith/lesson-plan.docx"


def test_policy_mode_names_a_missing_key(capsys):
    code, out, err = run(capsys, "--policy", HOME_FOLDER, "--action", "s3:PutObject",
                         "--resource", LESSON)
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert err.splitlines() == [
        "error: the request context says nothing about these condition keys:",
        "  aws:username, used by staff_home_folder.json statement 0 (Sid=OwnHomeFolder)",
        "hint: give each key a value with --context KEY=VALUE, or use --absent KEY if the "
        "request doesn't include it",
    ]


def test_context_gives_a_key_its_value(capsys):
    args = ["--policy", HOME_FOLDER, "--action", "s3:PutObject", "--resource", LESSON]
    code, _, _ = run(capsys, *args, "--context", "aws:username=jsmith")
    assert code == EXIT_ALLOWED
    code, _, _ = run(capsys, *args, "--context", "aws:username=mgarcia")
    assert code == EXIT_DENIED


def test_absent_key_with_no_default_is_refused(capsys):
    code, _, err = run(capsys, "--policy", HOME_FOLDER, "--action", "s3:PutObject",
                       "--resource", LESSON, "--absent", "aws:username")
    assert code == EXIT_INPUT_ERROR
    assert "policy variable '${aws:username}' has no value in this request" in err


@pytest.mark.parametrize("value", ["aws:username", "=jsmith"])
def test_context_needs_key_and_value(value, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["check", "--policy", HOME_FOLDER, "--action", "s3:PutObject",
              "--resource", LESSON, "--context", value])
    assert exc.value.code == 2
    assert "expected KEY=VALUE" in capsys.readouterr().err


def test_no_session_tags_needs_an_account():
    with pytest.raises(SystemExit) as exc:
        main(["check", "--policy", HOME_FOLDER, "--no-session-tags",
              "--action", "s3:PutObject", "--resource", LESSON])
    assert exc.value.code == 2


def test_context_cannot_change_what_the_account_file_says(capsys):
    code, _, err = run(capsys, "--account", ACCOUNT, "--principal", "user/jsmith",
                       "--action", "s3:GetObject", "--resource", ROSTER,
                       "--context", "aws:username=alee")
    assert code == EXIT_INPUT_ERROR
    assert "'aws:username' comes from district.json user/jsmith, so it can't also be given" in err


def test_a_users_tag_fills_in_a_policy_variable(capsys):
    # Registrar rnguyen is tagged campus=campus-02.
    record = "arn:aws:s3:::district-student-records/{}/transcript.pdf"
    args = ["--account", ACCOUNT, "--principal", "user/rnguyen", "--action", "s3:GetObject"]
    code, out, _ = run(capsys, *args, "--resource", record.format("campus-02"))
    assert code == EXIT_ALLOWED
    assert out.splitlines() == [
        "ALLOW",
        "  Allow  RegistrarCampusRecords (via group Registrars)  Sid=ManageOwnCampusRecords",
    ]
    code, _, _ = run(capsys, *args, "--resource", record.format("campus-01"))
    assert code == EXIT_DENIED


# Session tags can override a role's own tags, so a role's tags aren't known by default.
TAGGED_ROLE = {
    "Policies": {"CampusRecords": {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::district-student-records/${aws:PrincipalTag/campus}/*"}]}},
    "Roles": {"CampusApp": {"Policies": ["CampusRecords"],
                            "Tags": [{"Key": "campus", "Value": "campus-01"}]}},
}


def campus_app(capsys, tmp_path, campus, *flags):
    return run(capsys, "--account", account_file(tmp_path, TAGGED_ROLE),
               "--principal", "role/CampusApp", "--action", "s3:GetObject",
               "--resource", f"arn:aws:s3:::district-student-records/{campus}/grades.csv", *flags)


def test_a_roles_tags_are_unknown_because_of_session_tags(capsys, tmp_path):
    code, _, err = campus_app(capsys, tmp_path, "campus-01")
    assert code == EXIT_INPUT_ERROR
    assert "  aws:PrincipalTag/campus, used by CampusRecords statement 0" in err


def test_a_session_tag_can_be_given(capsys, tmp_path):
    flags = ["--context", "aws:PrincipalTag/campus=campus-02"]
    assert campus_app(capsys, tmp_path, "campus-02", *flags)[0] == EXIT_ALLOWED
    assert campus_app(capsys, tmp_path, "campus-01", *flags)[0] == EXIT_DENIED


def test_no_session_tags_uses_the_roles_own_tags(capsys, tmp_path):
    assert campus_app(capsys, tmp_path, "campus-01", "--no-session-tags")[0] == EXIT_ALLOWED
    code, _, err = campus_app(capsys, tmp_path, "campus-02", "--no-session-tags",
                              "--context", "aws:PrincipalTag/campus=campus-02")
    assert code == EXIT_INPUT_ERROR
    assert "'aws:PrincipalTag/campus' comes from acct.json role/CampusApp" in err


def test_a_roles_own_tag_cannot_be_absent(capsys, tmp_path):
    code, _, err = campus_app(capsys, tmp_path, "campus-01", "--absent", "aws:PrincipalTag/Campus")
    assert code == EXIT_INPUT_ERROR
    assert ("'aws:PrincipalTag/Campus' can't be absent: role/CampusApp has this tag, and "
            "session tags can override a role's tags but not remove them") in err


# --- Conditions ------------------------------------------------------------------------


def test_registrar_changes_need_mfa(capsys):
    # The Deny uses BoolIfExists, so it also blocks requests made with access keys, which
    # don't include aws:MultiFactorAuthPresent at all.
    args = ["--account", ACCOUNT, "--principal", "user/rnguyen", "--action", "s3:PutObject",
            "--resource", "arn:aws:s3:::district-student-records/campus-02/transcript.pdf"]
    code, _, err = run(capsys, *args)
    assert code == EXIT_INPUT_ERROR
    assert ("  aws:MultiFactorAuthPresent, used by RegistrarCampusRecords statement 1 "
            "(Sid=RequireMfaForChanges)") in err

    code, out, _ = run(capsys, *args, "--absent", "aws:MultiFactorAuthPresent")
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "EXPLICIT_DENY",
        "  Deny   RegistrarCampusRecords (via group Registrars)  Sid=RequireMfaForChanges",
        "         BoolIfExists aws:MultiFactorAuthPresent: false (request: not present)",
    ]

    code, out, _ = run(capsys, *args, "--context", "aws:MultiFactorAuthPresent=true")
    assert code == EXIT_ALLOWED
    assert out.splitlines() == [
        "ALLOW",
        "  Allow  RegistrarCampusRecords (via group Registrars)  Sid=ManageOwnCampusRecords",
    ]


def test_allow_reasons_show_their_conditions(capsys, tmp_path):
    path = tmp_path / "district_network.json"
    path.write_text(json.dumps({"Statement": [{
        "Sid": "DistrictNetwork", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
        "Condition": {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.0.2.0/24"]},
                      "StringLike": {"s3:prefix": ""}}}]}))
    code, out, _ = run(capsys, "--policy", str(path), "--action", "s3:GetObject",
                       "--resource", ROSTER, "--context", "aws:SourceIp=10.1.2.3",
                       "--context", "s3:prefix=")
    assert code == EXIT_ALLOWED
    assert out.splitlines() == [
        "ALLOW",
        "  Allow  district_network.json  Sid=DistrictNetwork",
        "         IpAddress aws:SourceIp: 10.0.0.0/8, 192.0.2.0/24 (request: 10.1.2.3)",
        '         StringLike s3:prefix: "" (request: "")',
    ]
