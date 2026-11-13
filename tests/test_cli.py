import json
from pathlib import Path

import pytest

from iam_analyzer.cli import (
    EXIT_ALLOWED,
    EXIT_DENIED,
    EXIT_FAILED,
    EXIT_INPUT_ERROR,
    EXIT_PASSED,
    EXIT_UNSETTLED,
    main,
)

POLICIES = Path(__file__).parent.parent / "examples" / "policies"
TEACHER = str(POLICIES / "teacher_read_grades.json")
NO_DELETE = str(POLICIES / "deny_student_records_delete.json")
IT_ADMIN = str(POLICIES / "it_admin_full_s3.json")
VENDOR_BOUNDARY = str(POLICIES / "gradebook_vendor_boundary.json")
ROSTER = "arn:aws:s3:::district-student-records/2026/roster.csv"
# With --policy, a request on a specific resource needs it described.
NO_RESOURCE_POLICY = "--no-resource-policy"


def run(capsys, *args):
    code = main(["check", *args])
    out, err = capsys.readouterr()
    return code, out, err


def test_explicit_deny(capsys):
    code, out, _ = run(
        capsys, "--policy", TEACHER, "--policy", NO_DELETE, NO_RESOURCE_POLICY,
        "--action", "s3:DeleteObject", "--resource", ROSTER,
    )
    assert code == EXIT_DENIED
    assert out.splitlines()[0] == "EXPLICIT_DENY"
    assert "deny_student_records_delete.json" in out
    assert "Sid=NoDeleteStudentRecords" in out


def test_allow(capsys):
    code, out, _ = run(
        capsys, "--policy", TEACHER, "--policy", NO_DELETE, NO_RESOURCE_POLICY,
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
    args = ["--policy", TEACHER, "--policy", str(path), NO_RESOURCE_POLICY,
            "--action", "s3:GetObject", "--resource", ROSTER]
    code, out, _ = run(capsys, *args, "--context", "aws:SecureTransport=false")
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "EXPLICIT_DENY",
        "  Deny   https_only.json  Sid=HttpsOnly",
        "         Bool aws:SecureTransport: false (request: false)",
        "  The Deny overrides:",
        "  Allow  teacher_read_grades.json  Sid=ReadStudentRecords",
        "  Without this Deny, the request would be allowed.",
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
        capsys, "--policy", IT_ADMIN, "--boundary", VENDOR_BOUNDARY, NO_RESOURCE_POLICY,
        "--action", "s3:GetObject", "--resource", ROSTER,
    )
    assert code == EXIT_DENIED
    assert out.splitlines() == ["IMPLICIT_DENY", "  The permissions boundary does not allow this."]


def test_boundary_allow_lists_both_layers(capsys):
    code, out, _ = run(
        capsys, "--policy", IT_ADMIN, "--boundary", VENDOR_BOUNDARY, NO_RESOURCE_POLICY,
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
        capsys, "--policy", IT_ADMIN, "--boundary", VENDOR_BOUNDARY, NO_RESOURCE_POLICY,
        "--action", "s3:DeleteBucket", "--resource", "arn:aws:s3:::district-gradebook-app",
    )
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "EXPLICIT_DENY",
        "  Deny   gradebook_vendor_boundary.json (permissions boundary)  Sid=NoBucketDeletion",
        # The boundary's own Allow covers the bucket, so the identity policy's Allow is overridden.
        "  The Deny overrides:",
        "  Allow  it_admin_full_s3.json  Sid=FullS3Access",
        "  Without this Deny, the request would be allowed.",
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
    # A grant to dpatel in the bucket policy would have been the other way in.
    assert out.splitlines() == [
        "IMPLICIT_DENY",
        "  The permissions boundary does not allow this.",
        "  The resource-based policy on arn:aws:s3:::district-student-records does not allow "
        "this either.",
    ]


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
        "  The Deny overrides:",
        "  Allow  ITAdminFullS3  Sid=FullS3Access",
        "  Without this Deny, the request would be allowed.",
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
        "  Allow  FullAWSAccess (SCP on the root)  statement 0",
        "  Allow  SchoolServicesOnly (SCP on OU Schools)  Sid=AllowApprovedServices",
        "  Allow  FullAWSAccess (SCP on account 111122223333)  statement 0",
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
    path = account_file(tmp_path, {"AccountId": "111122223333",
                                   "Policies": {"ChangeOwnPassword": OWN_PASSWORD},
                                   "Users": {"jsmith": {"Policies": ["ChangeOwnPassword"]}}})
    args = ["--account", path, "--principal", "user/jsmith", "--action", "iam:ChangePassword"]
    code, _, _ = run(capsys, *args, "--resource", "arn:aws:iam::111122223333:user/jsmith")
    assert code == EXIT_ALLOWED
    code, _, _ = run(capsys, *args, "--resource", "arn:aws:iam::111122223333:user/alee")
    assert code == EXIT_DENIED


def test_an_explicit_deny_lists_the_allows_it_overrides(capsys):
    args = ["--account", ACCOUNT, "--org", ORG, "--action", "s3:DeleteObject",
            "--resource", "arn:aws:s3:::district-student-records/campus-02/transcript.pdf"]
    code, out, _ = run(capsys, *args, "--principal", "user/alee")
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "EXPLICIT_DENY",
        "  Deny   DenyStudentRecordsDelete (via group ITStaff)  Sid=NoDeleteStudentRecords",
        "  Deny   ProtectStudentRecords (SCP on OU Schools)  Sid=NoDeletesOrPolicyChanges",
        # FullAWSAccess and SchoolServicesOnly allow it too, but SCPs only limit.
        "  The Denies override:",
        "  Allow  ITAdminFullS3  Sid=FullS3Access",
        "  Without these Denies, the request would be allowed.",
    ]
    # A teacher has no Allow for deleting, so the Denies override nothing, and without them the
    # request would still be denied.
    code, out, _ = run(capsys, *args, "--principal", "user/jsmith")
    assert code == EXIT_DENIED
    assert "override" not in out
    assert out.splitlines()[-3:] == [
        "  Without these Denies, the request would still be denied:",
        "    No identity policy allows this; access is denied by default.",
        "    The resource-based policy on arn:aws:s3:::district-student-records does not allow "
        "this either.",
    ]


def test_without_the_deny_the_analyzer_can_say_it_cant_tell(capsys, tmp_path):
    # The trust policy names the user directly, and the user's boundary doesn't allow
    # sts:AssumeRole. AWS's docs disagree on what that gives, so only the Deny is settled.
    path = account_file(tmp_path, {
        "AccountId": "111122223333",
        "Policies": {
            "NoAssume": {"Statement": [{"Sid": "NoAssume", "Effect": "Deny",
                                        "Action": "sts:AssumeRole", "Resource": "*"}]},
            "S3Only": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        },
        "Users": {"it": {"Policies": ["NoAssume"], "PermissionsBoundary": "S3Only"}},
        "Roles": {"Admin": {"AssumeRolePolicyDocument": {"Statement": [{
            "Sid": "Direct", "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111122223333:user/it"},
            "Action": "sts:AssumeRole"}]}}},
    })
    code, out, _ = run(capsys, "--account", path, "--principal", "user/it",
                       "--action", "sts:AssumeRole",
                       "--resource", "arn:aws:iam::111122223333:role/Admin")
    assert code == EXIT_DENIED
    assert out.splitlines()[-1].startswith(
        "  Without this Deny, the analyzer can't tell whether the request would be allowed: the "
        "trust policy names the caller directly, and the caller's permissions boundary")


def test_deny_with_a_policy_variable_applies_to_the_caller(capsys, tmp_path):
    # Matched as literal text, this Deny would never apply and the request would be allowed.
    path = account_file(tmp_path, {
        "AccountId": "111122223333",
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
    assert out.splitlines() == ["EXPLICIT_DENY", "  Deny   NoSelfDelete  statement 0",
                                "  The Deny overrides:", "  Allow  AdminAll  statement 0",
                                "  Without this Deny, the request would be allowed."]


def test_a_role_has_no_user_name(capsys, tmp_path):
    # So ${aws:username} has no value, and the resource with it matches nothing.
    path = account_file(tmp_path, {"AccountId": "111122223333",
                                   "Policies": {"ChangeOwnPassword": OWN_PASSWORD},
                                   "Roles": {"Helper": {"Policies": ["ChangeOwnPassword"]}}})
    code, out, _ = run(capsys, "--account", path, "--principal", "role/Helper",
                       "--action", "iam:ChangePassword",
                       "--resource", "arn:aws:iam::111122223333:user/jsmith")
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "IMPLICIT_DENY", "  No identity policy allows this; access is denied by default."
    ]


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


def test_a_statement_without_a_sid_is_named_by_its_position(capsys, tmp_path):
    # As in a report: the second statement of Mixed is "statement 1".
    path = account_file(tmp_path, {
        "Policies": {"Mixed": {"Statement": [
            {"Sid": "Logs", "Effect": "Allow", "Action": "logs:GetLogEvents", "Resource": "*"},
            {"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}]}},
        "Users": {"psantos": {"Policies": ["Mixed"]}},
    })
    code, out, _ = run(capsys, "--account", path, "--principal", "user/psantos",
                       "--action", "ec2:DescribeInstances", "--resource", "*")
    assert code == EXIT_ALLOWED
    assert out.splitlines() == ["ALLOW", "  Allow  Mixed  statement 1"]


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
    assert out.splitlines() == ["ALLOW", "  Allow  SupportPermissions  statement 0"]


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
    code, out, err = run(capsys, "--policy", HOME_FOLDER, NO_RESOURCE_POLICY,
                         "--action", "s3:PutObject", "--resource", LESSON)
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert err.splitlines() == [
        "error: the request context says nothing about these condition keys:",
        "  aws:username, used by staff_home_folder.json statement 0 (Sid=OwnHomeFolder)",
        "hint: give each key a value with --context KEY=VALUE, or use --absent KEY if the "
        "request doesn't include it",
    ]


def test_context_gives_a_key_its_value(capsys):
    args = ["--policy", HOME_FOLDER, NO_RESOURCE_POLICY, "--action", "s3:PutObject",
            "--resource", LESSON]
    code, _, _ = run(capsys, *args, "--context", "aws:username=jsmith")
    assert code == EXIT_ALLOWED
    code, _, _ = run(capsys, *args, "--context", "aws:username=mgarcia")
    assert code == EXIT_DENIED


def test_an_absent_key_with_no_default_matches_nothing(capsys):
    code, out, _ = run(capsys, "--policy", HOME_FOLDER, NO_RESOURCE_POLICY,
                       "--action", "s3:PutObject", "--resource", LESSON, "--absent", "aws:username")
    assert code == EXIT_DENIED
    assert out.splitlines()[0] == "IMPLICIT_DENY"


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
    "Resources": {"arn:aws:s3:::district-student-records": {}},
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
        "  The Deny overrides:",
        "  Allow  RegistrarCampusRecords (via group Registrars)  Sid=ManageOwnCampusRecords",
        "  Without this Deny, the request would be allowed.",
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
    code, out, _ = run(capsys, "--policy", str(path), NO_RESOURCE_POLICY,
                       "--action", "s3:GetObject", "--resource", ROSTER,
                       "--context", "aws:SourceIp=10.1.2.3", "--context", "s3:prefix=")
    assert code == EXIT_ALLOWED
    assert out.splitlines() == [
        "ALLOW",
        "  Allow  district_network.json  Sid=DistrictNetwork",
        "         IpAddress aws:SourceIp: 10.0.0.0/8, 192.0.2.0/24 (request: 10.1.2.3)",
        '         StringLike s3:prefix: "" (request: "")',
    ]


# --- Describing resources --------------------------------------------------------------

NOTHING_DESCRIBES = (
    "error: nothing describes {}: it can have a resource-based policy, and the analyzer can't "
    "tell whether it has one, or which account it is in"
)


def test_policy_mode_needs_the_resource_described(capsys):
    code, out, err = run(capsys, "--policy", TEACHER, "--action", "s3:GetObject",
                         "--resource", ROSTER)
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert err.splitlines() == [
        NOTHING_DESCRIBES.format("arn:aws:s3:::district-student-records"),
        "hint: give its resource-based policy with --resource-policy FILE, or "
        "--no-resource-policy if it has none; either says it is in the same account",
    ]


def test_account_mode_names_an_undescribed_bucket(capsys):
    code, out, err = run(capsys, "--account", ACCOUNT, "--principal", "user/jsmith",
                         "--action", "s3:GetObject",
                         "--resource", "arn:aws:s3:::district-lesson-plans/week1.pdf")
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert err.splitlines() == [
        NOTHING_DESCRIBES.format("arn:aws:s3:::district-lesson-plans"),
        "hint: describe it in the account file's Resources, as {} if it has no resource-based "
        "policy",
    ]


def test_no_resource_policy_only_works_with_policy(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["check", "--account", ACCOUNT, "--principal", "user/jsmith", NO_RESOURCE_POLICY,
              "--action", "s3:GetObject", "--resource", ROSTER])
    assert exc.value.code == 2
    assert "--no-resource-policy only works with --policy" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        ["--account", ACCOUNT, "--principal", "user/jsmith", "--resource-policy", TEACHER],
        ["--policy", TEACHER, "--resource-policy", TEACHER, NO_RESOURCE_POLICY],
        ["--policy", TEACHER, "--resource-policy", TEACHER, "--resource-policy", TEACHER],
    ],
)
def test_resource_policy_flag_misuse_is_a_usage_error(args):
    with pytest.raises(SystemExit) as exc:
        main(["check", *args, "--action", "s3:GetObject", "--resource", ROSTER])
    assert exc.value.code == 2


def test_kms_requests_are_refused(capsys):
    key = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    code, out, err = run(capsys, "--policy", IT_ADMIN, NO_RESOURCE_POLICY,
                         "--action", "kms:Decrypt", "--resource", key)
    assert code == EXIT_INPUT_ERROR
    assert out == ""
    assert "KMS isn't supported yet: every KMS key has a key policy" in err


def test_an_iam_request_needs_the_principals_account(capsys):
    user = "arn:aws:iam::111122223333:user/jsmith"
    args = ["--policy", IT_ADMIN, "--action", "iam:GetUser", "--resource", user]
    code, _, err = run(capsys, *args)
    assert code == EXIT_INPUT_ERROR
    assert f"  aws:PrincipalAccount, used by the check that {user} is in the principal's" in err
    code, _, err = run(capsys, *args, "--context", "aws:PrincipalAccount=444455556666")
    assert code == EXIT_INPUT_ERROR
    assert "cross-account requests aren't supported yet" in err
    code, _, _ = run(capsys, *args, "--context", "aws:PrincipalAccount=111122223333")
    assert code == EXIT_DENIED  # the policy only allows S3


# --- Resource-based policies -----------------------------------------------------------

BUCKET_POLICY = str(POLICIES / "student_records_bucket_policy.json")
COUNSELING = "arn:aws:s3:::district-student-records/counseling/2026/notes.pdf"
RECORDS_BUCKET = "arn:aws:s3:::district-student-records"
KWONG_ARN = "arn:aws:iam::111122223333:user/kwong"


def test_a_bucket_policy_alone_lets_a_counselor_read(capsys):
    # kwong has no identity policies at all.
    code, out, _ = run(capsys, "--account", ACCOUNT, "--principal", "user/kwong",
                       "--action", "s3:GetObject", "--resource", COUNSELING)
    assert code == EXIT_ALLOWED
    assert out.splitlines() == [
        "ALLOW",
        f"  Allow  {RECORDS_BUCKET} (resource-based policy, names the user)  "
        "Sid=CounselorsReadCounselingNotes",
    ]


def test_others_need_their_identity_policies(capsys):
    code, out, _ = run(capsys, "--account", ACCOUNT, "--principal", "user/kwong",
                       "--action", "s3:GetObject", "--resource", ROSTER)
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "IMPLICIT_DENY",
        "  No identity policy allows this; access is denied by default.",
        f"  The resource-based policy on {RECORDS_BUCKET} does not allow this either.",
    ]


def test_a_bucket_policy_deny_shows_its_condition(capsys):
    code, out, _ = run(capsys, "--account", ACCOUNT, "--principal", "user/alee",
                       "--action", "s3:PutBucketPolicy", "--resource", RECORDS_BUCKET)
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "EXPLICIT_DENY",
        f"  Deny   {RECORDS_BUCKET} (resource-based policy, names everyone)  "
        "Sid=OnlyITAdminChangesThePolicy",
        "         ArnNotEquals aws:PrincipalArn: arn:aws:iam::111122223333:role/ITAdmin "
        "(request: arn:aws:iam::111122223333:user/alee)",
        "  The Deny overrides:",
        "  Allow  ITAdminFullS3  Sid=FullS3Access",
        "  Without this Deny, the request would be allowed.",
    ]


def test_policy_mode_reads_a_resource_policy_file(capsys):
    args = ["--policy", TEACHER, "--resource-policy", BUCKET_POLICY,
            "--action", "s3:GetObject", "--resource", COUNSELING]
    code, _, err = run(capsys, *args)
    assert code == EXIT_INPUT_ERROR
    assert ("  aws:PrincipalArn, used by student_records_bucket_policy.json statement 1 "
            "(Sid=CounselorsReadCounselingNotes)") in err
    code, out, _ = run(capsys, *args, "--context", f"aws:PrincipalArn={KWONG_ARN}")
    assert code == EXIT_ALLOWED
    assert out.splitlines() == [
        "ALLOW",
        "  Allow  teacher_read_grades.json  Sid=ReadStudentRecords",
        "  Allow  student_records_bucket_policy.json (resource-based policy on "
        f"{RECORDS_BUCKET}, names the user)  Sid=CounselorsReadCounselingNotes",
    ]


def test_a_resource_policy_for_a_request_that_none_covers(capsys):
    code, _, err = run(capsys, "--policy", TEACHER, "--resource-policy", BUCKET_POLICY,
                       "--action", "iam:GetUser", "--resource", "*")
    assert code == EXIT_INPUT_ERROR
    assert "no resource-based policy applies to iam:GetUser on *" in err


def test_only_bucket_policies_are_evaluated(capsys):
    queue = "arn:aws:sqs:us-east-1:111122223333:district-alerts"
    code, _, err = run(capsys, "--policy", TEACHER, "--resource-policy", BUCKET_POLICY,
                       "--action", "sqs:SendMessage", "--resource", queue)
    assert code == EXIT_INPUT_ERROR
    assert "only S3 bucket policies and role trust policies are evaluated" in err


# --- Trust policies --------------------------------------------------------------------

IT_ADMIN_ROLE = "arn:aws:iam::111122223333:role/ITAdmin"
TRUST_POLICY = str(POLICIES / "it_admin_trust_policy.json")


def assume_it_admin(capsys, principal, *flags):
    return run(capsys, "--account", ACCOUNT, "--principal", principal,
               "--action", "sts:AssumeRole", "--resource", IT_ADMIN_ROLE, *flags)


def test_it_staff_assume_the_admin_role_with_mfa(capsys):
    mfa = ["--context", "aws:MultiFactorAuthPresent=true"]
    code, out, _ = assume_it_admin(capsys, "user/alee", *mfa)
    assert code == EXIT_ALLOWED
    assert out.splitlines() == [
        "ALLOW",
        "  Allow  AssumeITAdminRole (via group ITStaff)  Sid=AssumeITAdmin",
        f"  Allow  {IT_ADMIN_ROLE} (trust policy, names the account)  Sid=AccountWithMfa",
        "         Bool aws:MultiFactorAuthPresent: true (request: true)",
    ]


def test_without_mfa_the_trust_policy_doesnt_allow(capsys):
    code, out, _ = assume_it_admin(capsys, "user/alee", "--absent", "aws:MultiFactorAuthPresent")
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "IMPLICIT_DENY",
        f"  The trust policy of {IT_ADMIN_ROLE} does not allow this.",
    ]
    code, _, err = assume_it_admin(capsys, "user/alee")
    assert code == EXIT_INPUT_ERROR
    assert (f"  aws:MultiFactorAuthPresent, used by {IT_ADMIN_ROLE} statement 0 "
            "(Sid=AccountWithMfa)") in err


def test_trusting_the_account_still_needs_an_identity_policy(capsys):
    code, out, _ = assume_it_admin(capsys, "user/jsmith", "--context",
                                   "aws:MultiFactorAuthPresent=true")
    assert code == EXIT_DENIED
    assert out.splitlines() == [
        "IMPLICIT_DENY",
        "  No identity policy allows this; access is denied by default.",
    ]


def test_a_role_without_a_trust_policy_in_the_file(capsys, tmp_path):
    path = account_file(tmp_path, {"AccountId": "111122223333", "Policies": {},
                                   "Users": {"u": {}}, "Roles": {"Helper": {}}})
    code, _, err = run(capsys, "--account", path, "--principal", "user/u",
                       "--action", "sts:AssumeRole",
                       "--resource", "arn:aws:iam::111122223333:role/Helper")
    assert code == EXIT_INPUT_ERROR
    assert err.splitlines() == [
        "error: nothing gives the trust policy of arn:aws:iam::111122223333:role/Helper, which "
        "every role has and which must allow this request",
        "hint: give the role its trust policy as AssumeRolePolicyDocument in the account file",
    ]


def test_a_saml_roles_tags_need_no_flag(capsys):
    # Only the district's SAML identity provider can assume TeacherSignIn, and its trust policy
    # doesn't allow sts:TagSession, so the role's own campus tag is all there is.
    args = ["--account", ACCOUNT, "--principal", "role/TeacherSignIn", "--action", "s3:GetObject"]
    record = "arn:aws:s3:::district-student-records/{}/grades.csv"
    code, out, _ = run(capsys, *args, "--resource", record.format("campus-01"))
    assert code == EXIT_ALLOWED
    assert out.splitlines() == ["ALLOW", "  Allow  CampusTeacherRecords  Sid=ReadOwnCampusRecords"]
    code, _, _ = run(capsys, *args, "--resource", record.format("campus-02"))
    assert code == EXIT_DENIED


def test_policy_mode_reads_a_trust_policy_file(capsys):
    args = ["--policy", IT_ADMIN, "--resource-policy", TRUST_POLICY,
            "--action", "sts:AssumeRole", "--resource", IT_ADMIN_ROLE,
            "--context", "aws:PrincipalArn=arn:aws:iam::111122223333:user/alee",
            "--context", "aws:MultiFactorAuthPresent=true"]
    code, out, _ = run(capsys, *args)
    assert code == EXIT_DENIED  # the trust policy trusts the account, but no identity policy allows
    assert out.splitlines()[1] == "  No identity policy allows this; access is denied by default."


def test_a_role_always_has_a_trust_policy(capsys):
    code, _, err = run(capsys, "--policy", IT_ADMIN, NO_RESOURCE_POLICY,
                       "--action", "sts:AssumeRole", "--resource", IT_ADMIN_ROLE)
    assert code == EXIT_INPUT_ERROR
    assert "every role has a trust policy that must allow this request" in err


# --- Compliance reports ----------------------------------------------------------------

REGISTRAR_RECORDS = "arn:aws:s3:::district-student-records/campus-02/transcript.pdf"


def framework_file(tmp_path, *checks):
    path = tmp_path / "fw.json"
    path.write_text(json.dumps({"Framework": {"Id": "fw", "Title": "Student records"},
                                "Checks": list(checks)}))
    return str(path)


def report_check(check_type, **fields):
    names = {"requires": {"Key": "aws:MultiFactorAuthPresent", "Value": "true"}}.get(
        check_type, {"Principals": []})
    return {"Id": "c", "Title": "A check", "Severity": "high", "Type": check_type,
            "Actions": ["s3:DeleteObject"], "Resources": [REGISTRAR_RECORDS], "Fix": "Fix it.",
            **names, **fields}


def private_account(tmp_path):
    """The district account without its public roster bucket, whose high finding would make every
    report exit 1."""
    document = json.loads(Path(ACCOUNT).read_text())
    del document["Resources"]["arn:aws:s3:::district-roster-exports"]
    path = tmp_path / "district.json"
    path.write_text(json.dumps(document))
    return str(path)


def report(capsys, framework, *args, account=None):
    code = main(["report", "--account", account or private_account(Path(framework).parent),
                 "--framework", framework, *args])
    out, err = capsys.readouterr()
    return code, out, err


@pytest.mark.parametrize("check, expected, heading", [
    (report_check("only"), EXIT_PASSED, "## PASS: A check (high)"),
    (report_check("only", Actions=["s3:GetObject"]), EXIT_FAILED, "## FAIL: A check (high)"),
    (report_check("can", Principals=["group/Registrars"], Actions=["s3:PutObject"]),
     EXIT_UNSETTLED, "## DEPENDS: A check (high)"),
    (report_check("only", Resources=["arn:aws:s3:::district-lesson-plans/week1.pdf"]),
     EXIT_UNSETTLED, "## CAN'T TELL: A check (high)"),
])
def test_report_exit_codes(capsys, tmp_path, check, expected, heading):
    code, out, err = report(capsys, framework_file(tmp_path, check), "--org", ORG)
    assert (code, err) == (expected, "")
    assert out.startswith("# Compliance report: Student records\n")
    assert heading in out.splitlines()


def test_report_writes_json_too(capsys, tmp_path):
    framework = framework_file(tmp_path, report_check("only", Actions=["s3:GetObject"]))
    json_path = tmp_path / "out" / "report.json"
    code, out, _ = report(capsys, framework, "--no-org", "--json", str(tmp_path / "report.json"))
    assert code == EXIT_FAILED
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["checks"][0]["result"] == "FAIL"
    assert data["organization"] is None
    assert "## FAIL: A check (high)" in out
    code, _, err = report(capsys, framework, "--no-org", "--json", str(json_path))
    assert code == EXIT_INPUT_ERROR
    assert "report.json: cannot write file" in err


def test_report_a_public_bucket_fails_the_district_report(capsys, tmp_path):
    code, out, _ = report(capsys, framework_file(tmp_path, report_check("only")), "--org", ORG,
                          account=ACCOUNT)
    assert code == EXIT_FAILED
    assert "## PASS: A check (high)" in out
    assert "### HIGH: A bucket policy grants access to everyone" in out


def test_report_the_anycompany_example_fails(capsys):
    examples = Path(__file__).parent.parent / "examples"
    code = main(["report", "--account", str(examples / "accounts" / "anycompany-production.json"),
                 "--org", str(examples / "organizations" / "anycompany.json"),
                 "--framework", str(examples / "frameworks" / "anycompany.json")])
    out, _ = capsys.readouterr()
    assert code == EXIT_FAILED
    assert out.startswith("# Compliance report: AnyCompany production access\n")


def test_report_needs_scps_stated(tmp_path):
    framework = framework_file(tmp_path, report_check("only"))
    with pytest.raises(SystemExit) as exc:
        main(["report", "--account", ACCOUNT, "--framework", framework])
    assert exc.value.code == EXIT_INPUT_ERROR
    with pytest.raises(SystemExit):
        main(["report", "--account", ACCOUNT, "--framework", framework, "--org", ORG, "--no-org"])


@pytest.mark.parametrize("check, message", [
    ({**report_check("only"), "Severity": "urgent"}, "'Severity' must be critical"),
    (report_check("only", Principals=["user/ghost"]), "no user 'ghost' in district.json"),
    (report_check("only", Context={"aws:username": "jsmith"}),
     "'aws:username' comes from district.json"),
])
def test_report_input_errors(capsys, tmp_path, check, message):
    code, out, err = report(capsys, framework_file(tmp_path, check), "--no-org")
    assert (code, out) == (EXIT_INPUT_ERROR, "")
    assert message in err


def test_report_a_high_finding_exits_like_a_fail(capsys, tmp_path):
    late = {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*",
            "Condition": {"DateLessThan": {"aws:CurrentTime": "2027"}}}
    account = account_file(tmp_path, {"Policies": {"Window": {"Statement": [late]}},
                                      "Users": {"u": {"Policies": ["Window"]}},
                                      "Resources": {"arn:aws:s3:::district-student-records": {}}})
    framework = framework_file(tmp_path, report_check("only"))
    code = main(["report", "--account", account, "--no-org", "--framework", framework])
    out, _ = capsys.readouterr()
    # The check alone would exit 3: the Deny needs aws:CurrentTime, which it doesn't give.
    assert code == EXIT_FAILED
    assert "## CAN'T TELL: A check (high)" in out
    assert "### HIGH: A four-digit date is read as epoch seconds" in out
