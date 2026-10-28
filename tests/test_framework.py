import json

import pytest

from iam_analyzer.errors import FrameworkError
from iam_analyzer.framework import (
    CheckType,
    Requirement,
    Severity,
    load_framework_file,
    parse_framework,
)

NOTES = "arn:aws:s3:::district-student-records/counseling/2026/notes.pdf"
ADMIN = "arn:aws:iam::111122223333:role/ITAdmin"
AC_6 = {"Framework": "NIST SP 800-53 Rev. 5", "Id": "AC-6", "Title": "Least Privilege",
        "Link": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"}


def only(**fields):
    return {"Id": "notes", "Title": "Only counselors can read counseling notes",
            "Severity": "high", "Type": "only", "Principals": ["user/kwong"],
            "Actions": ["s3:GetObject"], "Resources": [NOTES], "Fix": "Narrow the reads.",
            **fields}


def requires(**fields):
    return {"Id": "mfa", "Title": "Assuming the admin role needs MFA", "Severity": "high",
            "Type": "requires", "Key": "aws:MultiFactorAuthPresent", "Value": "true",
            "Actions": ["sts:AssumeRole"], "Resources": [ADMIN], "Fix": "Require MFA.", **fields}


def document(*checks, **sections):
    return {"Framework": {"Id": "district", "Title": "District records"},
            "Requirements": {"NIST AC-6": AC_6}, "Checks": list(checks), **sections}


def parse(*checks, **sections):
    return parse_framework(document(*checks, **sections), name="fw.json")


def test_a_framework_reads_its_checks():
    framework = parse(only(MapsTo=["NIST AC-6"]), requires(Except=["role/BreakGlass"]))
    assert (framework.id, framework.title) == ("district", "District records")
    notes, mfa = framework.checks
    assert notes.type is CheckType.ONLY and notes.type.forbids
    assert notes.severity is Severity.HIGH
    assert notes.principals == ("user/kwong",)
    assert notes.maps_to == (Requirement(**{k.lower(): v for k, v in AC_6.items()}),)
    assert (mfa.key, mfa.value, mfa.exempt) == ("aws:MultiFactorAuthPresent", "true",
                                                ("role/BreakGlass",))


def test_a_can_check_expects_access():
    framework = parse({**only(), "Type": "can", "Principals": ["group/Counselors"]})
    assert not framework.checks[0].type.forbids


def test_context_gives_values_lists_and_absent_keys():
    context = parse(only(Context={
        "aws:SourceIp": "203.0.113.5", "aws:TagKeys": ["grade", "campus"],
        "aws:MultiFactorAuthPresent": None,
    })).checks[0].context
    assert context.get("aws:SourceIp") == ("203.0.113.5",)
    assert context.get("aws:TagKeys") == ("grade", "campus")
    assert context.get("aws:MultiFactorAuthPresent") is None
    assert not context.knows("aws:SecureTransport")


def test_a_requires_key_is_spelled_as_aws_documents_it():
    check = parse(requires(Key="AWS:SecureTransport")).checks[0]
    assert check.key == "aws:SecureTransport"


def test_a_resource_the_analyzer_cant_evaluate_is_left_for_the_report():
    # The report calls it CAN'T TELL; it isn't a mistake in the framework file.
    key = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    assert parse(only(Actions=["kms:Decrypt"], Resources=[key])).checks[0].resources == (key,)


def test_load_framework_file(tmp_path):
    path = tmp_path / "fw.json"
    path.write_text(json.dumps(document(only())))
    assert load_framework_file(path).name == "fw.json"


def test_load_framework_file_errors(tmp_path):
    with pytest.raises(FrameworkError, match="cannot read file"):
        load_framework_file(tmp_path / "missing.json")
    path = tmp_path / "fw.json"
    path.write_text('{"Framework": {}, "Framework": {}}')
    with pytest.raises(FrameworkError, match="fw.json: duplicate key 'Framework'"):
        load_framework_file(path)


@pytest.mark.parametrize(
    "doc, message",
    [
        ([], "framework must be a JSON object"),
        ({**document(only()), "Version": "1"}, "unknown key\\(s\\): Version"),
        ({"Framework": {"Id": "d", "Title": "D"}}, "framework has no 'Checks'"),
        (document(), "'Checks' must be a non-empty list"),
        ({**document(only()), "Framework": {"Id": "d"}}, "'Title' must be a string"),
        (document(only(Id="no spaces")), "'Id' must be letters, digits and hyphens"),
        (document(only(), only()), "check Id 'notes' is used more than once"),
        (document(only(Type="mostly")), "'Type' must be \"only\", \"requires\" or \"can\""),
        (document(only(Severity="urgent")), "'Severity' must be critical, high, medium or low"),
        (document(only(Key="aws:MultiFactorAuthPresent")), "unknown key\\(s\\): Key"),
        (document(requires(Principals=[])), "unknown key\\(s\\): Principals"),
        (document(only(Title="x" * 81)), "'Title' must be a string of 1 to 80 characters"),
        (document(only(Actions=[])), "'Actions' must not be empty"),
        (document(only(Actions=["s3:Get*"])), "the action must be one AWS action"),
        (document(only(Resources=["district-student-records"])), "must be \"\\*\" or a full ARN"),
        (document(only(Resources=["arn:aws:s3:::district-*"])), "must name one resource"),
        (document(only(Resources=[f"{NOTES}*"])), "can't have wildcards"),
        (document(requires(Resources=["*"])), "sts:AssumeRole is a request on a role"),
        (document(only(Fix="  ")), "'Fix' must say how to fix a failure"),
        (document(only(Principals=["jsmith"])), "must be user/NAME, role/NAME or group/NAME"),
        (document(only(Principals=["user/a", "user/a"])), "names someone more than once"),
        (document({**only(), "Type": "can", "Principals": []}), "needs at least one principal"),
        (document(requires(Key="aws:SourceIp")), "'Key' must be a key whose every value AWS"),
        (document(requires(Value="absent")), "'Value' for aws:MultiFactorAuthPresent must be"),
        (document(requires(Context={"aws:multifactorauthpresent": None})),
         "can't give 'aws:MultiFactorAuthPresent', which the check requires"),
        (document(only(Context={"SourceIp": "1.2.3.4"})), "'Context': 'SourceIp' is not a"),
        (document(only(Context={"aws:SourceIp": 5})), "must be a string, a non-empty list"),
        (document(only(MapsTo=["NIST AC-3"])), "'MapsTo' names unknown requirement 'NIST AC-3'"),
        (document(only(), Requirements={"X": {**AC_6, "Link": "http://example.com"}}),
         "'Link' must be an https:// URL"),
        (document(only(), Requirements={"X": {**AC_6, "Title": "x" * 61}}),
         "'Title' must be a string of 1 to 60 characters"),
        (document(only(), Requirements={"X": {**AC_6, "Title": "Least\nPrivilege"}}),
         "'Title' must be one line"),
        (document(only(), Requirements={"X": {**AC_6, "Text": "..."}}), "unknown key\\(s\\): Text"),
    ],
)
def test_invalid_frameworks(doc, message):
    with pytest.raises(FrameworkError, match=message):
        parse_framework(doc, name="fw.json")
