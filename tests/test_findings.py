import json
from pathlib import Path

import pytest

from iam_analyzer.account import load_account_file, parse_account
from iam_analyzer.findings import DATE_NUMBER, TYPES, Use, scan
from iam_analyzer.framework import Severity
from iam_analyzer.models import OrgTarget, PolicyType, TargetType
from iam_analyzer.organization import parse_organization
from simulator_check import FIXTURE_DIR, outcomes

EXAMPLES = Path(__file__).parent.parent / "examples"
BUCKET = "arn:aws:s3:::district-student-records"


# --- Evidence --------------------------------------------------------------------------

FIXTURES = [(t.id, f) for t in TYPES for f in t.fixtures]


@pytest.mark.parametrize("type_id, fixture", FIXTURES, ids=[f.case for _, f in FIXTURES])
def test_every_cited_fixture_holds_awss_answer(type_id, fixture):
    recorded = json.loads((FIXTURE_DIR / f"{fixture.case}.json").read_text())
    assert outcomes.aws(recorded).label == fixture.aws, type_id
    # And the analyzer agrees with AWS on it.
    assert outcomes.ours(recorded["simulate"]["request"], recorded["absent"]).label == fixture.aws


@pytest.mark.parametrize("finding_type", TYPES, ids=[t.id for t in TYPES])
def test_every_finding_type_cites_its_evidence(finding_type):
    assert finding_type.fixtures or finding_type.docs
    for doc in finding_type.docs:
        assert doc.link.startswith("https://docs.aws.amazon.com/")
        assert doc.quote
    assert finding_type.why and finding_type.fix


def test_finding_type_ids_are_unique():
    assert len({t.id for t in TYPES}) == len(TYPES)


# --- Scanning --------------------------------------------------------------------------


def statement(effect="Allow", **condition):
    return {"Effect": effect, "Action": "s3:GetObject", "Resource": f"{BUCKET}/*",
            "Condition": condition}


def account(*statements, version="2012-10-17", **sections):
    return parse_account({"AccountId": "111122223333", "Policies": {
        "P": {"Version": version, "Statement": list(statements)}}, **sections},
        name="acct.json")


def found(acct, organization=None):
    return [(f.type.id, f.severity, f.index) for f in scan(acct, organization=organization)]


@pytest.mark.parametrize("effect, operator, severity", [
    ("Allow", "DateLessThan", Severity.LOW),  # never holds, so the Allow never applies
    ("Deny", "DateLessThan", Severity.HIGH),  # the Deny never applies
    ("Allow", "DateGreaterThan", Severity.HIGH),  # always holds, so the Allow always applies
    ("Deny", "DateGreaterThanEquals", Severity.LOW),
    ("Allow", "DateNotEquals", Severity.HIGH),
])
def test_a_four_digit_date_is_found(effect, operator, severity):
    acct = account(statement(effect, **{operator: {"aws:CurrentTime": "2027"}}))
    assert found(acct) == [(DATE_NUMBER.id, severity, 0)]


@pytest.mark.parametrize("value", ["2027-01-01T00:00:00Z", "2027-01-01", "1798761600", "202"])
def test_other_dates_are_not_found(value):
    assert found(account(statement(DateLessThan={"aws:CurrentTime": value}))) == []


@pytest.mark.parametrize("effect, severity", [("Deny", Severity.HIGH), ("Allow", Severity.LOW)])
def test_a_bool_value_with_a_variable_is_found(effect, severity):
    acct = account(statement(effect, Bool={"aws:SecureTransport": "${aws:MultiFactorAuthPresent}"}))
    assert found(acct) == [("bool-variable-never-matches", severity, 0)]


def test_a_plain_bool_is_not_found():
    assert found(account(statement(Bool={"aws:SecureTransport": "true"}))) == []


def test_findings_say_where_the_policy_is_used():
    acct = account(statement(DateLessThan={"aws:CurrentTime": "2027"}),
                   Groups={"Summer": {"Policies": ["P"]}},
                   Users={"u": {"Policies": ["P"]}, "b": {"PermissionsBoundary": "P"}},
                   Roles={"r": {"Policies": ["P"]}})
    [finding] = scan(acct, organization=None)
    assert finding.kind is PolicyType.IDENTITY
    assert finding.uses == (
        Use(PolicyType.IDENTITY, principal="user/u"),
        Use(PolicyType.PERMISSIONS_BOUNDARY, principal="user/b"),
        Use(PolicyType.IDENTITY, principal="group/Summer"),
        Use(PolicyType.IDENTITY, principal="role/r"),
    )
    assert finding.condition.operator == "DateLessThan"
    assert finding.statement.effect.value == "Allow"


def test_an_unattached_policy_is_still_scanned():
    [finding] = scan(account(statement(DateLessThan={"aws:CurrentTime": "2027"})),
                     organization=None)
    assert finding.uses == ()


def test_bucket_trust_and_service_control_policies_are_scanned():
    four_digits = {"DateLessThan": {"aws:CurrentTime": "2027"}}
    acct = parse_account({
        "AccountId": "111122223333", "Policies": {},
        "Resources": {BUCKET: {"Policy": {"Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": f"{BUCKET}/*", "Condition": four_digits}]}}},
        "Roles": {"Admin": {"AssumeRolePolicyDocument": {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "111122223333"}, "Action": "sts:AssumeRole",
            "Condition": four_digits}]}}},
    }, name="acct.json")
    org = parse_organization({
        "ManagementAccountId": "999988887777",
        "ServiceControlPolicies": {"Window": {"Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": four_digits}]},
            "All": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
        "Root": {"ServiceControlPolicies": ["All", "Window"],
                 "OrganizationalUnits": {"Schools": {"ServiceControlPolicies": ["Window"], "Accounts": {
                     "111122223333": {"ServiceControlPolicies": ["All"]}}}},
                 "Accounts": {"999988887777": {"ServiceControlPolicies": ["All"]}}},
    }, name="org.json")
    kinds = {f.kind: f.uses for f in scan(acct, organization=org)}
    assert kinds[PolicyType.RESOURCE_BASED] == (Use(PolicyType.RESOURCE_BASED, resource=BUCKET),)
    assert kinds[PolicyType.TRUST] == (
        Use(PolicyType.TRUST, resource="arn:aws:iam::111122223333:role/Admin"),)
    assert kinds[PolicyType.SCP] == (
        Use(PolicyType.SCP, org_target=OrgTarget(TargetType.ROOT, "Root")),
        Use(PolicyType.SCP, org_target=OrgTarget(TargetType.ORGANIZATIONAL_UNIT, "Schools")),
    )


def test_findings_are_sorted_by_severity():
    acct = account(statement("Allow", DateLessThan={"aws:CurrentTime": "2027"}),
                   statement("Deny", DateLessThan={"aws:CurrentTime": "2027"}))
    assert found(acct) == [(DATE_NUMBER.id, Severity.HIGH, 1), (DATE_NUMBER.id, Severity.LOW, 0)]


def test_the_district_example_has_its_summer_school_date():
    [finding] = scan(load_account_file(EXAMPLES / "accounts" / "district.json"), organization=None)
    assert (finding.type, finding.severity, finding.policy.name) == (
        DATE_NUMBER, Severity.LOW, "SummerSchoolRecords")
    assert finding.uses == (Use(PolicyType.IDENTITY, principal="group/SummerSchool"),)
