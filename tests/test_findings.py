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
def test_other_dates_arent_read_as_epoch_seconds(value):
    acct = account(statement(DateLessThan={"aws:CurrentTime": value}))
    assert DATE_NUMBER.id not in [type_id for type_id, _, _ in found(acct)]


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


def test_the_district_example_has_its_two_mistakes():
    public, date = scan(load_account_file(EXAMPLES / "accounts" / "district.json"),
                        organization=None)
    assert (public.type.id, public.severity, public.statement.sid) == (
        "public-bucket-policy", Severity.HIGH, "ShareRosterWithVendor")
    assert public.uses == (
        Use(PolicyType.RESOURCE_BASED, resource="arn:aws:s3:::district-roster-exports"),)
    assert (date.type, date.severity, date.policy.name) == (
        DATE_NUMBER, Severity.LOW, "SummerSchoolRecords")
    assert date.uses == (Use(PolicyType.IDENTITY, principal="group/SummerSchool"),)


# --- Who policies grant access to ------------------------------------------------------

PUBLIC = "public-bucket-policy"


def bucket(*statements, version="2012-10-17"):
    return parse_account({"AccountId": "111122223333", "Policies": {}, "Resources": {
        BUCKET: {"Policy": {"Version": version, "Statement": list(statements)}}}},
        name="acct.json")


def grant(principal="*", effect="Allow", **condition):
    return {"Effect": effect, "Principal": principal, "Action": "s3:GetObject",
            "Resource": f"{BUCKET}/*", **({"Condition": condition} if condition else {})}


@pytest.mark.parametrize("condition", [
    {},
    {"Bool": {"aws:SecureTransport": "true"}},  # TLS says nothing about who
    {"StringLike": {"aws:SourceVpc": "vpc-*"}},  # S3's own public example
    {"StringNotEquals": {"aws:SourceVpce": "vpce-1a2b3c4d"}},
    {"StringEqualsIfExists": {"aws:SourceVpce": "vpce-1a2b3c4d"}},
    {"ForAllValues:StringEquals": {"aws:SourceVpce": "vpce-1a2b3c4d"}},
    {"StringEquals": {"aws:SourceVpce": "${aws:username}"}},
    {"IpAddress": {"aws:SourceIp": "0.0.0.0/1"}},  # broader than /8
    {"IpAddress": {"aws:SourceIp": "2001:db8::/16"}},  # broader than /32
    {"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
    {"ArnLike": {"s3:DataAccessPointArn": "arn:aws:s3:us-west-2:*:accesspoint/*"}},
])
def test_a_grant_to_everyone_is_public(condition):
    [finding] = [f for f in scan(bucket(grant(**condition)), organization=None)
                 if f.type.id == PUBLIC]
    assert (finding.type.id, finding.severity) == (PUBLIC, Severity.HIGH)
    assert finding.principal.value == "*"
    assert finding.kind is PolicyType.RESOURCE_BASED
    assert finding.unsettled == ()


@pytest.mark.parametrize("condition", [
    {"StringEquals": {"aws:SourceVpce": "vpce-1a2b3c4d"}},  # S3's own non-public example
    {"ForAnyValue:StringEquals": {"aws:SourceVpc": "vpc-91237329"}},
    {"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"}},
    {"StringEquals": {"aws:SourceAccount": "111122223333"}},
    {"ArnEquals": {"aws:SourceArn": "arn:aws:cloudtrail:us-east-1:111122223333:trail/t"}},
    {"StringEquals": {"aws:userid": "AIDAEXAMPLEEXAMPLE123"}},
    {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
    {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "2001:db8::/32"]}},
    {"ArnLike": {"s3:DataAccessPointArn": "arn:aws:s3:us-west-2:111122223333:accesspoint/*"}},
    {"StringEquals": {"s3:DataAccessPointAccount": "111122223333"}},
    {"Bool": {"aws:SecureTransport": "true"}, "StringEquals": {"aws:SourceVpce": "vpce-1"}},
])
def test_a_grant_limited_to_fixed_values_of_a_key_s3_names_isnt_public(condition):
    assert found(bucket(grant(**condition))) == []


def test_a_principal_key_s3_doesnt_name_is_unsettled():
    condition = {"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/Vendor"}}
    [finding] = scan(bucket(grant(**condition)), organization=None)
    assert finding.type.id == PUBLIC
    assert [c.key for c in finding.unsettled] == ["aws:PrincipalArn"]


def test_denies_and_named_principals_arent_public():
    named = grant({"AWS": "arn:aws:iam::111122223333:user/kwong"})
    assert found(bucket(grant(effect="Deny"), named)) == []


TRUST = "arn:aws:iam::111122223333:role/Admin"


def trust(*statements, organization=None):
    acct = parse_account({"AccountId": "111122223333", "Policies": {}, "Roles": {"Admin": {
        "AssumeRolePolicyDocument": {"Statement": list(statements)}}}}, name="acct.json")
    return scan(acct, organization=organization)


def assume(principal, effect="Allow", action="sts:AssumeRole", **condition):
    return {"Effect": effect, "Principal": principal, "Action": action,
            **({"Condition": condition} if condition else {})}


def test_a_trust_policy_that_names_everyone():
    [finding] = trust(assume("*"))
    assert (finding.type.id, finding.severity) == ("trust-policy-names-everyone", Severity.CRITICAL)
    assert finding.uses == (Use(PolicyType.TRUST, resource=TRUST),)
    org_id = {"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"}}
    [limited] = trust(assume("*", **org_id))
    assert limited.severity is Severity.HIGH
    assert trust(assume("*", effect="Deny")) == ()


@pytest.mark.parametrize("principal", [
    {"AWS": "444455556666"},
    {"AWS": "arn:aws:iam::444455556666:root"},
    {"AWS": "arn:aws:iam::444455556666:role/Deployer"},
])
def test_another_account_without_an_external_id(principal):
    [finding] = trust(assume(principal))
    assert (finding.type.id, finding.severity) == (
        "cross-account-trust-without-external-id", Severity.MEDIUM)
    assert finding.principal.value == principal["AWS"]


def test_an_external_id_the_same_account_or_the_organization_raises_nothing():
    external_id = {"StringEquals": {"sts:ExternalId": "district-gradebook-7f3a"}}
    assert trust(assume({"AWS": "444455556666"}, **external_id)) == ()
    assert trust(assume({"AWS": "arn:aws:iam::111122223333:root"})) == ()
    org = parse_organization({
        "ManagementAccountId": "444455556666",
        "ServiceControlPolicies": {"All": {"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
        "Root": {"ServiceControlPolicies": ["All"], "Accounts": {
            "444455556666": {"ServiceControlPolicies": ["All"]},
            "111122223333": {"ServiceControlPolicies": ["All"]}}},
    }, name="org.json")
    assert trust(assume({"AWS": "444455556666"}), organization=org) == ()
    saml = {"Federated": "arn:aws:iam::111122223333:saml-provider/DistrictIdP"}
    assert trust(assume(saml, action="sts:AssumeRoleWithSAML")) == ()


@pytest.mark.parametrize("effect, severity", [("Deny", Severity.HIGH), ("Allow", Severity.LOW)])
def test_a_unique_id_principal_was_deleted(effect, severity):
    [finding] = scan(bucket(grant({"AWS": "AIDAEXAMPLEEXAMPLE123"}, effect=effect)),
                     organization=None)
    assert (finding.type.id, finding.severity) == ("principal-is-a-unique-id", severity)
    assert finding.principal.value == "AIDAEXAMPLEEXAMPLE123"


# --- Condition surprises ---------------------------------------------------------------

MFA = "aws:MultiFactorAuthPresent"


def types(*statements):
    return [(type_id, severity) for type_id, severity, _ in found(account(*statements))]


def test_an_mfa_deny_that_skips_access_keys():
    assert types(statement("Deny", Bool={MFA: "false"})) == [
        ("mfa-deny-skips-access-keys", Severity.HIGH)]
    assert types(statement("Deny", BoolIfExists={MFA: "false"})) == []  # AWS's recommendation
    assert types(statement("Allow", Bool={MFA: "true"})) == []  # needs MFA: missing fails, safely


def test_a_for_all_values_allow_without_a_null_check():
    tags = {"ForAllValues:StringEquals": {"aws:TagKeys": ["campus", "grade"]}}
    assert types(statement("Allow", **tags)) == [("for-all-values-allow-without-null",
                                                  Severity.HIGH)]
    assert types(statement("Allow", **tags, Null={"aws:TagKeys": "false"})) == []
    assert types(statement("Deny", **tags)) == []


@pytest.mark.parametrize("effect, severity", [("Deny", Severity.HIGH), ("Allow", Severity.LOW)])
def test_for_any_value_with_if_exists(effect, severity):
    condition = {"ForAnyValue:StringEqualsIfExists": {"aws:TagKeys": "campus"}}
    assert types(statement(effect, **condition)) == [("for-any-value-ignores-if-exists", severity)]


@pytest.mark.parametrize("operator, value, effect, severity", [
    ("ForAnyValue:Null", "true", "Deny", Severity.HIGH),  # never holds, so the Deny never applies
    ("ForAnyValue:Null", "true", "Allow", Severity.LOW),
    ("ForAllValues:Null", "false", "Allow", Severity.HIGH),  # holds when the key is missing
    ("ForAllValues:Null", "false", "Deny", Severity.LOW),
])
def test_a_set_operator_on_null(operator, value, effect, severity):
    assert types(statement(effect, **{operator: {"aws:TagKeys": value}})) == [
        ("set-operator-on-null", severity)]


@pytest.mark.parametrize("operator, value", [("ForAnyValue:Null", "false"),
                                             ("ForAllValues:Null", "true")])
def test_a_set_operator_on_null_that_reads_as_written(operator, value):
    assert types(statement(**{operator: {"aws:TagKeys": value}})) == []


@pytest.mark.parametrize("value", ["2026-08", "2026-08-15", "2026-08-15T07:30",
                                   "2026-08-15T07:30:00"])
def test_a_date_without_a_time_zone(value):
    assert types(statement(DateGreaterThan={"aws:CurrentTime": value})) == [
        ("date-without-a-time-zone", Severity.LOW)]


def test_a_date_with_a_time_zone_or_a_number():
    assert types(statement(DateGreaterThan={"aws:CurrentTime": "2026-08-15T07:30:00Z"})) == []
    assert "date-without-a-time-zone" not in dict(
        types(statement(DateGreaterThan={"aws:CurrentTime": "2026"})))


@pytest.mark.parametrize("operator, value, found_it", [
    ("IpAddress", "203.0.113.5/24", True),
    ("NotIpAddress", "10.1.2.3/8", True),
    ("IpAddress", "203.0.113.0/24", False),
    ("IpAddress", "203.0.113.5", False),
    ("IpAddress", "2001:db8::/32", False),
])
def test_an_ip_range_with_host_bits(operator, value, found_it):
    result = types(statement(**{operator: {"aws:SourceIp": value}}))
    assert result == ([("ip-range-with-host-bits", Severity.LOW)] if found_it else [])


# --- A policy variable with no value for a principal -----------------------------------

HOME = f"{BUCKET}/home/${{aws:username}}/*"


def principals(policy, **sections):
    acct = parse_account({"AccountId": "111122223333",
                          "Policies": {"P": {"Version": "2012-10-17", "Statement": [policy]}},
                          **sections}, name="acct.json")
    return [f for f in scan(acct, organization=None) if f.type.id == "variable-without-a-value"]


@pytest.mark.parametrize("effect, element, severity", [
    ("Allow", "Resource", Severity.LOW),  # covers nothing
    ("Deny", "Resource", Severity.HIGH),  # the Deny never applies
    ("Allow", "NotResource", Severity.HIGH),  # excludes nothing, so it covers everything
    ("Deny", "NotResource", Severity.LOW),
])
def test_a_role_has_no_user_name(effect, element, severity):
    [finding] = principals({"Effect": effect, "Action": "s3:GetObject", element: HOME},
                           Users={"jsmith": {"Policies": ["P"]}},
                           Roles={"r1": {"Policies": ["P"]}, "r2": {"Policies": ["P"]}})
    assert (finding.severity, finding.variable, finding.element) == (
        severity, "aws:username", element)
    assert finding.subjects == ("role/r1", "role/r2")  # jsmith has a user name
    assert finding.uses == (Use(PolicyType.IDENTITY, principal="user/jsmith"),
                            Use(PolicyType.IDENTITY, principal="role/r1"),
                            Use(PolicyType.IDENTITY, principal="role/r2"))


@pytest.mark.parametrize("operator, effect, severity", [
    ("StringEquals", "Allow", Severity.LOW),  # fails, so the Allow never applies
    ("StringNotEquals", "Allow", Severity.HIGH),  # holds, so the Allow always applies
    ("StringNotEquals", "Deny", Severity.LOW),
])
def test_a_variable_in_a_condition(operator, effect, severity):
    owner = {operator: {"aws:ResourceTag/owner": "${aws:username}"}}
    [finding] = principals({"Effect": effect, "Action": "s3:GetObject", "Resource": "*",
                            "Condition": owner}, Roles={"r": {"Policies": ["P"]}})
    assert (finding.severity, finding.element, finding.condition.operator) == (
        severity, None, operator)


def test_a_user_without_the_tag_a_policy_reads():
    campus = {"Effect": "Allow", "Action": "s3:GetObject",
              "Resource": f"{BUCKET}/${{aws:PrincipalTag/campus}}/*"}
    tagged = {"Policies": ["P"], "Tags": [{"Key": "campus", "Value": "campus-01"}]}
    [finding] = principals(campus, Users={"tagged": tagged, "untagged": {"Policies": ["P"]}})
    assert (finding.variable, finding.subjects) == ("aws:PrincipalTag/campus", ("user/untagged",))


def test_what_the_file_doesnt_know_isnt_reported():
    campus = {"Effect": "Allow", "Action": "s3:GetObject",
              "Resource": f"{BUCKET}/${{aws:PrincipalTag/campus}}/*"}
    # A role's tags are unknown while session tags are possible, and a default is used when the
    # key is absent.
    assert principals(campus, Roles={"r": {"Policies": ["P"]}}) == []
    default = {**campus, "Resource": f"{BUCKET}/${{aws:PrincipalTag/campus, 'shared'}}/*"}
    assert principals(default, Users={"u": {"Policies": ["P"]}}) == []


def test_a_boundary_is_read_for_its_principals():
    [finding] = principals({"Effect": "Allow", "Action": "s3:GetObject", "Resource": HOME},
                           Roles={"r": {"PermissionsBoundary": "P"}})
    assert finding.subjects == ("role/r",)
    assert finding.uses == (Use(PolicyType.PERMISSIONS_BOUNDARY, principal="role/r"),)


def test_a_unique_id_in_not_principal_only_blocks_more():
    deny = {"Effect": "Deny", "NotPrincipal": {"AWS": "AIDAEXAMPLEEXAMPLE123"},
            "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"}
    [finding] = [f for f in scan(bucket(deny), organization=None)
                 if f.type.id == "principal-is-a-unique-id"]
    assert finding.severity is Severity.LOW
