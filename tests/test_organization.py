import json
from pathlib import Path

import pytest

from iam_analyzer.errors import OrganizationError, PolicyParseError, UnsupportedPolicyFeature
from iam_analyzer.models import TargetType
from iam_analyzer.organization import load_organization_file, parse_organization

EXAMPLE = Path(__file__).parent.parent / "examples" / "organizations" / "district.json"
MANAGEMENT = "999988887777"
DISTRICT = "111122223333"
ALLOW_ALL = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def attached(*scps, **children):
    """A root, OU or account node with these SCPs attached."""
    return {"ServiceControlPolicies": list(scps), **children}


def document(root, **overrides):
    return {
        "ManagementAccountId": MANAGEMENT,
        "ServiceControlPolicies": {"Full": ALLOW_ALL, "Guard": ALLOW_ALL},
        "Root": root,
        **overrides,
    }


def parse(root):
    return parse_organization(document(root), name="org.json")


def summary(levels):
    return [(lv.target.type, lv.target.name, [p.name for p in lv.policies]) for lv in levels]


# The smallest valid organization: the management account directly under the root.
MANAGEMENT_ONLY = {MANAGEMENT: attached("Full")}
VALID_ROOT = attached("Full", Accounts=MANAGEMENT_ONLY)


def test_account_directly_under_the_root():
    org = parse(attached("Full", Accounts={**MANAGEMENT_ONLY, DISTRICT: attached("Guard")}))
    assert summary(org.scp_levels_for(DISTRICT)) == [
        (TargetType.ROOT, "Root", ["Full"]),
        (TargetType.ACCOUNT, DISTRICT, ["Guard"]),
    ]


def test_nested_ous_are_listed_from_the_root_down():
    elementary = attached("Guard", Accounts={DISTRICT: attached("Full")})
    schools = attached("Full", "Guard", OrganizationalUnits={"Elementary": elementary})
    org = parse(attached("Full", Accounts=MANAGEMENT_ONLY, OrganizationalUnits={"Schools": schools}))
    assert summary(org.scp_levels_for(DISTRICT)) == [
        (TargetType.ROOT, "Root", ["Full"]),
        (TargetType.ORGANIZATIONAL_UNIT, "Schools", ["Full", "Guard"]),
        (TargetType.ORGANIZATIONAL_UNIT, "Elementary", ["Guard"]),
        (TargetType.ACCOUNT, DISTRICT, ["Full"]),
    ]


def test_scps_do_not_apply_to_the_management_account():
    org = parse(attached("Full", "Guard", Accounts=MANAGEMENT_ONLY))
    assert org.scp_levels_for(MANAGEMENT) == ()


def test_scps_do_not_apply_to_service_linked_roles():
    org = parse(attached("Full", Accounts={**MANAGEMENT_ONLY, DISTRICT: attached("Guard")}))
    assert org.scp_levels_for(DISTRICT, service_linked=True) == ()
    # Other principals in the same account still get the account's SCPs.
    assert len(org.scp_levels_for(DISTRICT)) == 2


def test_unknown_account():
    org = parse(VALID_ROOT)
    with pytest.raises(OrganizationError, match="no account '444455556666'"):
        org.scp_levels_for("444455556666")
    # Even a service-linked role must be in an account the organization knows.
    with pytest.raises(OrganizationError, match="no account '444455556666'"):
        org.scp_levels_for("444455556666", service_linked=True)


@pytest.mark.parametrize(
    "doc, message",
    [
        ([], "must be a JSON object"),
        (document(VALID_ROOT, Accounts={}), "org.json: unknown key"),
        ({"ManagementAccountId": MANAGEMENT, "ServiceControlPolicies": {}}, "missing key.*Root"),
        (
            document(VALID_ROOT, ServiceControlPolicies=[]),
            "'ServiceControlPolicies' must be a JSON object",
        ),
        (
            document(VALID_ROOT, ManagementAccountId=999988887777),
            "999988887777 is not an AWS account ID",
        ),
        (
            document(VALID_ROOT, ManagementAccountId="444455556666"),
            "management account '444455556666' is not in the tree",
        ),
        (document(attached(Accounts=MANAGEMENT_ONLY)), "root: needs at least one SCP"),
        (document(attached("Missing", Accounts=MANAGEMENT_ONLY)), "unknown SCP 'Missing'"),
        (
            document(attached("Full", Accounts={MANAGEMENT: attached()})),
            "account '999988887777': needs at least one SCP",
        ),
        (
            document(attached("Full", Accounts={MANAGEMENT: {"ServiceControlPolicies": "Full"}})),
            "must be a list of names",
        ),
        (
            document(attached("Full", Accounts={MANAGEMENT: attached("Full", Accounts={})})),
            "account '999988887777': unknown key",
        ),
        (
            document(attached("Full", Accounts={**MANAGEMENT_ONLY, "1234": attached("Full")})),
            "'1234' is not an AWS account ID",
        ),
        (document(attached("Full", Accounts=MANAGEMENT_ONLY, Users={})), "root: unknown key"),
        (
            document(attached("Full", Accounts=MANAGEMENT_ONLY, OrganizationalUnits=[])),
            "'OrganizationalUnits' must be a JSON object",
        ),
        (
            document(
                attached(
                    "Full",
                    Accounts=MANAGEMENT_ONLY,
                    OrganizationalUnits={"Schools": attached("Full", Accounts=MANAGEMENT_ONLY)},
                )
            ),
            "'999988887777' appears more than once",
        ),
    ],
)
def test_invalid_organizations(doc, message):
    with pytest.raises(OrganizationError, match=message):
        parse_organization(doc, name="org.json")


def test_scps_are_parsed_like_any_policy():
    doc = document(VALID_ROOT)
    statement = {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
    }
    doc["ServiceControlPolicies"]["RegionLock"] = {"Statement": [statement]}
    [region_lock] = parse_organization(doc, name="org.json").policies["RegionLock"].statements
    [condition] = region_lock.conditions
    assert (condition.operator, condition.key) == ("StringNotEquals", "aws:RequestedRegion")
    statement["Condition"] = {"StringNotEqual": {"aws:RequestedRegion": "us-east-1"}}
    message = "RegionLock statement 0: unknown condition operator 'StringNotEqual'"
    with pytest.raises(PolicyParseError, match=message):
        parse_organization(doc, name="org.json")


def test_scps_are_loaded_as_scps():
    # So a short ARN is refused: AWS documents completing one only in identity-based policies.
    doc = document(VALID_ROOT)
    no_s3 = {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3"}]}
    doc["ServiceControlPolicies"]["NoS3"] = no_s3
    message = "NoS3 statement 0: 'Resource' entry 'arn:aws:s3' has fewer than six fields"
    with pytest.raises(UnsupportedPolicyFeature, match=message):
        parse_organization(doc, name="org.json")


def test_load_organization_file(tmp_path):
    path = tmp_path / "org.json"
    path.write_text(json.dumps(document(VALID_ROOT)))
    org = load_organization_file(path)
    assert org.name == "org.json"
    assert org.management_account_id == MANAGEMENT


def test_load_organization_file_errors(tmp_path):
    with pytest.raises(OrganizationError, match="cannot read file"):
        load_organization_file(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(OrganizationError, match="invalid JSON"):
        load_organization_file(bad)


def test_account_listed_twice_under_one_parent_is_rejected(tmp_path):
    # json.loads would keep only the second copy, silently dropping the DenyAll SCP.
    path = tmp_path / "org.json"
    path.write_text("""{
      "ManagementAccountId": "999988887777",
      "ServiceControlPolicies": {
        "Full": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        "DenyAll": {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
      },
      "Root": {
        "ServiceControlPolicies": ["Full"],
        "Accounts": {
          "999988887777": {"ServiceControlPolicies": ["Full"]},
          "111122223333": {"ServiceControlPolicies": ["Full", "DenyAll"]},
          "111122223333": {"ServiceControlPolicies": ["Full"]}
        }
      }
    }""")
    with pytest.raises(OrganizationError, match="org.json: duplicate key '111122223333'"):
        load_organization_file(path)


def test_example_organization():
    org = load_organization_file(EXAMPLE)
    assert summary(org.scp_levels_for(DISTRICT)) == [
        (TargetType.ROOT, "Root", ["FullAWSAccess"]),
        (TargetType.ORGANIZATIONAL_UNIT, "Schools", ["SchoolServicesOnly", "ProtectStudentRecords"]),
        (TargetType.ACCOUNT, DISTRICT, ["FullAWSAccess"]),
    ]
    assert org.scp_levels_for(MANAGEMENT) == ()


def test_anycompany_organization():
    org = load_organization_file(EXAMPLE.parent / "anycompany.json")
    assert summary(org.scp_levels_for("111122223333")) == [
        (TargetType.ROOT, "Root", ["FullAWSAccess", "ProtectAuditLogging"]),
        (TargetType.ORGANIZATIONAL_UNIT, "Production", ["ProductionServices"]),
        (TargetType.ACCOUNT, "111122223333", ["FullAWSAccess"]),
    ]
    assert summary(org.scp_levels_for("123456789012")) == [
        (TargetType.ROOT, "Root", ["FullAWSAccess", "ProtectAuditLogging"]),
        (TargetType.ORGANIZATIONAL_UNIT, "Development", ["FullAWSAccess"]),
        (TargetType.ACCOUNT, "123456789012", ["FullAWSAccess"]),
    ]
    assert org.scp_levels_for(MANAGEMENT) == ()
