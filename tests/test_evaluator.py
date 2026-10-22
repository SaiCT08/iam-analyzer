import dataclasses
import itertools
import json
from pathlib import Path

import pytest

from iam_analyzer.errors import RequestError
from iam_analyzer.evaluator import evaluate
from iam_analyzer.loader import parse_policy
from iam_analyzer.models import Decision, Layer, OrgTarget, PolicyType, Request, ScpLevel, TargetType
from iam_analyzer.organization import parse_organization

BUCKET = "arn:aws:s3:::district-student-records"
OBJECT = f"{BUCKET}/2026/roster.csv"
GET = Request(action="s3:GetObject", resource=OBJECT)


def policy(name, *statements):
    return parse_policy({"Statement": list(statements)}, name=name)


def allow(action, resource, sid=None):
    return {"Sid": sid, "Effect": "Allow", "Action": action, "Resource": resource}


def deny(action, resource, sid=None):
    return {"Sid": sid, "Effect": "Deny", "Action": action, "Resource": resource}


@pytest.mark.parametrize(
    "action", ["s3:*", "s3:Get*", "s3:GetObjec?", "*", "GetObject", "s3:", ":GetObject"]
)
def test_request_names_one_concrete_action(action):
    # A real AWS request is for one action; a pattern here would be matched as literal text.
    with pytest.raises(RequestError, match="one AWS action"):
        Request(action=action, resource=OBJECT)


def test_policy_variable_without_version_is_plain_text():
    # Without "Version": "2012-10-17", AWS treats ${aws:username} as literal text.
    p = policy("p", allow("s3:GetObject", "arn:aws:s3:::home/${aws:username}/*"))
    literal = Request(action="s3:GetObject", resource="arn:aws:s3:::home/${aws:username}/a.txt")
    named = Request(action="s3:GetObject", resource="arn:aws:s3:::home/jsmith/a.txt")
    assert evaluate(literal, [p]).decision is Decision.ALLOW
    assert evaluate(named, [p]).decision is Decision.IMPLICIT_DENY


def test_no_policies_is_implicit_deny():
    result = evaluate(GET, [])
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.reasons == ()
    assert not result.allowed


def test_matching_allow():
    result = evaluate(GET, [policy("p", allow("s3:GetObject", OBJECT, sid="A"))])
    assert result.decision is Decision.ALLOW
    assert result.allowed
    assert [(r.policy_name, r.statement.sid) for r in result.reasons] == [("p", "A")]


@pytest.mark.parametrize(
    "statement",
    [
        allow("s3:PutObject", OBJECT),  # wrong action
        allow("s3:GetObject", f"{BUCKET}-archive/*"),  # wrong resource
        allow("s3:GetObject", BUCKET),  # bucket ARN, not object ARN
    ],
)
def test_allow_for_something_else_is_implicit_deny(statement):
    assert evaluate(GET, [policy("p", statement)]).decision is Decision.IMPLICIT_DENY


def test_action_and_resource_must_both_match_in_the_same_statement():
    # One statement allows the action elsewhere, another allows a different action here.
    p = policy("p", allow("s3:GetObject", "arn:aws:s3:::other/*"), allow("s3:PutObject", OBJECT))
    assert evaluate(GET, [p]).decision is Decision.IMPLICIT_DENY


def test_wildcard_allow():
    p = policy("p", allow("s3:Get*", f"{BUCKET}/*"))
    assert evaluate(GET, [p]).decision is Decision.ALLOW


def test_any_entry_in_action_and_resource_lists_can_match():
    p = policy("p", allow(["ec2:*", "s3:GetObject"], ["arn:aws:s3:::other/*", f"{BUCKET}/*"]))
    assert evaluate(GET, [p]).decision is Decision.ALLOW


def test_explicit_deny_beats_allow_in_any_order():
    statements = [allow("s3:*", "*", sid="AllowAll"), deny("s3:GetObject", OBJECT, sid="NoGet")]
    for ordering in itertools.permutations(statements):
        # Same policy, both orders.
        assert evaluate(GET, [policy("p", *ordering)]).decision is Decision.EXPLICIT_DENY
        # Separate policies, both orders.
        policies = [policy(f"p{i}", s) for i, s in enumerate(ordering)]
        assert evaluate(GET, policies).decision is Decision.EXPLICIT_DENY


def test_explicit_deny_reasons_list_only_denies():
    policies = [
        policy("allow.json", allow("s3:*", "*", sid="AllowAll")),
        policy("deny.json", deny("s3:Get*", f"{BUCKET}/*", sid="NoGet")),
    ]
    result = evaluate(GET, policies)
    assert [(r.policy_name, r.statement.sid) for r in result.reasons] == [("deny.json", "NoGet")]


def test_deny_alone_is_explicit_deny():
    result = evaluate(GET, [policy("p", deny("*", "*"))])
    assert result.decision is Decision.EXPLICIT_DENY


def test_non_matching_deny_does_not_block_allow():
    p = policy("p", allow("s3:*", "*"), deny("s3:DeleteObject", f"{BUCKET}/*"))
    assert evaluate(GET, [p]).decision is Decision.ALLOW


def test_all_matching_allows_are_reported():
    policies = [
        policy("a.json", allow("s3:GetObject", OBJECT, sid="One")),
        policy("b.json", allow("s3:*", "*", sid="Two")),
    ]
    result = evaluate(GET, policies)
    assert [r.statement.sid for r in result.reasons] == ["One", "Two"]


def test_via_group_is_carried_into_reasons():
    direct = policy("Direct", allow("s3:GetObject", OBJECT))
    inherited = dataclasses.replace(policy("Shared", allow("s3:*", "*")), via_group="Teachers")
    result = evaluate(GET, [direct, inherited])
    assert [(r.policy_name, r.via_group) for r in result.reasons] == [
        ("Direct", None),
        ("Shared", "Teachers"),
    ]


# --- NotAction / NotResource -----------------------------------------------------------


def statement(effect, sid=None, **elements):
    return {"Sid": sid, "Effect": effect, **elements}


def test_allow_not_action_allows_everything_except_listed():
    p = policy("p", statement("Allow", NotAction="s3:Delete*", Resource="*"))
    assert evaluate(GET, [p]).decision is Decision.ALLOW
    delete = Request(action="s3:DeleteObject", resource=OBJECT)
    assert evaluate(delete, [p]).decision is Decision.IMPLICIT_DENY


def test_deny_not_action_guardrail_blocks_everything_except_listed():
    guardrail = statement(
        "Deny", sid="ReadOnly", NotAction=["s3:Get*", "s3:List*"], Resource=f"{BUCKET}/*"
    )
    policies = [policy("p", allow("s3:*", "*"), guardrail)]
    assert evaluate(GET, policies).decision is Decision.ALLOW
    put = Request(action="s3:PutObject", resource=OBJECT)
    result = evaluate(put, policies)
    assert result.decision is Decision.EXPLICIT_DENY
    assert [r.statement.sid for r in result.reasons] == ["ReadOnly"]


def test_deny_not_action_only_applies_to_its_resource():
    guardrail = statement("Deny", NotAction="s3:Get*", Resource=f"{BUCKET}/*")
    put_elsewhere = Request(action="s3:PutObject", resource="arn:aws:s3:::other/file")
    p = policy("p", allow("s3:*", "*"), guardrail)
    assert evaluate(put_elsewhere, [p]).decision is Decision.ALLOW


def test_allow_not_resource_allows_everywhere_except_listed():
    p = policy("p", statement("Allow", Action="s3:GetObject", NotResource=f"{BUCKET}/*"))
    assert evaluate(GET, [p]).decision is Decision.IMPLICIT_DENY
    other = Request(action="s3:GetObject", resource="arn:aws:s3:::other/file")
    assert evaluate(other, [p]).decision is Decision.ALLOW


def test_deny_not_resource_blocks_everywhere_except_listed():
    p = policy(
        "p",
        allow("s3:*", "*"),
        statement("Deny", Action="s3:*", NotResource=[BUCKET, f"{BUCKET}/*"]),
    )
    assert evaluate(GET, [p]).decision is Decision.ALLOW
    other = Request(action="s3:GetObject", resource="arn:aws:s3:::other/file")
    assert evaluate(other, [p]).decision is Decision.EXPLICIT_DENY


def test_not_action_with_not_resource():
    # Deny anything except reads, anywhere except the public bucket.
    p = policy(
        "p",
        allow("*", "*"),
        statement("Deny", NotAction="s3:Get*", NotResource="arn:aws:s3:::public/*"),
    )

    def decide(action, resource):
        return evaluate(Request(action=action, resource=resource), [p]).decision

    assert decide("s3:GetObject", OBJECT) is Decision.ALLOW  # read: excluded action
    assert decide("s3:PutObject", "arn:aws:s3:::public/x") is Decision.ALLOW  # excluded resource
    assert decide("s3:PutObject", OBJECT) is Decision.EXPLICIT_DENY  # neither excluded


# --- Permissions boundaries ------------------------------------------------------------

IDENTITY = Layer(PolicyType.IDENTITY)
BOUNDARY = Layer(PolicyType.PERMISSIONS_BOUNDARY)


def reasons(result):
    return [(r.policy_name, r.statement.sid, r.layer) for r in result.reasons]


def test_without_boundary_implicit_deny_names_identity_layer():
    result = evaluate(GET, [policy("p", allow("s3:PutObject", OBJECT))])
    assert result.not_allowed_by == (IDENTITY,)


def test_identity_and_boundary_both_allow():
    identity = policy("identity", allow("s3:*", "*", sid="BroadS3"))
    boundary = policy("boundary", allow("s3:GetObject", f"{BUCKET}/*", sid="ReadRecords"))
    result = evaluate(GET, [identity], boundary=boundary)
    assert result.decision is Decision.ALLOW
    assert result.not_allowed_by == ()
    assert reasons(result) == [
        ("identity", "BroadS3", IDENTITY),
        ("boundary", "ReadRecords", BOUNDARY),
    ]


def test_boundary_blocks_what_identity_allows():
    identity = policy("identity", allow("s3:*", "*"))
    boundary = policy("boundary", allow("s3:*", "arn:aws:s3:::district-gradebook-app/*"))
    result = evaluate(GET, [identity], boundary=boundary)
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.reasons == ()
    assert result.not_allowed_by == (BOUNDARY,)


def test_boundary_never_grants_access():
    identity = policy("identity", allow("s3:PutObject", OBJECT))
    boundary = policy("boundary", allow("*", "*"))
    result = evaluate(GET, [identity], boundary=boundary)
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.not_allowed_by == (IDENTITY,)


def test_every_layer_without_an_allow_is_listed_in_order():
    boundary = policy("boundary", allow("ec2:*", "*"))
    result = evaluate(GET, [], boundary=boundary)
    assert result.not_allowed_by == (IDENTITY, BOUNDARY)


def test_deny_in_boundary_is_an_explicit_deny():
    identity = policy("identity", allow("s3:*", "*"))
    boundary = policy("boundary", allow("s3:*", "*"), deny("s3:GetObject", OBJECT, sid="NoGet"))
    result = evaluate(GET, [identity], boundary=boundary)
    assert result.decision is Decision.EXPLICIT_DENY
    assert reasons(result) == [("boundary", "NoGet", BOUNDARY)]


def test_denies_from_every_layer_are_reported():
    identity = policy("identity", allow("s3:*", "*"), deny("s3:Get*", "*", sid="IdentityDeny"))
    boundary = policy("boundary", deny("s3:GetObject", OBJECT, sid="BoundaryDeny"))
    result = evaluate(GET, [identity], boundary=boundary)
    assert reasons(result) == [
        ("identity", "IdentityDeny", IDENTITY),
        ("boundary", "BoundaryDeny", BOUNDARY),
    ]


def test_boundary_with_only_denies_allows_nothing():
    identity = policy("identity", allow("s3:*", "*"))
    boundary = policy("boundary", deny("iam:*", "*"))
    result = evaluate(GET, [identity], boundary=boundary)
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.not_allowed_by == (BOUNDARY,)


def test_boundary_limits_group_policies_too():
    inherited = dataclasses.replace(policy("Shared", allow("s3:*", "*")), via_group="Teachers")
    boundary = policy("boundary", allow("s3:GetObject", "arn:aws:s3:::other/*"))
    result = evaluate(GET, [inherited], boundary=boundary)
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.not_allowed_by == (BOUNDARY,)


# --- Service control policies (SCPs) ---------------------------------------------------

ROOT = OrgTarget(TargetType.ROOT, "Root")
SCHOOLS = OrgTarget(TargetType.ORGANIZATIONAL_UNIT, "Schools")
DISTRICT = OrgTarget(TargetType.ACCOUNT, "111122223333")
FULL_ACCESS = policy("FullAWSAccess", allow("*", "*"))
BROAD_S3 = policy("identity", allow("s3:*", "*", sid="BroadS3"))


def scp(target):
    return Layer(PolicyType.SCP, target)


def org_path(root=(FULL_ACCESS,), ou=(FULL_ACCESS,), account=(FULL_ACCESS,)):
    """SCP levels from the root, through OU Schools, down to the district account."""
    return [
        ScpLevel(ROOT, tuple(root)),
        ScpLevel(SCHOOLS, tuple(ou)),
        ScpLevel(DISTRICT, tuple(account)),
    ]


def test_scps_allowing_at_every_level():
    result = evaluate(GET, [BROAD_S3], scps=org_path())
    assert result.decision is Decision.ALLOW
    assert reasons(result) == [
        ("identity", "BroadS3", IDENTITY),
        ("FullAWSAccess", None, scp(ROOT)),
        ("FullAWSAccess", None, scp(SCHOOLS)),
        ("FullAWSAccess", None, scp(DISTRICT)),
    ]


def test_scp_level_without_an_allow_blocks():
    ec2_only = policy("Ec2Only", allow("ec2:*", "*"))
    result = evaluate(GET, [BROAD_S3], scps=org_path(ou=[ec2_only]))
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.reasons == ()
    assert result.not_allowed_by == (scp(SCHOOLS),)


def test_scp_levels_intersect():
    # The root allows only S3 and the OU allows only EC2, so nothing gets through both.
    s3_only = policy("S3Only", allow("s3:*", "*"))
    ec2_only = policy("Ec2Only", allow("ec2:*", "*"))
    identity = policy("identity", allow("*", "*"))
    scps = org_path(root=[s3_only], ou=[ec2_only])
    s3 = evaluate(GET, [identity], scps=scps)
    assert s3.not_allowed_by == (scp(SCHOOLS),)
    ec2 = evaluate(Request(action="ec2:RunInstances", resource="*"), [identity], scps=scps)
    assert ec2.not_allowed_by == (scp(ROOT),)


def test_any_scp_at_a_level_can_allow():
    ec2_only = policy("Ec2Only", allow("ec2:*", "*"))
    s3_only = policy("S3Only", allow("s3:*", "*", sid="S3"))
    result = evaluate(GET, [BROAD_S3], scps=org_path(ou=[ec2_only, s3_only]))
    assert result.decision is Decision.ALLOW
    assert ("S3Only", "S3", scp(SCHOOLS)) in reasons(result)


def test_scp_deny_beats_every_allow():
    protect = policy("ProtectRecords", deny("s3:*", f"{BUCKET}/*", sid="NoRecords"))
    result = evaluate(GET, [BROAD_S3], scps=org_path(ou=[FULL_ACCESS, protect]))
    assert result.decision is Decision.EXPLICIT_DENY
    assert reasons(result) == [("ProtectRecords", "NoRecords", scp(SCHOOLS))]


def test_scps_never_grant_access():
    result = evaluate(GET, [], scps=org_path())
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.not_allowed_by == (IDENTITY,)


def test_scp_level_with_no_policies_denies():
    result = evaluate(GET, [BROAD_S3], scps=org_path(account=[]))
    assert result.not_allowed_by == (scp(DISTRICT),)


def test_boundary_and_scps_are_both_checked_in_order():
    ec2_only = policy("Ec2Only", allow("ec2:*", "*"))
    result = evaluate(GET, [BROAD_S3], boundary=ec2_only, scps=org_path(root=[ec2_only]))
    assert result.not_allowed_by == (BOUNDARY, scp(ROOT))


# --- Data-driven scenarios -------------------------------------------------------------

SCENARIO_DIR = Path(__file__).parent / "scenarios"
SCENARIOS = sorted(SCENARIO_DIR.glob("*.json"))


@pytest.mark.parametrize("path", SCENARIOS, ids=[p.stem for p in SCENARIOS])
def test_scenario(path):
    scenario = json.loads(path.read_text())
    policies = [parse_policy(doc, name=name) for name, doc in scenario["policies"].items()]
    boundary = None
    if "boundary" in scenario:
        boundary = parse_policy(scenario["boundary"], name="boundary")
    scps = ()
    if "organization" in scenario:
        organization = parse_organization(scenario["organization"], name="organization")
        scps = organization.scp_levels_for(
            scenario["account_id"], service_linked=scenario.get("service_linked", False)
        )
    request = Request(**scenario["request"])
    result = evaluate(request, policies, boundary=boundary, scps=scps)
    assert result.decision is Decision(scenario["expected"]), scenario.get("description")
