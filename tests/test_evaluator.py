import dataclasses
import itertools
import json
from pathlib import Path

import pytest

from iam_analyzer import resources
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import (
    MissingContextError,
    MissingResourceError,
    RequestError,
    UnsupportedPolicyFeature,
)
from iam_analyzer.evaluator import evaluate, statement_matches
from iam_analyzer.loader import parse_policy
from iam_analyzer.models import (
    Decision,
    Layer,
    OrgTarget,
    PolicyType,
    PrincipalMatch,
    Request,
    Resource,
    ScpLevel,
    TargetType,
    WithoutDenies,
)
from iam_analyzer.organization import parse_organization

BUCKET = "arn:aws:s3:::district-student-records"
OBJECT = f"{BUCKET}/2026/roster.csv"
GET = Request(action="s3:GetObject", resource=OBJECT)


def check(request, policies, **layers):
    """Evaluate `request` with its resource described as having no resource-based policy, as
    `--no-resource-policy` describes it. Most tests here are about the other layers."""
    resource = resources.describe(request.resource, request.action)
    return evaluate(request, policies, resource=resource, **layers)


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
    assert check(literal, [p]).decision is Decision.ALLOW
    assert check(named, [p]).decision is Decision.IMPLICIT_DENY


def test_no_policies_is_implicit_deny():
    result = check(GET, [])
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.reasons == ()
    assert not result.allowed


def test_matching_allow():
    result = check(GET, [policy("p", allow("s3:GetObject", OBJECT, sid="A"))])
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
    assert check(GET, [policy("p", statement)]).decision is Decision.IMPLICIT_DENY


def test_action_and_resource_must_both_match_in_the_same_statement():
    # One statement allows the action elsewhere, another allows a different action here.
    p = policy("p", allow("s3:GetObject", "arn:aws:s3:::other/*"), allow("s3:PutObject", OBJECT))
    assert check(GET, [p]).decision is Decision.IMPLICIT_DENY


def test_wildcard_allow():
    p = policy("p", allow("s3:Get*", f"{BUCKET}/*"))
    assert check(GET, [p]).decision is Decision.ALLOW


def test_any_entry_in_action_and_resource_lists_can_match():
    p = policy("p", allow(["ec2:*", "s3:GetObject"], ["arn:aws:s3:::other/*", f"{BUCKET}/*"]))
    assert check(GET, [p]).decision is Decision.ALLOW


def test_explicit_deny_beats_allow_in_any_order():
    statements = [allow("s3:*", "*", sid="AllowAll"), deny("s3:GetObject", OBJECT, sid="NoGet")]
    for ordering in itertools.permutations(statements):
        # Same policy, both orders.
        assert check(GET, [policy("p", *ordering)]).decision is Decision.EXPLICIT_DENY
        # Separate policies, both orders.
        policies = [policy(f"p{i}", s) for i, s in enumerate(ordering)]
        assert check(GET, policies).decision is Decision.EXPLICIT_DENY


def test_explicit_deny_reasons_list_only_denies():
    policies = [
        policy("allow.json", allow("s3:*", "*", sid="AllowAll")),
        policy("deny.json", deny("s3:Get*", f"{BUCKET}/*", sid="NoGet")),
    ]
    result = check(GET, policies)
    assert [(r.policy_name, r.statement.sid) for r in result.reasons] == [("deny.json", "NoGet")]


def test_deny_alone_is_explicit_deny():
    result = check(GET, [policy("p", deny("*", "*"))])
    assert result.decision is Decision.EXPLICIT_DENY


def test_non_matching_deny_does_not_block_allow():
    p = policy("p", allow("s3:*", "*"), deny("s3:DeleteObject", f"{BUCKET}/*"))
    assert check(GET, [p]).decision is Decision.ALLOW


def test_all_matching_allows_are_reported():
    policies = [
        policy("a.json", allow("s3:GetObject", OBJECT, sid="One")),
        policy("b.json", allow("s3:*", "*", sid="Two")),
    ]
    result = check(GET, policies)
    assert [r.statement.sid for r in result.reasons] == ["One", "Two"]


def test_via_group_is_carried_into_reasons():
    direct = policy("Direct", allow("s3:GetObject", OBJECT))
    inherited = dataclasses.replace(policy("Shared", allow("s3:*", "*")), via_group="Teachers")
    result = check(GET, [direct, inherited])
    assert [(r.policy_name, r.via_group) for r in result.reasons] == [
        ("Direct", None),
        ("Shared", "Teachers"),
    ]


def test_reasons_say_where_each_statement_is_in_its_policy():
    # Statements without a Sid can still be named: "p statement 2".
    p = policy("p", allow("s3:PutObject", "*"), allow("s3:GetObject", OBJECT), allow("s3:*", "*"))
    assert [r.index for r in check(GET, [p]).reasons] == [1, 2]
    denied = check(GET, [policy("q", allow("s3:*", "*"), deny("s3:Get*", "*"))])
    assert [r.index for r in denied.reasons] == [1]


# --- NotAction / NotResource -----------------------------------------------------------


def statement(effect, sid=None, **elements):
    return {"Sid": sid, "Effect": effect, **elements}


def test_allow_not_action_allows_everything_except_listed():
    p = policy("p", statement("Allow", NotAction="s3:Delete*", Resource="*"))
    assert check(GET, [p]).decision is Decision.ALLOW
    delete = Request(action="s3:DeleteObject", resource=OBJECT)
    assert check(delete, [p]).decision is Decision.IMPLICIT_DENY


def test_deny_not_action_guardrail_blocks_everything_except_listed():
    guardrail = statement(
        "Deny", sid="ReadOnly", NotAction=["s3:Get*", "s3:List*"], Resource=f"{BUCKET}/*"
    )
    policies = [policy("p", allow("s3:*", "*"), guardrail)]
    assert check(GET, policies).decision is Decision.ALLOW
    put = Request(action="s3:PutObject", resource=OBJECT)
    result = check(put, policies)
    assert result.decision is Decision.EXPLICIT_DENY
    assert [r.statement.sid for r in result.reasons] == ["ReadOnly"]


def test_deny_not_action_only_applies_to_its_resource():
    guardrail = statement("Deny", NotAction="s3:Get*", Resource=f"{BUCKET}/*")
    put_elsewhere = Request(action="s3:PutObject", resource="arn:aws:s3:::other/file")
    p = policy("p", allow("s3:*", "*"), guardrail)
    assert check(put_elsewhere, [p]).decision is Decision.ALLOW


def test_allow_not_resource_allows_everywhere_except_listed():
    p = policy("p", statement("Allow", Action="s3:GetObject", NotResource=f"{BUCKET}/*"))
    assert check(GET, [p]).decision is Decision.IMPLICIT_DENY
    other = Request(action="s3:GetObject", resource="arn:aws:s3:::other/file")
    assert check(other, [p]).decision is Decision.ALLOW


def test_deny_not_resource_blocks_everywhere_except_listed():
    p = policy(
        "p",
        allow("s3:*", "*"),
        statement("Deny", Action="s3:*", NotResource=[BUCKET, f"{BUCKET}/*"]),
    )
    assert check(GET, [p]).decision is Decision.ALLOW
    other = Request(action="s3:GetObject", resource="arn:aws:s3:::other/file")
    assert check(other, [p]).decision is Decision.EXPLICIT_DENY


def test_not_action_with_not_resource():
    # Deny anything except reads, anywhere except the public bucket.
    p = policy(
        "p",
        allow("*", "*"),
        statement("Deny", NotAction="s3:Get*", NotResource="arn:aws:s3:::public/*"),
    )

    def decide(action, resource):
        return check(Request(action=action, resource=resource), [p]).decision

    assert decide("s3:GetObject", OBJECT) is Decision.ALLOW  # read: excluded action
    assert decide("s3:PutObject", "arn:aws:s3:::public/x") is Decision.ALLOW  # excluded resource
    assert decide("s3:PutObject", OBJECT) is Decision.EXPLICIT_DENY  # neither excluded


# --- Permissions boundaries ------------------------------------------------------------

IDENTITY = Layer(PolicyType.IDENTITY)
BOUNDARY = Layer(PolicyType.PERMISSIONS_BOUNDARY)


def reasons(result):
    return [(r.policy_name, r.statement.sid, r.layer) for r in result.reasons]


def test_without_boundary_implicit_deny_names_identity_layer():
    result = check(GET, [policy("p", allow("s3:PutObject", OBJECT))])
    assert result.not_allowed_by == (IDENTITY,)


def test_identity_and_boundary_both_allow():
    identity = policy("identity", allow("s3:*", "*", sid="BroadS3"))
    boundary = policy("boundary", allow("s3:GetObject", f"{BUCKET}/*", sid="ReadRecords"))
    result = check(GET, [identity], boundary=boundary)
    assert result.decision is Decision.ALLOW
    assert result.not_allowed_by == ()
    assert reasons(result) == [
        ("identity", "BroadS3", IDENTITY),
        ("boundary", "ReadRecords", BOUNDARY),
    ]


def test_boundary_blocks_what_identity_allows():
    identity = policy("identity", allow("s3:*", "*"))
    boundary = policy("boundary", allow("s3:*", "arn:aws:s3:::district-gradebook-app/*"))
    result = check(GET, [identity], boundary=boundary)
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.reasons == ()
    assert result.not_allowed_by == (BOUNDARY,)


def test_boundary_never_grants_access():
    identity = policy("identity", allow("s3:PutObject", OBJECT))
    boundary = policy("boundary", allow("*", "*"))
    result = check(GET, [identity], boundary=boundary)
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.not_allowed_by == (IDENTITY,)


def test_every_layer_without_an_allow_is_listed_in_order():
    boundary = policy("boundary", allow("ec2:*", "*"))
    result = check(GET, [], boundary=boundary)
    assert result.not_allowed_by == (IDENTITY, BOUNDARY)


def test_deny_in_boundary_is_an_explicit_deny():
    identity = policy("identity", allow("s3:*", "*"))
    boundary = policy("boundary", allow("s3:*", "*"), deny("s3:GetObject", OBJECT, sid="NoGet"))
    result = check(GET, [identity], boundary=boundary)
    assert result.decision is Decision.EXPLICIT_DENY
    assert reasons(result) == [("boundary", "NoGet", BOUNDARY)]


def test_denies_from_every_layer_are_reported():
    identity = policy("identity", allow("s3:*", "*"), deny("s3:Get*", "*", sid="IdentityDeny"))
    boundary = policy("boundary", deny("s3:GetObject", OBJECT, sid="BoundaryDeny"))
    result = check(GET, [identity], boundary=boundary)
    assert reasons(result) == [
        ("identity", "IdentityDeny", IDENTITY),
        ("boundary", "BoundaryDeny", BOUNDARY),
    ]


def test_boundary_with_only_denies_allows_nothing():
    identity = policy("identity", allow("s3:*", "*"))
    boundary = policy("boundary", deny("iam:*", "*"))
    result = check(GET, [identity], boundary=boundary)
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.not_allowed_by == (BOUNDARY,)


def test_boundary_limits_group_policies_too():
    inherited = dataclasses.replace(policy("Shared", allow("s3:*", "*")), via_group="Teachers")
    boundary = policy("boundary", allow("s3:GetObject", "arn:aws:s3:::other/*"))
    result = check(GET, [inherited], boundary=boundary)
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
    result = check(GET, [BROAD_S3], scps=org_path())
    assert result.decision is Decision.ALLOW
    assert reasons(result) == [
        ("identity", "BroadS3", IDENTITY),
        ("FullAWSAccess", None, scp(ROOT)),
        ("FullAWSAccess", None, scp(SCHOOLS)),
        ("FullAWSAccess", None, scp(DISTRICT)),
    ]


def test_scp_level_without_an_allow_blocks():
    ec2_only = policy("Ec2Only", allow("ec2:*", "*"))
    result = check(GET, [BROAD_S3], scps=org_path(ou=[ec2_only]))
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.reasons == ()
    assert result.not_allowed_by == (scp(SCHOOLS),)


def test_scp_levels_intersect():
    # The root allows only S3 and the OU allows only EC2, so nothing gets through both.
    s3_only = policy("S3Only", allow("s3:*", "*"))
    ec2_only = policy("Ec2Only", allow("ec2:*", "*"))
    identity = policy("identity", allow("*", "*"))
    scps = org_path(root=[s3_only], ou=[ec2_only])
    s3 = check(GET, [identity], scps=scps)
    assert s3.not_allowed_by == (scp(SCHOOLS),)
    ec2 = check(Request(action="ec2:RunInstances", resource="*"), [identity], scps=scps)
    assert ec2.not_allowed_by == (scp(ROOT),)


def test_any_scp_at_a_level_can_allow():
    ec2_only = policy("Ec2Only", allow("ec2:*", "*"))
    s3_only = policy("S3Only", allow("s3:*", "*", sid="S3"))
    result = check(GET, [BROAD_S3], scps=org_path(ou=[ec2_only, s3_only]))
    assert result.decision is Decision.ALLOW
    assert ("S3Only", "S3", scp(SCHOOLS)) in reasons(result)


def test_scp_deny_beats_every_allow():
    protect = policy("ProtectRecords", deny("s3:*", f"{BUCKET}/*", sid="NoRecords"))
    result = check(GET, [BROAD_S3], scps=org_path(ou=[FULL_ACCESS, protect]))
    assert result.decision is Decision.EXPLICIT_DENY
    assert reasons(result) == [("ProtectRecords", "NoRecords", scp(SCHOOLS))]


def test_scps_never_grant_access():
    result = check(GET, [], scps=org_path())
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.not_allowed_by == (IDENTITY,)


def test_scp_level_with_no_policies_denies():
    result = check(GET, [BROAD_S3], scps=org_path(account=[]))
    assert result.not_allowed_by == (scp(DISTRICT),)


def test_boundary_and_scps_are_both_checked_in_order():
    ec2_only = policy("Ec2Only", allow("ec2:*", "*"))
    result = check(GET, [BROAD_S3], boundary=ec2_only, scps=org_path(root=[ec2_only]))
    assert result.not_allowed_by == (BOUNDARY, scp(ROOT))


# --- Policy variables and the request context ------------------------------------------

HOME = "arn:aws:s3:::district-staff-files/home"
OWN_HOME = f"{HOME}/${{aws:username}}/*"


def versioned(name, *statements):
    """A policy with "Version": "2012-10-17", where ${...} is a policy variable."""
    return parse_policy({"Version": "2012-10-17", "Statement": list(statements)}, name=name)


def home_request(folder, values=(), absent=()):
    context = RequestContext.of(values, absent)
    return Request(action="s3:GetObject", resource=f"{HOME}/{folder}/a.txt", context=context)


JSMITH = [("aws:username", "jsmith")]


def test_policy_variable_is_filled_in_from_the_context():
    p = versioned("home", allow("s3:GetObject", OWN_HOME))
    assert check(home_request("jsmith", JSMITH), [p]).decision is Decision.ALLOW
    assert check(home_request("mgarcia", JSMITH), [p]).decision is Decision.IMPLICIT_DENY


def test_deny_with_a_policy_variable_applies():
    p = versioned("p", allow("s3:*", "*"), deny("s3:GetObject", OWN_HOME, sid="NotOwnFolder"))
    result = check(home_request("jsmith", JSMITH), [p])
    assert result.decision is Decision.EXPLICIT_DENY
    assert [r.statement.sid for r in result.reasons] == ["NotOwnFolder"]


def test_not_resource_with_a_policy_variable():
    # Deny reads anywhere except the caller's own home folder.
    p = versioned(
        "p", allow("s3:*", "*"), statement("Deny", Action="s3:GetObject", NotResource=OWN_HOME)
    )
    assert check(home_request("jsmith", JSMITH), [p]).decision is Decision.ALLOW
    assert check(home_request("mgarcia", JSMITH), [p]).decision is Decision.EXPLICIT_DENY


def test_policy_variables_work_in_boundaries_and_scps():
    own_only = versioned("OwnHomeOnly", allow("s3:*", OWN_HOME))
    for kwargs in ({"boundary": own_only}, {"scps": org_path(ou=[own_only])}):
        assert check(home_request("jsmith", JSMITH), [BROAD_S3], **kwargs).allowed
        result = check(home_request("mgarcia", JSMITH), [BROAD_S3], **kwargs)
        assert result.decision is Decision.IMPLICIT_DENY


def test_missing_keys_are_all_named_with_the_statements_that_use_them():
    identity = versioned("home", allow("s3:GetObject", OWN_HOME, sid="Own"))
    boundary = versioned(
        "teams",
        allow("s3:*", f"{HOME}/${{aws:PrincipalTag/team}}/*"),
        allow("s3:*", f"{HOME}/${{AWS:Username}}/*"),
    )
    with pytest.raises(MissingContextError) as exc:
        check(home_request("jsmith"), [identity], boundary=boundary)
    assert exc.value.keys == ("aws:username", "aws:PrincipalTag/team")
    assert str(exc.value) == (
        "the request context says nothing about these condition keys:\n"
        "  aws:username, used by home statement 0 (Sid=Own); teams statement 1\n"
        "  aws:PrincipalTag/team, used by teams statement 0"
    )


def test_keys_are_only_needed_when_the_action_matches():
    p = versioned("p", allow("s3:PutObject", OWN_HOME), allow("s3:GetObject", "*"))
    assert check(home_request("jsmith"), [p]).decision is Decision.ALLOW


def test_a_variable_with_no_value_matches_nothing():
    # AWS: "the resource that includes a policy variable with no value will not match any
    # resource" (variables_without_a_value/*).
    no_user = home_request("jsmith", absent=["aws:username"])
    own = versioned("home", allow("s3:GetObject", OWN_HOME, sid="Own"))
    assert check(no_user, [own]).decision is Decision.IMPLICIT_DENY
    # So a NotResource with it excludes nothing, and the Deny applies.
    others = versioned("others", statement("Deny", Action="s3:GetObject", NotResource=OWN_HOME))
    result = check(no_user, [BROAD_S3, others])
    assert result.decision is Decision.EXPLICIT_DENY


def test_a_variable_from_a_key_with_several_values_matches_nothing():
    # As AWS's IAM policy simulator showed (variables_with_several_values/*).
    two_users = home_request("jsmith", [("aws:username", "jsmith"), ("aws:username", "mgarcia")])
    own = versioned("home", allow("s3:GetObject", OWN_HOME))
    assert check(two_users, [own]).decision is Decision.IMPLICIT_DENY


def test_a_star_in_a_variables_value_is_literal():
    # As AWS's IAM policy simulator showed (variables_with_wildcards/star_in_a_value).
    own = versioned("home", allow("s3:GetObject", OWN_HOME))
    assert check(home_request("jsmith", [("aws:username", "j*")]), [own]).decision is (
        Decision.IMPLICIT_DENY
    )
    assert check(home_request("j*", [("aws:username", "j*")]), [own]).decision is Decision.ALLOW


def test_without_variables_the_context_is_never_read():
    # GET has an empty context, and nothing here uses a policy variable.
    assert check(GET, [versioned("p", allow("s3:GetObject", OBJECT))]).allowed


# --- Conditions ------------------------------------------------------------------------


def get_with(*values):
    return Request(action="s3:GetObject", resource=OBJECT, context=RequestContext.of(values))


REGION_LOCK = versioned("RegionLock", {
    "Sid": "ApprovedRegionsOnly", "Effect": "Deny", "NotAction": ["iam:*", "sts:*"],
    "Resource": "*",
    "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-east-2"]}},
})


def test_an_scp_condition_can_deny():
    scps = org_path(ou=[FULL_ACCESS, REGION_LOCK])
    approved = get_with(("aws:RequestedRegion", "us-east-1"))
    assert check(approved, [BROAD_S3], scps=scps).decision is Decision.ALLOW
    result = check(get_with(("aws:RequestedRegion", "eu-west-1")), [BROAD_S3], scps=scps)
    assert result.decision is Decision.EXPLICIT_DENY
    assert reasons(result) == [("RegionLock", "ApprovedRegionsOnly", scp(SCHOOLS))]


def test_a_boundary_condition_limits_access():
    district_network = versioned("DistrictNetwork", {
        "Effect": "Allow", "Action": "s3:*", "Resource": "*",
        "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
    })
    inside = get_with(("aws:SourceIp", "10.1.2.3"))
    assert check(inside, [BROAD_S3], boundary=district_network).allowed
    outside = get_with(("aws:SourceIp", "198.51.100.7"))
    result = check(outside, [BROAD_S3], boundary=district_network)
    assert result.decision is Decision.IMPLICIT_DENY
    assert result.not_allowed_by == (BOUNDARY,)


def test_condition_keys_are_only_needed_once_action_and_resource_match():
    p = versioned("p", allow("s3:GetObject", "*"), {
        "Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::other/*",
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    })
    # The Deny is for another bucket, so whether GET used HTTPS doesn't matter.
    assert check(GET, [p]).allowed
    other = Request(action="s3:GetObject", resource="arn:aws:s3:::other/x")
    with pytest.raises(MissingContextError, match="aws:SecureTransport, used by p statement 1"):
        check(other, [p])


# --- Describing the resource -----------------------------------------------------------

USER_ARN = "arn:aws:iam::111122223333:user/jsmith"
ALLOW_ALL = policy("p", allow("*", "*"))


def in_account(account, action="iam:ChangePassword", resource=USER_ARN):
    """A request from a principal in `account`."""
    context = RequestContext.of([("aws:PrincipalAccount", account)])
    return Request(action=action, resource=resource, context=context)


def test_a_request_on_an_undescribed_bucket_is_refused():
    message = f"^nothing describes {BUCKET}: it can have a resource-based policy"
    with pytest.raises(MissingResourceError, match=message) as exc:
        evaluate(GET, [ALLOW_ALL])
    assert exc.value.resource == BUCKET


def test_even_a_deny_needs_the_resource_described():
    # As with an unknown condition key, the analyzer doesn't answer without what it needs.
    with pytest.raises(MissingResourceError):
        evaluate(GET, [policy("p", deny("*", "*"))])


def test_a_bucket_is_described_for_its_objects():
    assert evaluate(GET, [ALLOW_ALL], resource=Resource(BUCKET)).allowed


def test_the_description_must_be_of_the_bucket():
    with pytest.raises(RequestError, match=f"needs {BUCKET} described, not {OBJECT}"):
        evaluate(GET, [ALLOW_ALL], resource=Resource(OBJECT))


def test_iam_sts_and_star_resources_need_no_description():
    assert evaluate(in_account("111122223333"), [ALLOW_ALL]).allowed
    federation = in_account(
        "111122223333", "sts:GetFederationToken", "arn:aws:sts::111122223333:federated-user/bob"
    )
    assert evaluate(federation, [ALLOW_ALL]).allowed
    assert evaluate(Request(action="s3:ListAllMyBuckets", resource="*"), [ALLOW_ALL]).allowed


def test_a_request_on_an_iam_resource_needs_the_principals_account():
    with pytest.raises(MissingContextError) as exc:
        evaluate(Request(action="iam:ChangePassword", resource=USER_ARN), [ALLOW_ALL])
    assert exc.value.keys == ("aws:PrincipalAccount",)
    assert str(exc.value).splitlines()[1] == (
        f"  aws:PrincipalAccount, used by the check that {USER_ARN} is in the principal's account"
    )


def test_a_request_on_another_accounts_resource_is_refused():
    message = (
        f"^{USER_ARN} is in account 111122223333, and the principal is in account 444455556666: "
        "cross-account requests aren't supported yet$"
    )
    with pytest.raises(UnsupportedPolicyFeature, match=message):
        evaluate(in_account("444455556666"), [ALLOW_ALL])


def test_a_described_resource_is_in_the_principals_account():
    queue = "arn:aws:sqs:us-east-1:444455556666:vendor-alerts"
    send = Request(action="sqs:SendMessage", resource=queue)
    assert evaluate(send, [ALLOW_ALL], resource=Resource(queue)).allowed
    # But not when the principal's account is known to be another one.
    from_district = in_account("111122223333", "sqs:SendMessage", queue)
    with pytest.raises(UnsupportedPolicyFeature, match="cross-account"):
        evaluate(from_district, [ALLOW_ALL], resource=Resource(queue))


def test_the_principals_account_is_never_absent():
    context = RequestContext.of(absent=["aws:PrincipalAccount"])
    request = Request(action="iam:ChangePassword", resource=USER_ARN, context=context)
    with pytest.raises(RequestError, match="needs exactly one value"):
        evaluate(request, [ALLOW_ALL])


def test_kms_keys_are_refused():
    key = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    with pytest.raises(UnsupportedPolicyFeature, match="KMS isn't supported yet"):
        evaluate(Request(action="kms:Decrypt", resource=key), [ALLOW_ALL])


def test_a_role_needs_its_trust_policy():
    role = "arn:aws:iam::111122223333:role/ITAdmin"
    request = in_account("111122223333", "sts:AssumeRole", role)
    message = f"^nothing gives the trust policy of {role}, which every role has"
    with pytest.raises(MissingResourceError, match=message):
        evaluate(request, [ALLOW_ALL])
    with pytest.raises(RequestError, match="every role has a trust policy that must allow"):
        evaluate(request, [ALLOW_ALL], resource=Resource(role))


def test_only_s3_bucket_policies_and_trust_policies_are_evaluated():
    queue = "arn:aws:sqs:us-east-1:111122223333:district-alerts"
    send = Request(action="sqs:SendMessage", resource=queue)
    with pytest.raises(UnsupportedPolicyFeature, match="only S3 bucket policies and role trust"):
        evaluate(send, [ALLOW_ALL], resource=Resource(queue, policy=ALLOW_ALL))


def test_a_policy_for_a_request_that_no_resource_based_policy_covers():
    message = "no resource-based policy applies to iam:ChangePassword"
    with pytest.raises(RequestError, match=message):
        evaluate(in_account("111122223333"), [ALLOW_ALL], resource=Resource(USER_ARN, ALLOW_ALL))


# --- s3:ListAllMyBuckets ---------------------------------------------------------------

LIST_BUCKETS = Request(action="s3:ListAllMyBuckets", resource="*")
# AWS's Carlos example: "The AllowS3ListRead statement in this policy allows Carlos to view a list
# of all of the buckets in the account". tests/scenarios has the whole example.
LIST_READ = allow(
    ["s3:GetBucketLocation", "s3:ListAllMyBuckets"], "arn:aws:s3:::*", sid="AllowS3ListRead"
)


def test_the_carlos_example_lists_every_bucket():
    # The example's Deny on *log*, which "denies Carlos access to any S3 bucket with log in its
    # name", doesn't stop the listing.
    p = policy("carlos", LIST_READ, deny("s3:*", "arn:aws:s3:::*log*", sid="DenyS3Logs"))
    result = evaluate(LIST_BUCKETS, [p])
    assert result.decision is Decision.ALLOW
    assert reasons(result) == [("carlos", "AllowS3ListRead", IDENTITY)]


@pytest.mark.parametrize(
    "resource", ["*", "arn:aws:s3:::*", "arn:aws:s3:::**", "arn:*:s3:::*", "arn:aws:s3"]
)
def test_a_statement_on_every_bucket_covers_listing_them(resource):
    # The request is matched as arn:aws:s3:::, a bucket ARN with an empty name.
    p = policy("p", allow("s3:ListAllMyBuckets", resource))
    assert evaluate(LIST_BUCKETS, [p]).decision is Decision.ALLOW


@pytest.mark.parametrize(
    "resource",
    [
        "arn:aws:s3:::*log*",  # needs characters in the name
        "arn:aws:s3:::district-kwong-files",  # names a bucket
        "arn:aws:s3:::district-*",
        "arn:aws:s3:::*/*",  # every object, not every bucket
        "arn:aws:ec2:*:*:instance/*",
    ],
)
def test_a_statement_on_some_buckets_does_not_cover_listing_them(resource):
    assert evaluate(LIST_BUCKETS, [policy("p", allow("s3:*", resource))]).decision is (
        Decision.IMPLICIT_DENY
    )
    # Nor does a Deny on them stop the listing.
    p = policy("p", allow("s3:ListAllMyBuckets", "*"), deny("s3:*", resource))
    assert evaluate(LIST_BUCKETS, [p]).decision is Decision.ALLOW


def test_not_resource_is_matched_the_same_way():
    allow_listing = allow("s3:ListAllMyBuckets", "*")
    # A Deny on everything but every bucket doesn't apply to the listing.
    but_every_bucket = {"Effect": "Deny", "Action": "s3:*", "NotResource": "arn:aws:s3:::*"}
    assert evaluate(LIST_BUCKETS, [policy("p", allow_listing, but_every_bucket)]).allowed
    # A Deny on everything but some buckets does.
    but_some = {"Effect": "Deny", "Action": "s3:*", "NotResource": "arn:aws:s3:::district-*"}
    result = evaluate(LIST_BUCKETS, [policy("p", allow_listing, but_some)])
    assert result.decision is Decision.EXPLICIT_DENY


def test_other_requests_on_star_are_not_covered_by_arns():
    # The Service Authorization Reference: for an action with no resource type, "you must specify
    # all resources ("*") in your policy".
    p = policy(
        "p",
        allow("ec2:*", "arn:aws:ec2:*:*:instance/*"),
        allow("s3:GetAccountPublicAccessBlock", "arn:aws:s3:::*"),
    )
    for action in ("ec2:DescribeInstances", "s3:GetAccountPublicAccessBlock"):
        assert evaluate(Request(action=action, resource="*"), [p]).decision is Decision.IMPLICIT_DENY


def test_statement_matches_reads_the_listing_the_same_way():
    [statement] = policy("carlos", LIST_READ).statements
    assert statement_matches(statement, LIST_BUCKETS)


# --- Resource-based policies -----------------------------------------------------------

KWONG = "arn:aws:iam::111122223333:user/kwong"
CAMPUS_APP = "arn:aws:iam::111122223333:role/district/CampusApp"
RESOURCE = Layer(PolicyType.RESOURCE_BASED, resource=BUCKET)
NO_S3 = policy("NoS3", allow("ec2:*", "*"))


def bucket_policy(*statements):
    document = {"Version": "2012-10-17", "Statement": list(statements)}
    return parse_policy(document, name=BUCKET, kind=PolicyType.RESOURCE_BASED)


def grant(principal, effect="Allow", sid=None, **elements):
    return {"Sid": sid, "Effect": effect, "Principal": principal, "Action": "s3:GetObject",
            "Resource": f"{BUCKET}/*", **elements}


def get_by(arn, *values):
    context = RequestContext.of([("aws:PrincipalArn", arn), *values])
    return Request(action="s3:GetObject", resource=OBJECT, context=context)


def with_bucket_policy(request, policies, *statements, **layers):
    described = Resource(BUCKET, bucket_policy(*statements))
    return evaluate(request, policies, resource=described, **layers)


@pytest.mark.parametrize(
    "caller, principal, boundary, decision",
    [
        # A grant to the user isn't limited by their identity policies or boundary.
        (KWONG, {"AWS": KWONG}, None, Decision.ALLOW),
        (KWONG, {"AWS": KWONG}, NO_S3, Decision.ALLOW),
        # Neither is a grant to everyone (a judgment call).
        (KWONG, "*", NO_S3, Decision.ALLOW),
        (CAMPUS_APP, "*", NO_S3, Decision.ALLOW),
        # A grant to the role needs no identity policy, but the role's boundary limits it.
        (CAMPUS_APP, {"AWS": CAMPUS_APP}, None, Decision.ALLOW),
        (CAMPUS_APP, {"AWS": CAMPUS_APP}, NO_S3, Decision.IMPLICIT_DENY),
        # A grant to the account delegates to its identity policies, which don't allow S3 here.
        (KWONG, {"AWS": "111122223333"}, None, Decision.IMPLICIT_DENY),
        (CAMPUS_APP, {"AWS": "arn:aws:iam::111122223333:root"}, None, Decision.IMPLICIT_DENY),
        # Naming someone else grants the caller nothing.
        (KWONG, {"AWS": "arn:aws:iam::111122223333:user/jsmith"}, None, Decision.IMPLICIT_DENY),
        (KWONG, {"AWS": "arn:aws:iam::111122223333:user/KWONG"}, None, Decision.IMPLICIT_DENY),
        (CAMPUS_APP, {"Service": "cloudtrail.amazonaws.com"}, None, Decision.IMPLICIT_DENY),
    ],
)
def test_what_a_bucket_policy_grant_still_needs(caller, principal, boundary, decision):
    # The caller's identity policy doesn't allow S3, so only the bucket policy can.
    layers = {"boundary": boundary} if boundary else {}
    result = with_bucket_policy(get_by(caller), [NO_S3], grant(principal), **layers)
    assert result.decision is decision


def test_identity_policies_alone_still_allow():
    result = with_bucket_policy(get_by(KWONG), [BROAD_S3], grant({"AWS": "444455556666"}))
    assert result.decision is Decision.ALLOW
    assert reasons(result) == [("identity", "BroadS3", IDENTITY)]


def test_a_grant_to_the_account_works_with_an_identity_allow():
    to_account = grant({"AWS": "111122223333"}, sid="Acct")
    result = with_bucket_policy(get_by(KWONG), [BROAD_S3], to_account)
    assert result.decision is Decision.ALLOW
    assert [(r.statement.sid, r.layer, r.principal_match) for r in result.reasons] == [
        ("BroadS3", IDENTITY, None),
        ("Acct", RESOURCE, PrincipalMatch.ACCOUNT),
    ]


def test_allow_reasons_say_how_the_principal_matched():
    result = with_bucket_policy(get_by(KWONG), [], grant({"AWS": KWONG}, sid="Counselor"))
    [reason] = result.reasons
    assert (reason.policy_name, reason.statement.sid, reason.layer, reason.principal_match) == (
        BUCKET, "Counselor", RESOURCE, PrincipalMatch.USER
    )


def test_a_bucket_policy_deny_wins():
    result = with_bucket_policy(get_by(KWONG), [BROAD_S3], grant("*", effect="Deny", sid="NoOne"))
    assert result.decision is Decision.EXPLICIT_DENY
    assert reasons(result) == [(BUCKET, "NoOne", RESOURCE)]


def test_a_deny_naming_the_account_covers_its_users():
    deny_account = grant({"AWS": "111122223333"}, effect="Deny")
    result = with_bucket_policy(get_by(KWONG), [BROAD_S3], deny_account)
    assert result.decision is Decision.EXPLICIT_DENY


def test_a_deny_in_identity_policies_beats_a_bucket_policy_grant():
    no_get = policy("NoGet", deny("s3:GetObject", "*"))
    assert with_bucket_policy(get_by(KWONG), [no_get], grant({"AWS": KWONG})).decision is (
        Decision.EXPLICIT_DENY
    )


def test_not_allowed_by_lists_the_bucket_policy_when_it_grants_nothing():
    result = with_bucket_policy(get_by(KWONG), [NO_S3], grant({"AWS": "444455556666"}))
    assert result.not_allowed_by == (IDENTITY, RESOURCE)


def test_not_allowed_by_names_only_the_boundary_for_a_role_grant():
    result = with_bucket_policy(get_by(CAMPUS_APP), [NO_S3], grant({"AWS": CAMPUS_APP}),
                                boundary=NO_S3)
    assert result.not_allowed_by == (BOUNDARY,)


def test_not_allowed_by_doesnt_list_a_delegating_bucket_policy():
    result = with_bucket_policy(get_by(KWONG), [NO_S3], grant({"AWS": "111122223333"}))
    assert result.not_allowed_by == (IDENTITY,)


def test_scps_still_limit_a_bucket_policy_grant():
    ec2_only = policy("Ec2Only", allow("ec2:*", "*"))
    result = with_bucket_policy(get_by(KWONG), [], grant({"AWS": KWONG}),
                                scps=org_path(ou=[ec2_only]))
    assert result.decision is Decision.IMPLICIT_DENY
    # The bucket policy isn't listed: no grant gets a request past an SCP.
    assert result.not_allowed_by == (scp(SCHOOLS),)


def test_the_caller_is_needed_unless_the_principal_is_everyone():
    anonymous_context = Request(action="s3:GetObject", resource=OBJECT)
    with pytest.raises(MissingContextError) as exc:
        with_bucket_policy(anonymous_context, [], grant({"AWS": KWONG}, sid="Counselor"))
    assert exc.value.keys == ("aws:PrincipalArn",)
    assert f"aws:PrincipalArn, used by {BUCKET} statement 0 (Sid=Counselor)" in str(exc.value)
    assert with_bucket_policy(anonymous_context, [], grant("*")).allowed


def test_condition_keys_are_needed_only_once_the_principal_matches():
    on_campus = grant({"AWS": "arn:aws:iam::111122223333:user/jsmith"},
                      Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})
    # The statement is about jsmith, so kwong's request doesn't need aws:SourceIp.
    assert with_bucket_policy(get_by(KWONG), [BROAD_S3], on_campus).allowed


def test_a_refused_principal_only_matters_when_the_statement_could_apply():
    canonical = {"CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef"}
    off_campus = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
    deny = grant(canonical, effect="Deny", Condition=off_campus)
    outside = get_by(KWONG, ("aws:SourceIp", "198.51.100.7"))
    assert with_bucket_policy(outside, [BROAD_S3], deny).allowed  # the condition fails
    inside = get_by(KWONG, ("aws:SourceIp", "10.1.2.3"))
    with pytest.raises(UnsupportedPolicyFeature, match="S3 canonical user IDs"):
        with_bucket_policy(inside, [BROAD_S3], deny)


def test_a_direct_match_makes_a_refused_principal_moot():
    principal = {"AWS": KWONG, "CanonicalUser": "79a59df900b949e5"}
    assert with_bucket_policy(get_by(KWONG), [], grant(principal)).allowed


def test_principals_the_analyzer_cannot_check_are_refused():
    session = "arn:aws:sts::111122223333:assumed-role/CampusApp/nightly-export"
    lowercase = CAMPUS_APP.replace("CampusApp", "campusapp")
    cases = [
        (CAMPUS_APP, {"AWS": session}, "doesn't know the session's name"),
        (CAMPUS_APP, {"AWS": lowercase}, "only if case is ignored"),
        (KWONG, {"AWS": "AIDAJQABLZS4A3QDU576Q"}, "is an IAM unique ID"),
    ]
    for caller, principal, message in cases:
        with pytest.raises(UnsupportedPolicyFeature, match=message):
            with_bucket_policy(get_by(caller), [], grant(principal))


def test_a_session_of_another_role_is_not_the_caller():
    other = {"AWS": "arn:aws:sts::111122223333:assumed-role/OtherApp/nightly-export"}
    assert with_bucket_policy(get_by(CAMPUS_APP), [], grant(other)).decision is (
        Decision.IMPLICIT_DENY
    )


def test_resource_based_policies_are_for_iam_users_and_role_sessions():
    root = get_by("arn:aws:iam::111122223333:root")
    with pytest.raises(UnsupportedPolicyFeature, match="IAM users and role sessions"):
        with_bucket_policy(root, [], grant({"AWS": KWONG}))


# --- Trust policies --------------------------------------------------------------------

ITADMIN = "arn:aws:iam::111122223333:role/ITAdmin"
ALEE = "arn:aws:iam::111122223333:user/alee"
TRUST = Layer(PolicyType.TRUST, resource=ITADMIN)
ASSUME = policy("Assume", allow("sts:AssumeRole", ITADMIN, sid="Assume"))


def trust_policy(*statements):
    document = {"Version": "2012-10-17", "Statement": list(statements)}
    return parse_policy(document, name=ITADMIN, kind=PolicyType.TRUST)


def trusts(principal, effect="Allow", action="sts:AssumeRole", **elements):
    return {"Effect": effect, "Principal": principal, "Action": action, **elements}


def assume_by(arn, action="sts:AssumeRole"):
    context = RequestContext.of(
        [("aws:PrincipalArn", arn), ("aws:PrincipalAccount", "111122223333")]
    )
    return Request(action=action, resource=ITADMIN, context=context)


def with_trust_policy(request, policies, *statements, **layers):
    described = Resource(ITADMIN, trust_policy(*statements))
    return evaluate(request, policies, resource=described, **layers)


@pytest.mark.parametrize(
    "principal, identity, decision, blocked",
    [
        # AWS's AssumeRole page: within one account, either the trust policy names the user...
        ({"AWS": ALEE}, [], Decision.ALLOW, ()),
        # ...or it trusts the account, and an identity policy allows sts:AssumeRole.
        ({"AWS": "111122223333"}, [ASSUME], Decision.ALLOW, ()),
        ({"AWS": "111122223333"}, [], Decision.IMPLICIT_DENY, (IDENTITY,)),
        # Unlike a bucket policy, a trust policy must allow, whatever the identity policies say.
        ({"AWS": "444455556666"}, [ASSUME], Decision.IMPLICIT_DENY, (TRUST,)),
        ({"AWS": "444455556666"}, [], Decision.IMPLICIT_DENY, (IDENTITY, TRUST)),
        ({"Service": "ec2.amazonaws.com"}, [ASSUME], Decision.IMPLICIT_DENY, (TRUST,)),
        ("*", [], Decision.ALLOW, ()),
    ],
)
def test_what_a_trust_policy_needs(principal, identity, decision, blocked):
    result = with_trust_policy(assume_by(ALEE), identity, trusts(principal))
    assert result.decision is decision
    assert result.not_allowed_by == blocked


def test_allow_reasons_include_the_trust_policy():
    result = with_trust_policy(assume_by(ALEE), [ASSUME], trusts({"AWS": "111122223333"}))
    assert [(r.statement.sid, r.layer, r.principal_match) for r in result.reasons] == [
        ("Assume", IDENTITY, None),
        (None, TRUST, PrincipalMatch.ACCOUNT),
    ]


def test_a_trust_policy_deny_wins():
    no_alee = trusts({"AWS": ALEE}, effect="Deny", Sid="NoAlee")
    statements = [trusts({"AWS": "111122223333"}), no_alee]
    result = with_trust_policy(assume_by(ALEE), [ASSUME], *statements)
    assert result.decision is Decision.EXPLICIT_DENY
    assert reasons(result) == [(ITADMIN, "NoAlee", TRUST)]


def test_role_chaining_is_limited_by_the_calling_roles_boundary():
    by_campus_app = assume_by(CAMPUS_APP)
    trusted = trusts({"AWS": CAMPUS_APP})
    assert with_trust_policy(by_campus_app, [], trusted).allowed
    result = with_trust_policy(by_campus_app, [], trusted, boundary=NO_S3)
    assert result.not_allowed_by == (BOUNDARY,)


def test_a_direct_grant_with_a_boundary_that_doesnt_allow_is_refused():
    # AWS's trust policy page and its evaluation logic page disagree here.
    message = "the trust policy names the caller directly, and the caller's permissions boundary"
    for principal in ({"AWS": ALEE}, "*"):
        with pytest.raises(UnsupportedPolicyFeature, match=message):
            with_trust_policy(assume_by(ALEE), [], trusts(principal), boundary=NO_S3)
    # Both pages agree when the boundary allows it.
    allows_sts = policy("AllowsSts", allow("sts:*", "*"))
    alee = trusts({"AWS": ALEE})
    assert with_trust_policy(assume_by(ALEE), [], alee, boundary=allows_sts).allowed


def test_a_trust_policy_covers_every_sts_action_on_its_role():
    tag_session = assume_by(ALEE, "sts:TagSession")
    tagging = trusts({"AWS": ALEE}, action="sts:TagSession")
    assert with_trust_policy(tag_session, [], tagging).allowed
    # But not the IAM actions on the role, which have no resource-based policy.
    get_role = assume_by(ALEE, "iam:GetRole")
    with pytest.raises(RequestError, match="no resource-based policy applies to iam:GetRole"):
        with_trust_policy(get_role, [ALLOW_ALL], trusts("*"))
    assert evaluate(get_role, [ALLOW_ALL]).allowed


def test_requests_by_federated_users_are_refused():
    with pytest.raises(UnsupportedPolicyFeature, match="called by a SAML or OIDC user"):
        with_trust_policy(assume_by(ALEE, "sts:AssumeRoleWithSAML"), [], trusts("*"))


def test_a_role_in_another_account_is_refused_before_its_trust_policy_is_needed():
    other = Request(action="sts:AssumeRole", resource="arn:aws:iam::444455556666:role/Vendor",
                    context=RequestContext.of([("aws:PrincipalAccount", "111122223333")]))
    with pytest.raises(UnsupportedPolicyFeature, match="cross-account requests aren't supported"):
        evaluate(other, [ALLOW_ALL])


# --- Data-driven scenarios -------------------------------------------------------------

SCENARIO_DIR = Path(__file__).parent / "scenarios"
SCENARIOS = sorted(SCENARIO_DIR.glob("*.json"))


def scenario_context(entries):
    """A scenario's "context": {"key": "value" or ["value", ...], or null when absent}."""
    values = []
    for key, value in entries.items():
        if value == []:
            raise ValueError(f"{key}: give at least one value, or null when the key is absent")
        if value is not None:
            values += [(key, v) for v in (value if isinstance(value, list) else [value])]
    return RequestContext.of(values, [key for key, value in entries.items() if value is None])


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
    resource = None
    if "resource_policy" in scenario:
        # A policy, or null for none, as --resource-policy and --no-resource-policy say.
        asked = scenario["request"]
        resource = resources.describe(
            asked["resource"], asked["action"], scenario["resource_policy"], name="resource_policy"
        )
    context = scenario_context(scenario.get("context", {}))
    request = Request(**scenario["request"], context=context)
    result = evaluate(request, policies, boundary=boundary, scps=scps, resource=resource)
    assert result.decision is Decision(scenario["expected"]), scenario.get("description")


# --- NotPrincipal ----------------------------------------------------------------------


def not_principal(action="s3:GetObject", **elements):
    return {"Sid": "AllButKwong", "Effect": "Deny", "NotPrincipal": {"AWS": KWONG},
            "Action": action, "Resource": f"{BUCKET}/*", **elements}


def test_a_not_principal_deny_is_refused_when_it_applies():
    with pytest.raises(UnsupportedPolicyFeature,
                       match=f"{BUCKET} statement 0 \\(Sid=AllButKwong\\): 'NotPrincipal' isn't "
                             "supported yet"):
        with_bucket_policy(get_by(KWONG), [BROAD_S3], not_principal())


def test_a_not_principal_deny_that_doesnt_cover_the_request_is_ignored():
    # It covers PutObject only, so a read is answered as if it weren't there.
    result = with_bucket_policy(get_by(KWONG), [BROAD_S3], not_principal("s3:PutObject"))
    assert result.decision is Decision.ALLOW
    # Its conditions fail here, so it doesn't apply either.
    tls = not_principal(Condition={"Bool": {"aws:SecureTransport": "false"}})
    request = get_by(KWONG, ("aws:SecureTransport", "true"))
    assert with_bucket_policy(request, [BROAD_S3], tls).decision is Decision.ALLOW


def test_a_not_principal_deny_needs_its_condition_keys():
    tls = not_principal(Condition={"Bool": {"aws:SecureTransport": "false"}})
    with pytest.raises(MissingContextError, match="aws:SecureTransport"):
        with_bucket_policy(get_by(KWONG), [BROAD_S3], tls)


# --- Which Allows grant an allowed request ---------------------------------------------

GRADEBOOK_ONLY = policy("GradebookOnly", allow("s3:*", "arn:aws:s3:::district-gradebook-app/*",
                                                sid="GradebookApp"))


def granted_by(result):
    return [(r.policy_name, r.statement.sid) for r in result.grants]


def test_an_identity_allow_the_boundary_blocks_doesnt_grant():
    # The boundary blocks the identity policy's way in, so only the grant to everyone lets the
    # caller in. AWS doesn't let a boundary limit that grant (star_grant_and_boundary/*).
    result = with_bucket_policy(get_by(CAMPUS_APP), [BROAD_S3], grant("*", sid="Everyone"),
                                boundary=GRADEBOOK_ONLY)
    assert result.decision is Decision.ALLOW
    assert ("identity", "BroadS3", IDENTITY) in reasons(result)  # it matched...
    assert granted_by(result) == [(BUCKET, "Everyone")]  # ...but doesn't grant


def test_every_way_in_that_works_by_itself_grants():
    result = with_bucket_policy(get_by(CAMPUS_APP), [BROAD_S3], grant("*", sid="Everyone"))
    assert granted_by(result) == [("identity", "BroadS3"), (BUCKET, "Everyone")]


@pytest.mark.parametrize("boundary, granted", [
    (None, [("identity", "BroadS3"), (BUCKET, "Role")]),
    (policy("Bound", allow("s3:*", "*", sid="Bound")), [("identity", "BroadS3"), (BUCKET, "Role")]),
])
def test_a_grant_to_the_role_needs_the_boundary(boundary, granted):
    layers = {"boundary": boundary} if boundary else {}
    result = with_bucket_policy(get_by(CAMPUS_APP), [BROAD_S3],
                                grant({"AWS": CAMPUS_APP}, sid="Role"), **layers)
    assert granted_by(result) == granted
    assert ("Bound", "Bound") not in granted_by(result)  # a boundary only limits


def test_naming_the_account_grants_nothing_itself():
    result = with_bucket_policy(get_by(KWONG), [BROAD_S3],
                                grant({"AWS": "111122223333"}, sid="Account"))
    assert result.decision is Decision.ALLOW
    assert granted_by(result) == [("identity", "BroadS3")]


def test_scps_never_grant():
    result = check(GET, [BROAD_S3], scps=org_path())
    assert any(r.layer.policy_type is PolicyType.SCP for r in result.reasons)
    assert granted_by(result) == [("identity", "BroadS3")]


def test_a_trust_policy_is_part_of_every_grant():
    result = with_trust_policy(assume_by(ALEE), [ASSUME],
                               trusts({"AWS": "111122223333"}, Sid="Account"))
    assert granted_by(result) == [("Assume", "Assume"), (ITADMIN, "Account")]


def test_denials_have_no_grants():
    assert check(GET, [policy("p", deny("*", "*"))]).grants == ()
    assert check(GET, []).grants == ()


# --- Which Allows an explicit Deny overrides -------------------------------------------

NO_GETS = policy("NoGets", deny("s3:GetObject", "*", sid="NoGets"))


def overridden_by(result):
    return [(r.policy_name, r.statement.sid) for r in result.overridden]


def test_a_deny_lists_the_allows_it_overrides_and_never_itself():
    # The identity policies match with an Allow and a Deny. `_grants` counts every statement it
    # gets as an Allow, so it must get only the Allows, or the Deny would be listed too.
    result = check(GET, [BROAD_S3, NO_GETS])
    assert result.decision is Decision.EXPLICIT_DENY
    assert overridden_by(result) == [("identity", "BroadS3")]


def test_a_deny_with_no_matching_grant_lists_nothing():
    assert check(GET, [NO_GETS]).overridden == ()
    assert check(GET, [policy("Put", allow("s3:PutObject", OBJECT)), NO_GETS]).overridden == ()


def test_an_identity_allow_the_boundary_blocks_isnt_overridden():
    result = check(GET, [BROAD_S3, NO_GETS], boundary=GRADEBOOK_ONLY)
    assert result.decision is Decision.EXPLICIT_DENY
    assert result.overridden == ()


def test_a_deny_in_the_boundary_doesnt_count_as_the_boundary_allowing():
    # The boundary's only matching statement is its Deny. Read as an Allow, it would make the
    # identity policy's Allow look like it gets through the boundary.
    result = check(GET, [BROAD_S3], boundary=policy("Bound", deny("s3:GetObject", "*")))
    assert result.decision is Decision.EXPLICIT_DENY
    assert result.overridden == ()


def test_a_deny_overrides_bucket_policy_and_trust_policy_grants():
    result = with_bucket_policy(get_by(KWONG), [NO_GETS], grant({"AWS": KWONG}, sid="Kwong"))
    assert overridden_by(result) == [(BUCKET, "Kwong")]
    no_assume = policy("NoAssume", deny("sts:AssumeRole", "*", sid="NoAssume"))
    result = with_trust_policy(assume_by(ALEE), [ASSUME, no_assume],
                               trusts({"AWS": "111122223333"}, Sid="Account"))
    assert overridden_by(result) == [("Assume", "Assume"), (ITADMIN, "Account")]


def test_boundary_and_scp_allows_are_never_overridden():
    # Both allow the request, but they only limit, so only the identity policy's Allow counts.
    result = check(GET, [BROAD_S3, NO_GETS], boundary=policy("Bound", allow("s3:*", "*")),
                   scps=org_path())
    assert overridden_by(result) == [("identity", "BroadS3")]


def test_only_explicit_denies_override():
    assert check(GET, [BROAD_S3]).overridden == ()
    assert check(GET, []).overridden == ()


# --- What an explicitly denied request would get without its Denies ---------------------


def test_without_the_deny_the_request_would_be_allowed():
    result = check(GET, [BROAD_S3, NO_GETS])
    assert result.without_denies == WithoutDenies(Decision.ALLOW)
    # Then the Allows the Deny overrides are the ones that would grant the request.
    assert result.overridden == check(GET, [BROAD_S3]).grants


@pytest.mark.parametrize("layers, overridden, blocked", [
    ({"scps": org_path(ou=(NO_S3,))}, [("identity", "BroadS3")], (scp(SCHOOLS),)),
    ({"boundary": GRADEBOOK_ONLY}, [], (BOUNDARY,)),
], ids=["an SCP level", "the boundary"])
def test_without_the_deny_another_layer_would_still_block_it(layers, overridden, blocked):
    # An SCP never grants, so with an OU whose SCPs don't allow S3, the Deny still overrides the
    # identity policy's Allow, and the OU would still block the request. A boundary that doesn't
    # allow it blocks that Allow's way in too, so the Deny overrides nothing.
    result = check(GET, [BROAD_S3, NO_GETS], **layers)
    assert result.decision is Decision.EXPLICIT_DENY
    assert overridden_by(result) == overridden
    assert result.without_denies == WithoutDenies(Decision.IMPLICIT_DENY, blocked)


def test_without_the_deny_no_identity_policy_would_allow_it():
    assert check(GET, [NO_GETS]).without_denies == WithoutDenies(Decision.IMPLICIT_DENY,
                                                                 (IDENTITY,))


def test_without_the_deny_the_analyzer_cant_tell_where_awss_docs_disagree():
    # The trust policy names alee directly, and alee's boundary doesn't allow sts:AssumeRole:
    # without the Deny, evaluation would be refused (see the refusal test above).
    no_assume = policy("NoAssume", deny("sts:AssumeRole", "*", sid="NoAssume"))
    result = with_trust_policy(assume_by(ALEE), [no_assume], trusts({"AWS": ALEE}),
                               boundary=NO_S3)
    assert result.decision is Decision.EXPLICIT_DENY  # the Deny settles the answer itself
    assert result.without_denies.decision is None
    assert result.without_denies.refusal.startswith(
        "the trust policy names the caller directly, and the caller's permissions boundary")


def test_only_explicit_denies_say_what_they_would_get_without_denies():
    assert check(GET, [BROAD_S3]).without_denies is None
    assert check(GET, []).without_denies is None
