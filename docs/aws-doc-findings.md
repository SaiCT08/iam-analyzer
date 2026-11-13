# AWS doc findings

These are the places where AWS's own documentation contradicts itself, or doesn't match what AWS's
IAM policy simulator (`iam:SimulateCustomPolicy`) did. They turned up while building the analyzer
and checking it against the simulator.
- **Sources:** [the simulator check](simulator-check.md), [the documentation review](aws-review.md)
  and [the design decisions](design-decisions.md), which say what the analyzer does about each one.
- **Checked:** every quote below was found on the live page on 2026-11-12. The
  [Since updated](#since-updated) section covers what that check turned up.
- **Evidence:** the simulator's answers are fixtures in
  [`tests/simulator_fixtures`](../tests/simulator_fixtures), named here by group and case, with the
  request ID AWS returned for the `SimulateCustomPolicy` call. They were recorded on 2026-10-25 and
  2026-10-26.
- **Simulator limits are kept apart.** Where AWS's documentation is clear and the simulator is the
  one that's off, the case is listed under
  [Simulator limits](#simulator-limits-not-doc-problems), not as a doc problem.

Each entry starts with how strong it is. A **contradiction** means two passages can't both be
right. **Doesn't match** means the documentation, read plainly, says something the simulator didn't
do. **Ambiguous** means the text can be read in a way that fits, but it doesn't say so.

| # | Finding | Kind |
|---|---|---|
| 1 | [Policy variables in `Bool` values](#1-policy-variables-in-bool-values) | contradiction |
| 2 | [The `ForAllValues:StringNotLike` example table](#2-the-forallvaluesstringnotlike-example-table) | contradiction |
| 3 | [`IfExists` and `ForAnyValue` on a missing key](#3-ifexists-and-foranyvalue-on-a-missing-key) | contradiction, for one combination |
| 4 | [A trust policy naming a user whose boundary doesn't allow it](#4-a-trust-policy-naming-a-user-whose-boundary-doesnt-allow-it) | contradiction, not settled |
| 5 | [Resource ARNs in SCP `Allow` statements](#5-resource-arns-in-scp-allow-statements) | contradiction |
| 6 | [The `Version` element in SCPs](#6-the-version-element-in-scps) | contradiction, minor |
| 7 | [Policy variables with no value](#7-policy-variables-with-no-value) | ambiguous |
| 8 | [`Resource` in a trust policy](#8-resource-in-a-trust-policy) | contradiction, in wording |
| 9 | [The default Object Ownership for a new bucket](#9-the-default-object-ownership-for-a-new-bucket) | contradiction, not tested |
| 10 | [The default prefix of a bare IP address](#10-the-default-prefix-of-a-bare-ip-address) | doesn't match, for IPv6 |
| 11 | [Wildcards and colons in `Resource`](#11-wildcards-and-colons-in-resource) | ambiguous |
| 12 | [A four-digit date](#12-a-four-digit-date) | ambiguous |
| 13 | [Context keys left out of a simulation](#13-context-keys-left-out-of-a-simulation) | doesn't match, as a general rule |
| 14 | [`EvalResourceName`](#14-evalresourcename) | doesn't match |
| 15 | [Resource-based policies and IAM roles in the simulator](#15-resource-based-policies-and-iam-roles-in-the-simulator) | ambiguous |

## Pages that contradict each other

### 1. Policy variables in `Bool` values
**Contradiction.** One page says Boolean operators take policy variables, and another says they
don't. The simulator sided with the second.
- **Page:** [Condition operators, Boolean](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_Boolean):
  "Policy variables – Supported".
- **The other page:** [Variables and tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html):
  "You can't use a policy variable with other operators, such as Numeric, Date, Boolean, Binary, IP
  Address, or Null operators."
- **What the simulator did:** it didn't fill the variable in. A `Bool` condition on
  `aws:SecureTransport` with the value `${aws:MultiFactorAuthPresent}`, with both keys `true`, didn't
  hold, so the read was an implicit deny. Had the variable been filled in, the condition would have
  held and the read been allowed.
- **Evidence:** `bool_with_a_variable/mfa_true`, request `76b57c87-b247-42e6-b49b-68155d379dcd`.

### 2. The `ForAllValues:StringNotLike` example table
**Contradiction, on one page.** The table under an example gives the opposite of the operators'
definitions in all three of its rows. The simulator followed the definitions.
- **Page:** [Condition operators, String](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_String),
  the example whose Deny has `"ForAllValues:StringNotLike"` on `aws:ResourceOrgPaths`, with the
  values `o-acorg/r-acroot/ou-acroot-mediaou/` and `o-acorg/r-acroot/ou-acroot-sportsou/*`. The table
  says "Match" (the Deny applies) for `o-acorg/r-acroot/ou-acroot-sportsou/costcenter/`, "No match"
  for `o-acorg/r-acroot/ou-acroot-mediaou/costcenter/`, and "No match" when the request has no
  `aws:ResourceOrgPaths`.
- **The definitions:** [`ForAllValues`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html#reference_policies_condition-forallvalues)
  "returns true if every context key value in the request matches a context key value in the policy.
  It also returns true if there are no context keys in the request." With `StringNotLike`, a value
  "matches" when it's like none of the policy's values. So the sportsou path, which is like
  `ou-acroot-sportsou/*`, gives no match; the mediaou path, which is like neither, gives a match; and
  a missing key gives a match. Each row is the opposite.
- **The example's own description** only works with the definitions: the policy "denies access to
  Amazon S3 actions unless the resource being accessed is in a specific set of organizational units".
- **What the simulator did:** with the example's Deny copied word for word beside an Allow for all of
  S3, it gave the definitions' answer in all three rows:
  - the sportsou path: allowed, `for_all_values_string_not_like/sportsou_costcenter`, request
    `1df601e7-5a67-4757-88c3-eed182e98919`;
  - the mediaou path: explicitly denied, `mediaou_costcenter`, request
    `ad61ff84-ab9d-4e19-aae4-2f2a39ddc782`;
  - no `aws:ResourceOrgPaths`: explicitly denied, `no_resource_org_paths`, request
    `94863e1f-a495-4a80-9e40-7dd8649cb71b`.

### 3. `IfExists` and `ForAnyValue` on a missing key
**Contradiction, for one combination.** Two definitions give opposite answers for
`ForAnyValue:...IfExists` when the request doesn't have the key, and neither page says which wins.
In the simulator, `ForAnyValue` won.
- **Page:** [Condition operators, IfExists](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IfExists):
  "If the key is not present, evaluate the condition element as true."
- **The other page:** [`ForAnyValue`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html#reference_policies_condition-foranyvalue):
  "For no matching context key or if the key does not exist, the condition returns false."
- **What the simulator did:** an Allow with `ForAnyValue:StringEqualsIfExists` on `aws:TagKeys`, for
  a request with no tags, didn't apply: an implicit deny, with `aws:TagKeys` in
  `MissingContextValues`. A key left out of a call acts as absent (see entry 13).
- **Evidence:** `for_any_value_if_exists/key_absent`, request `e8c1ce24-69c2-4647-8bd2-90224c25bb17`.

### 4. A trust policy naming a user whose boundary doesn't allow it
**Contradiction, not settled.** For a trust policy that names a user directly, one page says the
user's permissions boundary must allow `sts:AssumeRole`, and another says a boundary doesn't limit a
grant to a user. The simulator can't settle it, since it doesn't simulate trust policies
(entry 15).
- **Page:** [Update a role trust policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_update-role-trust-policy.html):
  "If a permissions boundary is set for the user, then it must allow the sts:AssumeRole action."
- **The other page:** [How AWS enforcement code logic evaluates requests](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html):
  "Within the same account, resource-based policies that grant permissions to an IAM user ARN (that
  is not a federated user session) are not limited by an implicit deny in an identity-based policy or
  permissions boundary." A role's trust policy is a resource-based policy: "The IAM resource-based
  policy type is a role trust policy"
  ([Principal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)).
  The same page names trust policies as an exception only in that they "must explicitly allow access
  for principals".
- **Evidence:** the two quotes.

### 5. Resource ARNs in SCP `Allow` statements
**Contradiction.** The SCP syntax page says an SCP `Allow` can only use `"*"` in `Resource`. AWS's
2025 announcement says SCPs now support resource ARNs with `Allow`, and the simulator honored one.
- **Page:** [SCP syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html#scp-syntax-resource):
  "In statements where the Effect element has a value of Allow, you can specify only "*" in the
  Resource element of an SCP. You can't specify individual resource Amazon Resource Names (ARNs)."
- **The other page:** [AWS's announcement of 2025-09-19](https://aws.amazon.com/about-aws/whats-new/2025/09/aws-organizations-iam-language-service-control-policies/):
  "With this launch, SCPs now support use of conditions, individual resource ARNs, and the NotAction
  element with Allow statements."
- **What the simulator did:** with an `Allow` for everything at the level above, an SCP whose only
  statement allows `s3:GetObject` on `arn:aws:s3:::district-gradebook-app/*` let a read inside that
  bucket through, and not a read outside it. An SCP `Allow` with `NotAction` worked as well.
- **Evidence:**
  - `scp_allow_statements/resource_scoped_allow_inside`: allowed, request
    `4489ebe2-287f-40d6-8c45-c2c8d4b9a3f4`;
  - `scp_allow_statements/resource_scoped_allow_outside`: implicit deny, request
    `76264413-9399-4197-ae8b-234b1f09d857`;
  - `scp_allow_statements/not_action_allow_s3`: allowed, request
    `51a0d2e4-9a53-45f1-bc61-3c3c250f556f`;
  - `scp_allow_statements/not_action_allow_ec2`: implicit deny, request
    `603e3d81-1f93-42f6-a7a7-449a4b6fef0f`.

### 6. The `Version` element in SCPs
**Contradiction, minor.** The SCP syntax page says every SCP must have a `Version`, and two of its
own complete examples have none.
- **Page:** [SCP syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html#scp-syntax-version):
  "Every SCP must include a Version element with the value "2012-10-17"."
- **The same page's examples:** eight of its twelve examples include a `Version`, two are fragments,
  and two are complete SCPs with none, such as
  `{ "Statement": { "Effect": "Allow", "Action": "s3:*", "Resource": "*" } }`.
- **The simulator** accepted SCPs with no `Version`, such as the `FullAWSAccess` in
  `scenarios/scp_deny_beats_admin` (request `de98b299-de16-4e8b-97d0-58fc31f74d85`). That only shows
  the simulator doesn't check the rule, not whether AWS Organizations does.

### 7. Policy variables with no value
**Ambiguous.** A hedged note on the policy variables page points the other way from that page's own
section on variables with no value. The simulator followed the section.
- **Page:** [Variables and tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html),
  a note near the top: "If AWS cannot resolve a variable this might cause the entire statement to be
  invalid."
- **The same page, further down:** "If a variable that has no value in the authorization context is
  used as part of the Resource or NotResource element of a policy, the resource that includes a
  policy variable with no value will not match any resource." In a condition, "StringEquals or
  StringLike do not match", while "Inverted condition operators like StringNotEquals or StringNotLike
  do match against a null value". So a statement with such a variable still applies through
  `NotResource` or a negated operator, which an invalid statement wouldn't.
- **What the simulator did:** a Deny whose `NotResource` is
  `arn:aws:s3:::district-teams-${aws:PrincipalTag/team}/*`, for a caller with no team tag, applied.
  Had the statement been dropped as invalid, the Allow beside it would have allowed the read.
- **Evidence:** `variables_without_a_value/deny_not_resource`: explicitly denied, request
  `f7cfe021-ddd4-4a42-92e8-a90e0e5bf2ac`. Its partner, `allow_control`, an Allow on the team's bucket
  for the same caller, gave an implicit deny (request `3429bd07-a93b-478d-a760-0ce204863abb`).
- **Not overstated:** the note says "might", so it isn't strictly wrong. It just suggests the
  opposite of what the section and the simulator show.

### 8. `Resource` in a trust policy
**Contradiction, in wording.** The Resource page says every statement needs `Resource` or
`NotResource`, and the trust policy examples on the role pages have neither.
- **Page:** [Resource](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html):
  "Statements must include either a Resource or a NotResource element." The page makes no exception
  for trust policies.
- **The examples:** every trust policy on
  [Create a role to give permissions to an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html)
  and [Update a role trust policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_update-role-trust-policy.html)
  leaves both out, such as an `Allow` for `arn:aws:iam::123456789012:root` on `sts:AssumeRole` with
  an MFA condition and nothing else.
- **Not overstated:** the likeliest reading is that the rule is meant for other kinds of policy, but
  no page checked says so. The simulator can't check trust policies (entry 15).

### 9. The default Object Ownership for a new bucket
**Contradiction, not tested.** Two S3 pages say a new bucket has ACLs disabled by default, and a
third says a bucket created with the AWS CLI gets ACLs enabled unless the setting is given.
- **Pages:** [Controlling ownership of objects](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html):
  "Bucket owner enforced (default)", and "For newly created buckets, ACLs are disabled by default."
  The [CreateBucket API reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html)
  agrees: to set an ACL, "you must explicitly set S3 Object Ownership for the bucket to a different
  value than the default, BucketOwnerEnforced".
- **The other page:** [Setting Object Ownership when you create a bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-ownership-new-bucket.html):
  "If you don't set Object Ownership when you create a bucket by using the AWS CLI, the default
  setting will be ObjectWriter (ACLs enabled)."
- **Evidence:** the quotes. Settling it would mean creating a bucket, which wasn't done.

## Pages that don't match what the simulator did

### 10. The default prefix of a bare IP address
**Doesn't match, for IPv6.** The condition operators page gives a bare IP address a /32 prefix, and
the simulator treated a bare IPv6 address as /128.
- **Page:** [Condition operators, IP address](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IPAddress):
  "If you specify an IP address without the associated routing prefix, IAM uses the default prefix
  value of /32." The same paragraph's examples include an IPv6 range, `2001:DB8:1234:5678::/64`, and
  nothing limits the default to IPv4.
- **What the simulator did:** `IpAddress` with the bare value `2001:db8::1` matched a request from
  `2001:db8::1`, and not one from `2001:db8::2`. That's /128: a /32 in IPv6 covers 2^96 addresses,
  both of these included.
- **Evidence:**
  - `ip_ranges/bare_ipv6_address`, from `2001:db8::2`: implicit deny, request
    `ca616546-be05-4381-8afc-11f5f210502f`;
  - `ip_ranges/bare_ipv6_address_itself`, from `2001:db8::1`: allowed, request
    `dde2cdd7-dde0-44c2-baf8-e0237ff0fa99`.
- **Not overstated:** /32 is right for IPv4, and the sentence was probably written for it. As
  written, it covers IPv6 too, where it's wrong.

### 11. Wildcards and colons in `Resource`
**Ambiguous.** The Resource page suggests that a wildcard stays inside one colon-separated segment of
an ARN, unless a `*` ends the segment. The simulator let a `*` or a `?` match a colon anywhere.
- **Page:** [Resource, wildcards](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html#reference_policies_elements_resource_wildcards):
  "You can use wildcard characters (* and ?) within the individual segments of an ARN (the parts
  separated by colons)", "If the * wildcard is the last character of a resource ARN segment, it can
  expand to match beyond the colon boundaries", and "We recommend you use wildcards (* and ?) within
  ARN segments separated by a colon."
- **Not overstated:** read together, these suggest that only a `*` ending a segment crosses a colon,
  but the page never says a wildcard can't. It recommends staying within segments.
- **What the simulator did:** every pattern below matched, by matching a colon:

  | Pattern | Request | Fixture | Request ID |
  |---|---|---|---|
  | `function:*-prod` | the Lambda alias `function:billing:canary-prod` | `wildcards_and_colons/lambda_alias_mid_segment_star` | `c158785d-ec18-44de-a82f-4aa165f9e529` |
  | `arn:aws:s3:::district-logs/*.json` | the key `2026-10-25T10:00:00.json` | `wildcards_and_colons/s3_key_colon_mid_segment_star` | `c09f131d-11b2-4034-8800-8f137f59d702` |
  | `arn:aws:s3:::district-student-records/campus?01/*` | the key `campus:01/roster.csv` | `wildcards_and_colons/s3_key_colon_question_mark` | `50f1330b-6542-4653-8d56-e91394ce0759` |
  | `arn:aws:lambda:us-*3:function:billing:canary` | the alias in us-east-1, account 111122223333: the `*` ran from the region field to the account ID's last `3` | `wildcards_and_colons/mid_field_star_crossing_a_colon` | `051b0e31-b479-4627-b8e3-21604a3c8a8e` |
  | `arn:aws:lambda:us-east-1?111122223333:function:billing:canary` | the same alias: the `?` stood for the colon | `wildcards_and_colons/mid_field_question_mark_crossing_a_colon` | `e3d04993-3a02-4521-a220-7bdf518604b0` |

  In a condition, `ArnLike` with `function:*-prod` matched the alias too
  (`wildcards_and_colons/arn_like_mid_segment_star`, request `5cccfea5-63cd-49d8-9374-1d2b967574f3`).
  Controls that need no colon matched as expected, such as `us-*-1`
  (`wildcards_and_colons/mid_field_star_control`, request `c71cb76e-83e4-4edb-bd0c-ba53f152fd04`).
- **Where the docs did hold:** the condition operators page says that for the ARN operators "Each of
  the six colon-delimited components of the ARN is checked separately", and the simulator kept them
  separate. `arn:aws:lambda:*:function:billing:canary` matched the alias in `Resource`, where the `*`
  can run on from the region field, and didn't match it in `ArnLike`
  (`wildcards_and_colons/arn_like_star_ending_the_region_field`, request
  `4fdd221a-7301-4e76-8fa4-e480278d05c1`).

### 12. A four-digit date
**Ambiguous.** The condition operators page accepts W3C's ISO 8601 formats or epoch time, and a
four-digit number is valid in both. The simulator read it as epoch seconds.
- **Page:** [Condition operators, Date](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_Date):
  "You must specify date/time values with one of the W3C implementations of the ISO 8601 date
  formats or in epoch (UNIX) time." The [W3C profile](https://www.w3.org/TR/NOTE-datetime) that
  sentence links to includes a year on its own: "Year: YYYY (eg 1997)".
- **What the simulator did:** `DateGreaterThan` on `aws:CurrentTime` with the value `2026`, at
  2000-01-01T00:00:00Z, held, so the read was allowed. As the year 2026, it wouldn't have held. As
  epoch seconds, `2026` is 1970-01-01T00:33:46Z.
- **Evidence:** `dates_without_a_time_zone/four_digits`, request
  `1ce78fd7-47c5-44cd-936d-e5616971970b`.
- **Not overstated:** the page doesn't say which reading wins, so it isn't wrong. But someone who
  writes `"2027"` meaning the year gets a moment in 1970.

### 13. Context keys left out of a simulation
**Doesn't match, as a general rule.** The simulator's how-to page says a simulation missing a context
key's value returns an implicit deny. In the simulator, a key left out acted as absent, and the
answer was an implicit deny only when a statement needed the key.
- **Page:** [How to simulate policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/policies_policy-simulator-how-to.html):
  "If you do not provide a value for a context key, the simulation still runs and returns an implicit
  deny, and the missing keys are returned in missingContextValues so you know which values to add."
- **What the simulator did:** six cases leave a key out, and each has a documented answer other than
  an implicit deny. All six gave that answer:

  | Case | Answer | Request ID |
  |---|---|---|
  | `calibration_absent_keys/string_not_equals_on_an_absent_tag` | allowed | `63b35eec-cc0a-4a81-9275-036b545d823e` |
  | `calibration_absent_keys/string_like_if_exists_on_an_absent_instance_type` | allowed | `6e93e98c-988b-4472-99c6-68a8fb890a7b` |
  | `calibration_absent_keys/null_true_on_an_absent_token_issue_time` | allowed | `fca885d1-e51c-4e55-877e-460aaa7678ce` |
  | `scenarios/condition_for_all_values_holds_when_the_key_is_missing` | allowed | `e12c4cd2-fd32-4d11-a95a-9d4741c4ce0c` |
  | `scenarios/policy_variable_default_when_tag_is_absent` | allowed | `44264c23-e211-4f0d-8781-ae6b495a91c3` |
  | `scenarios/condition_bool_if_exists_denies_access_keys` | explicitly denied | `094f76e5-1364-4ea9-acdf-f5006cb3df02` |

  `MissingContextValues` named a key only in implicit denies where a statement failed for lack of it,
  such as `for_any_value_if_exists/key_absent` (entry 3).
- **Not overstated:** the sentence is right for a statement that needs the missing key to match. As
  a rule for every missing key, it's wrong.

### 14. `EvalResourceName`
**Doesn't match.** The API reference says the simulator's `EvalResourceName` is an ARN template, not
the resource asked about. The simulator returned the resource asked about.
- **Page:** [EvaluationResult](https://docs.aws.amazon.com/IAM/latest/APIReference/API_EvaluationResult.html):
  "The ARN template for the simulated resource type (for example,
  arn:${Partition}:s3:::${BucketName}/${KeyName}), or * if no ARN format is defined for the action.
  This is not a specific customer-provided resource ARN."
- **What the simulator did:** in all 118 answers recorded, `EvalResourceName` was exactly the
  resource the call asked about, never a template. It was `*` only where the call asked about `*`.
- **Evidence:** every fixture. For example, a teacher's read of
  `arn:aws:s3:::district-student-records/campus-01/grades.csv` came back with that ARN
  (`scenarios/teacher_can_read_roster`, request `fe5c66ec-4de1-461e-aca9-ab4a9b86c4be`).

### 15. Resource-based policies and IAM roles in the simulator
**Ambiguous.** The `SimulateCustomPolicy` reference says resource-based policies can't be simulated
"for IAM roles", which can mean two things. The simulator's behavior fits one of them.
- **Page:** [SimulateCustomPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html),
  in a note under both `ResourceArns` and `ResourcePolicy`: "Simulation of resource-based policies
  isn't supported for IAM roles."
- **The two readings:** a role's own resource-based policy, its trust policy, can't be simulated; or
  no resource-based policy is simulated when the caller is a role.
- **What the simulator did:** with a role as the caller, a bucket policy decided an Allow and a Deny,
  and `MatchedStatements` named `ResourcePolicy` both times. So the second reading doesn't hold, and
  trust policies are the part that can't be simulated.
- **Evidence:**
  - `calibration_role_callers/bucket_policy_grants_to_the_role`: allowed, request
    `0651588f-2d89-48e8-a9c8-39ff56c3a1b9`;
  - `calibration_role_callers/bucket_policy_denies_everyone`: explicitly denied, request
    `55f70a02-ac74-4dca-847c-9e84cd655d73`.

## Since updated
No quoted sentence has changed since it was recorded: every one was on its live page on
2026-11-12.

One mismatch recorded on 2026-10-25 no longer holds against today's page, so it isn't counted above:
- **Then:** [IAM policy testing with the IAM policy simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
  says "The policy simulator evaluates SCPs, including condition keys and resource scoping in deny
  statements", and the simulator applied resource scoping in SCP `Allow` statements too (entry 5's
  `scp_allow_statements/resource_scoped_allow_*`). That was recorded as a mismatch.
- **Now:** the same page also has a section that says "The simulator evaluates the condition keys
  and resource scoping in SCPs", with no limit to Deny statements, which fits what the simulator did.
- **Not overstated:** it isn't possible to tell whether AWS added that section after 2026-10-25, or
  it was already there and the recorded mismatch overlooked it. The Internet Archive has no copy of
  the page from then.

## Simulator limits (not doc problems)
In these cases AWS's documentation is clear, and the simulator didn't follow it. They aren't doc
problems, and the analyzer follows the documentation. They're here because anyone who compares the
analyzer with the simulator will see them.

| What AWS documents | What the simulator did | Evidence |
|---|---|---|
| "When you specify an incomplete ARN (one with fewer than the standard six fields) in an identity-based policy, AWS automatically completes the ARN by adding wildcard characters (*) to all missing fields." ([ARNs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html#arns-paths-wildcards)) | Didn't complete them: an Allow on `arn:aws:sqs` didn't cover a queue, a Deny on `arn:aws:s3` didn't cover an object, and a short pattern's `*` ran across fields | `scenarios/incomplete_arn_allow_is_completed_with_wildcards` (`f5b5ac64-a568-48f6-9a14-bbedcf5bb049`), `scenarios/incomplete_arn_is_completed_with_wildcards` (`b1137675-d076-49c3-847d-a74d8a485eb8`), `wildcards_and_colons/short_pattern_star_across_fields` (`325d2573-5ddb-4fb0-b490-54cec5d8db15`) |
| "Resource-based policies that grant permissions to an IAM role ARN are limited by an implicit deny in a permissions boundary or session policy." ([evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)) | Allowed a bucket policy's grant to a role whose boundary doesn't allow the read | `scenarios/bucket_policy_role_grant_is_limited_by_the_boundary` (`9e81bbaa-9115-4f67-aab5-b454cfa075d7`) |
| A bucket policy that names an account: "This delegates authority to the account." ([Principal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-accounts)) | Treated it as a grant to everyone in the account, even when no identity policy allowed the read | `star_grant_and_boundary/account_principal` (`64d3a256-0783-48ca-9d9b-2e7d5f5580e9`), `star_grant_and_boundary/account_principal_without_identity_allow` (`8cbc2b98-0271-45f0-b1fd-df7e13f1ebfa`) |
| "SCPs do not affect any service-linked role." ([SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html#scp-effects-on-permissions)) | Applied an SCP to a service-linked role | `scenarios/scp_skips_service_linked_role` (`f8326f2f-1b08-4e17-94cb-3e7840a87fa3`) |
| "The NotPrincipal element uses "Effect":"Deny" to deny access to all principals except the principal specified in the NotPrincipal element." ([NotPrincipal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html)) | Denied a user that the element names, with the user's account, as AWS recommends | `not_principal/names_the_account_and_the_caller` (`5fca69a2-73e6-4da7-b8a1-e8296ba581f5`) |
| "The AllowS3ListRead statement in this policy allows Carlos to view a list of all of the buckets in the account." That statement allows `s3:ListAllMyBuckets` on `arn:aws:s3:::*`. ([evaluation example](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html#reference_policies_evaluation-logic_policies_evaluation_example)) | Denied the listing under an Allow on `arn:aws:s3:::*`, and allowed it under an Allow on `*`. It compared the patterns with the `*` it was sent, which says nothing about the resource a real request carries. Treating this as a simulator limit is a judgment call (see [design decisions](design-decisions.md#resource-patterns-and-arns)) | `list_all_my_buckets/allowed_on_every_bucket_arn` (`9a18a3fb-080b-40a2-9ba1-622f41cfc564`), `list_all_my_buckets/allowed_on_star_control` (`ea92b174-bf2a-4e7e-990e-8abd6ee83947`) |

AWS also documents what its simulator can't do, such as trust policies, assumed-role callers and
resource control policies. [The simulator check](simulator-check.md) lists those, and which cases
they kept out.
