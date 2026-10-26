# Checking the analyzer against AWS's IAM policy simulator

Recorded on 2026-10-25 and 2026-10-26. For 121 cases, the analyzer and AWS's IAM policy simulator
(`iam:SimulateCustomPolicy`) were given the same policies and the same request, and their answers
were compared. The cases are 98 from the first run and 23 follow-up probes, recorded in three
rounds.
- **Fixtures:** each request and AWS's raw response is a fixture in
  [`tests/simulator_fixtures`](../tests/simulator_fixtures), with AWS's request IDs and the date.
- **Offline replay:** [`tests/test_simulator_fixtures.py`](../tests/test_simulator_fixtures.py)
  replays the fixtures without AWS, so the comparison keeps running after the AWS account is
  closed.
- **Engine changes:** the differences below were decided on 2026-10-25, and a third round of
  probes on 2026-10-26 settled the questions still open (see
  [Differences and decisions](#differences-and-decisions)). Since 2026-10-26 the engine follows
  differences 1, 3 and 4, and the policy-variable rows of section 5. The rest of section 5
  comes next.

## Summary

| Verdict | Cases | Meaning |
|---|---|---|
| agrees | 84 | Both sides gave the same answer. |
| differs | 0 | A real mismatch. |
| simulator limit | 9 | AWS documents a behavior that the simulator doesn't follow. |
| analyzer refuses | 28 | AWS answered a case the analyzer refuses because AWS's docs don't settle it. |
| can't express | 4 | The simulator can't be given the case faithfully. |

- **Calibration passed:**
  - the harness reproduces AWS's own "Same-Account Simulation" example;
  - a key left out of the call acts like a key absent from a real request;
  - the simulator uses a bucket policy when a role is the caller.
- **Confirmed by the simulator:**
  - `ForAllValues:StringNotLike` follows its definitions, not the table under AWS's
    `aws:ResourceOrgPaths` example. This was a judgment call in phase 4b.
  - A bucket policy's grant to `*` isn't limited by a permissions boundary, for a user or a role
    caller. This was a judgment call in phase 5.
  - SCP `Allow` statements honor `Resource` and `NotAction`, as the analyzer assumes (review open
    question 2).
  - Set operators work with `Numeric` operators. This was a judgment call.
  - `ArnLike` checks an ARN's six fields separately, as AWS documents. A `*` that ends the region
    field doesn't run into the account field, although the same pattern does in `Resource` (third
    follow-up).
  - Every existing scenario the simulator can express agrees, except the four that simulator
    limits explain.
- **The main difference was that wildcards can match a colon.** In `Resource` and in `ArnLike`, a
  `*` in the middle of the resource part, or a `?`, matches a colon (7 cases). In `Resource`, a `*`
  or a `?` in the middle of the region field crosses a colon too (2 cases).
  - The analyzer said they can't, so in eight cases it missed an `Allow`. It said someone couldn't
    get in when AWS would let them: the unsafe direction.
  - In the ninth it missed a `Deny` written as `*.json` for S3 keys that contain colons. That
    over-reported access, which is wrong but errs on the safe side.
  - Since 2026-10-26 the analyzer matches as the simulator does, and all nine agree.
- **The simulator's own limits.** Against AWS's documentation, it:
  - doesn't complete short ARNs;
  - doesn't exempt service-linked roles from SCPs;
  - doesn't limit a grant to a role ARN by that role's boundary;
  - treats naming the account as a grant to everyone in it;
  - denies a principal that `NotPrincipal` names.

## How the check works
- **Where the harness lives:** [`simulator_check/`](../simulator_check) is a dev tool. It sits
  outside `src/`, and boto3 is an optional extra (`pip install -e ".[simulator]"`), so the analyzer
  itself still has no dependencies.
- **Cases:** a case has the shape of a scenario in `tests/scenarios`. The hand-written probes are in
  `simulator_check/cases/*.json`, one file per question, each with what every possible answer would
  mean. The existing scenarios are cases too.
- **Context keys:** for each case, `GetContextKeysForCustomPolicy` lists the keys that the
  policies use. The case must give every listed key, and every key the analyzer reads, or mark it
  absent.
  - A key marked absent is left out of the simulator call and marked absent on the analyzer's side.
  - AWS's `MissingContextValues` is recorded in the fixture.
- **The caller:** every call sends a `CallerArn`. The simulator fills in `aws:username`,
  `aws:PrincipalAccount` and other principal keys from it, so a case's values for those keys must
  agree with its caller. Otherwise the simulator could have taken them from the real identity
  behind the profile.
- **One request per call:** each call has one action and one resource.
- **The analyzer's side:** it is rebuilt from the recorded request, so both sides read the same
  policy text.
- **Example accounts only:** every case uses AWS's example account IDs. A scan refuses to send or
  save anything with another 12-digit number or an access key ID in it. It ignores AWS's request
  IDs, which are UUIDs whose last group can happen to be all digits.
- **Verdicts:** [`verdicts.json`](../tests/simulator_fixtures/verdicts.json) lists every case that
  doesn't simply agree, with the analyzer's answer today. The offline test:
  - fails if that answer changes;
  - re-derives the two calibration findings from the fixtures;
  - checks that every simulator limit quotes AWS and links to its docs.

## Calibration

### AWS's own example
The "Example: Same-Account Simulation" request from the
[`SimulateCustomPolicy` API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html)
is documented as allowed, with `AllowedByPermissionsBoundary` false.
- **The simulator gave exactly that** (request `bbf22e28-c24e-484f-8b2a-e4939bcf71d4`), decided
  by the bucket policy's statement.
- **The analyzer says ALLOW too.**

The sample's JSON is invalid, so only that was fixed:
- `"Action":{"iam:*"}` became `["iam:*"]`, and `"Resource":{"*"}` became `["*"]`, in the identity
  policy and in the boundary.
- `"Action":{"s3:List*","s3:Put*"}` and `"Resource":{"arn:aws:s3:::production/*"}` became lists
  in the bucket policy.
- A comma was added after the bucket policy's `Principal`.

### A key left out of the call acts as an absent key
AWS's "How to simulate policies" page says: "If you do not provide a value for a context key, the
simulation still runs and returns an implicit deny, and the missing keys are returned in
`missingContextValues`".
- **The test:** six calibration cases leave a key out, and each has a documented answer other than
  an implicit deny:
  - `StringNotEquals`, `StringLikeIfExists` and `Null` on a missing key;
  - three scenarios: `ForAllValues` with no key, a `BoolIfExists` Deny, and a variable default.
- **The result:** all six gave their documented answer. So the simulator applies AWS's rules for
  missing keys, and the sentence describes a statement that fails for lack of a value. No case is
  inconclusive.
- **When `MissingContextValues` names a key:** only in three cases, each an implicit deny where a
  statement failed for lack of that key:
  - `for_any_value_if_exists/key_absent`;
  - `variables_with_wildcards/star_in_a_default`;
  - `variables_without_a_value/allow_control`.

  It stayed empty for absent keys that didn't decide the answer.

### The simulator uses a bucket policy when a role is the caller
"Simulation of resource-based policies isn't supported for IAM roles" can mean either of two
things:
- **(a)** a role's own resource-based policy, its trust policy, can't be simulated;
- **(b)** no resource-based policy is simulated when a role is the caller.

With a role as the caller, the bucket policy decided both controls, and both list `ResourcePolicy`
in `MatchedStatements`:
- an Allow (`bucket_policy_grants_to_the_role`);
- a Deny (`bucket_policy_denies_everyone`).

So reading (a) holds. Trust policies are out either way.

## What the simulator can't express

| What | Cases | Why |
|---|---|---|
| A role's trust policy | the three `trust_policy_*` scenarios; the refused contradiction about a trust policy and the boundary; the judgment calls that a trust policy has no `Resource` and covers six STS actions | AWS: "Simulation of resource-based policies isn't supported for IAM roles." |
| The management-account exemption | `scp_skips_management_account` | The simulator applies the SCPs it's given, and nothing tells it which account is the management account. |
| Role sessions, canonical user IDs and unique IDs as principals | none written | `CallerArn` can't be "an assumed role, federated user, or a service principal", and the example identities have no canonical or unique ID. |
| A key the simulator fills in, made absent or different | none written | For example, `aws:username` absent for a role: the simulator fills it in from the caller. |
| Cross-account requests, KMS keys, SAML and OIDC users | not included | The analyzer refuses these as unsupported. They aren't open questions. |

## Where AWS says the simulator differs from real requests
- **Results can differ:**
  - "The policy simulator results can differ from your live AWS environment. We recommend that
    you check your policies against your live AWS environment after testing with the policy
    simulator to confirm that you have the desired results."
  - "It does not use real context key values from production, and because the actions are not
    actually run, it returns no service response."

  ([IAM policy testing with the IAM policy simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html))
- **SCPs and advanced configurations:** "The policy simulator evaluates SCPs, including condition
  keys and resource scoping in deny statements, but does not support resource control policies
  (RCPs). Simulation results can still differ from live behavior for some advanced
  configurations, such as VPC endpoint policies, role chaining, or multiple resource-based
  policies on a single resource." (same page)
- **The API reference words SCP support more broadly:** the simulator "evaluates statements in
  identity-based policies, service control policies (SCPs) including their condition keys and
  resource scoping, and the inputs that you provide during simulation."
  ([SimulateCustomPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html))
  - The part 5 probes of SCP `Allow` statements all agreed with the analyzer. So the simulator
    honored resource scoping in an Allow too, and the User Guide's narrower wording didn't
    matter here.
- **IAM roles:** "Simulation of resource-based policies isn't supported for IAM roles" (same page).
  Its two readings are under Calibration.
- **The caller:** "You cannot specify the ARN of an assumed role, federated user, or a service
  principal" (same page, `CallerArn`).
- **Keys filled in from the caller:** "The simulator populates the following principal and
  organization context keys for the evaluation: Principal context: `aws:PrincipalAccount`,
  `aws:PrincipalId`, `aws:PrincipalType`, `aws:UserId`, `aws:UserName`. Organization context:
  `aws:PrincipalOrgID`, `aws:PrincipalOrgMasterAccountId`, `aws:PrincipalOrgPaths`."
  ([testing page](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html))
- **Global keys:** "For identity-based policies and resource-based policies, the simulator does
  not determine which services support a given global condition key for authorization." (same
  page)
- **SCP details are hidden:**
  - "For security reasons, SCP evaluation does not return missing context values." (same page)
  - `MatchedStatements` "doesn't include statements from service control policies (SCPs)".
    ([EvaluationResult](https://docs.aws.amazon.com/IAM/latest/APIReference/API_EvaluationResult.html))
- **Only the policies you pass:** "The simulation does not automatically retrieve policies for the
  specified resources", and the resource owner "defaults to the account of the identity provided
  in `CallerArn`".
  ([SimulateCustomPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html))
- **`EvalResourceName` isn't what the docs say:** they call it "The ARN template for the
  simulated resource type ... This is not a specific customer-provided resource ARN."
  - In every case with a resource, it was the actual resource ARN.
  - For actions with no resource type, it was `*`.
- **Not documented by AWS, but true here:**
  - The example identities don't exist, so AWS can't turn their ARNs into unique IDs, as it does
    when a policy is saved.
  - Neither side models S3 Block Public Access or ACLs.

The nine simulator limits under [Differences and decisions](#differences-and-decisions) were found
in this check. Each quotes the AWS documentation that the simulator doesn't follow.

## Results

The tables come from `python -m simulator_check.report`:
- **Matched:** where the statements that decided AWS's answer come from.
- **Details:** AWS's verdicts on the boundary and the SCPs, and the documented answer for
  calibration cases.

### Calibration cases

| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |
|---|---|---|---|---|---|---|
| `calibration_aws_example/same_account_simulation` | ALLOW | ALLOW | agrees | - | ResourcePolicy | documented: ALLOW; AllowedByPermissionsBoundary: False |
| `calibration_absent_keys/null_true_on_an_absent_token_issue_time` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | documented: ALLOW |
| `calibration_absent_keys/string_like_if_exists_on_an_absent_instance_type` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | documented: ALLOW |
| `calibration_absent_keys/string_not_equals_on_an_absent_tag` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | documented: ALLOW |
| `calibration_role_callers/bucket_policy_denies_everyone` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | ResourcePolicy | documented: EXPLICIT_DENY |
| `calibration_role_callers/bucket_policy_grants_to_the_role` | ALLOW | ALLOW | agrees | - | ResourcePolicy | documented: ALLOW |
| `scenarios/condition_bool_if_exists_denies_access_keys` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | documented: EXPLICIT_DENY |
| `scenarios/condition_for_all_values_holds_when_the_key_is_missing` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | documented: ALLOW |
| `scenarios/policy_variable_default_when_tag_is_absent` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | documented: ALLOW |

### Part 1. Wildcards and colons

| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |
|---|---|---|---|---|---|---|
| `wildcards_and_colons/arn_like_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/arn_like_mid_segment_star` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/arn_like_question_mark` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/arn_like_s3_key_colon_star` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/arn_like_star_ending_the_region_field` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `wildcards_and_colons/arn_like_star_ending_the_region_field_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/lambda_alias_end_of_segment_star` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/lambda_alias_mid_segment_star` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/lambda_mid_segment_star_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/mid_field_question_mark_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/mid_field_question_mark_crossing_a_colon` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/mid_field_star_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/mid_field_star_crossing_a_colon` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/s3_key_colon_end_of_segment_star` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/s3_key_colon_mid_segment_star` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/s3_key_colon_mid_segment_star_deny` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | - |
| `wildcards_and_colons/s3_key_colon_question_mark` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/s3_key_question_mark_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/short_pattern_star_across_fields` | IMPLICIT_DENY | ALLOW | simulator limit | - | PolicyInputList.1 | - |
| `wildcards_and_colons/star_ending_the_region_field` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/string_like_crosses_colons` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |

### Part 2. ForAllValues:StringNotLike

| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |
|---|---|---|---|---|---|---|
| `for_all_values_string_not_like/mediaou_costcenter` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | - |
| `for_all_values_string_not_like/no_resource_org_paths` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | - |
| `for_all_values_string_not_like/sportsou_costcenter` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |

### Part 3. A `*` grant when the boundary doesn't allow

| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |
|---|---|---|---|---|---|---|
| `star_grant_and_boundary/account_principal` | IMPLICIT_DENY | ALLOW | simulator limit | - | PolicyInputList.1, ResourcePolicy | AllowedByPermissionsBoundary: False |
| `star_grant_and_boundary/account_principal_without_identity_allow` | IMPLICIT_DENY | ALLOW | simulator limit | - | ResourcePolicy | AllowedByPermissionsBoundary: False |
| `star_grant_and_boundary/aws_star_principal` | ALLOW | ALLOW | agrees | - | ResourcePolicy | AllowedByPermissionsBoundary: False |
| `star_grant_and_boundary/star_principal` | ALLOW | ALLOW | agrees | - | ResourcePolicy | AllowedByPermissionsBoundary: False |
| `star_grant_and_boundary/star_principal_no_boundary_control` | ALLOW | ALLOW | agrees | - | ResourcePolicy | - |
| `star_grant_and_boundary/star_principal_role_caller` | ALLOW | ALLOW | agrees | - | ResourcePolicy | AllowedByPermissionsBoundary: False |
| `star_grant_and_boundary/star_principal_with_principal_arn_condition` | ALLOW | ALLOW | agrees | - | ResourcePolicy | AllowedByPermissionsBoundary: False |

### Part 4. The other refusals

| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |
|---|---|---|---|---|---|---|
| `variables_without_a_value/allow_control` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | aws:PrincipalTag/team | - | - |
| `variables_without_a_value/deny_not_resource` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | - |
| `variables_with_several_values/condition_string_equals` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `variables_with_several_values/condition_string_not_equals_deny` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | - |
| `variables_with_several_values/first_value` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `variables_with_several_values/not_resource_on_a_value` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | - |
| `variables_with_several_values/not_resource_on_another_bucket` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | - |
| `variables_with_several_values/second_value` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `variables_with_wildcards/condition_star_in_a_default` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | aws:PrincipalTag/team | - | - |
| `variables_with_wildcards/condition_star_in_a_value` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `variables_with_wildcards/star_in_a_default` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | aws:PrincipalTag/team | - | - |
| `variables_with_wildcards/star_in_a_value` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `bool_with_a_variable/mfa_false` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `bool_with_a_variable/mfa_true` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `dates_without_a_time_zone/date_only_just_after_midnight_utc` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `dates_without_a_time_zone/date_only_just_before_midnight_utc` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `dates_without_a_time_zone/four_digits` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `dates_without_a_time_zone/month_only_just_after_midnight_utc` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `dates_without_a_time_zone/month_only_just_before_midnight_utc` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `dates_without_a_time_zone/time_without_a_zone_just_after` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `dates_without_a_time_zone/time_without_a_zone_just_before` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `dates_without_a_time_zone/time_without_seconds_just_after` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `dates_without_a_time_zone/time_without_seconds_just_before` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `ip_ranges/bare_ipv6_address` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `ip_ranges/bare_ipv6_address_itself` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `ip_ranges/range_with_host_bits` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `short_arns_in_arn_operators/four_fields_ending_in_star` | refused | rejected | analyzer refuses | - | - | - |
| `short_arns_in_arn_operators/three_fields` | refused | rejected | analyzer refuses | - | - | - |
| `several_values_without_a_set_operator/string_equals` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `several_values_without_a_set_operator/string_not_equals` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `several_values_without_a_set_operator/string_not_equals_neither_matches` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `empty_values/for_any_value` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `empty_values/null_true` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `for_any_value_if_exists/key_absent` | refused | IMPLICIT_DENY | analyzer refuses | aws:TagKeys | - | - |
| `set_operator_on_null/for_all_values_null_false` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `set_operator_on_null/for_all_values_null_false_key_absent` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `set_operator_on_null/for_any_value_null_true_key_absent` | refused | IMPLICIT_DENY | analyzer refuses | aws:TagKeys | - | - |
| `operator_name_case/lowercase_string_equals` | rejected | rejected | agrees | - | - | - |
| `role_principal_case/role_name_in_lowercase` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `role_principal_case/user_name_in_uppercase_control` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `not_principal/names_another_user_control` | refused | EXPLICIT_DENY | analyzer refuses | - | ResourcePolicy | - |
| `not_principal/names_the_account_and_another_user` | refused | EXPLICIT_DENY | analyzer refuses | - | ResourcePolicy | - |
| `not_principal/names_the_account_and_the_caller` | refused | EXPLICIT_DENY | simulator limit | - | ResourcePolicy | - |
| `not_principal/names_the_caller` | refused | EXPLICIT_DENY | analyzer refuses | - | ResourcePolicy | - |

### Part 5. The review's other open questions

| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |
|---|---|---|---|---|---|---|
| `list_all_my_buckets/allowed_on_every_bucket_arn` | refused | IMPLICIT_DENY | simulator limit | - | - | - |
| `list_all_my_buckets/allowed_on_star_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `scp_allow_statements/not_action_allow_ec2` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | AllowedByOrganizations: False |
| `scp_allow_statements/not_action_allow_s3` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | AllowedByOrganizations: True |
| `scp_allow_statements/resource_scoped_allow_inside` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | AllowedByOrganizations: True |
| `scp_allow_statements/resource_scoped_allow_outside` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | AllowedByOrganizations: False |
| `scp_short_arn/short_arn_in_an_scp_deny` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | AllowedByOrganizations: True |

### Judgment call

| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |
|---|---|---|---|---|---|---|
| `set_operators_on_numbers/for_any_value_numeric_less_than` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |

### Part 6. Existing scenarios

| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |
|---|---|---|---|---|---|---|
| `scenarios/action_case_insensitive` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `scenarios/admin_blocked_from_deleting_records` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | - |
| `scenarios/admin_can_delete_other_buckets` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `scenarios/boundary_allows_vendor_bucket` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | AllowedByPermissionsBoundary: True |
| `scenarios/boundary_blocks_vendor_from_student_records` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | AllowedByPermissionsBoundary: False |
| `scenarios/boundary_deny_beats_bucket_policy_allow` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PermissionsBoundaryPolicyInputList.1 | AllowedByPermissionsBoundary: False |
| `scenarios/boundary_does_not_grant_access` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | AllowedByPermissionsBoundary: True |
| `scenarios/bucket_policy_alone_allows_a_named_user` | ALLOW | ALLOW | agrees | - | ResourcePolicy | - |
| `scenarios/bucket_policy_and_identity_policy_both_allow` | ALLOW | ALLOW | agrees | - | PolicyInputList.1, ResourcePolicy | - |
| `scenarios/bucket_policy_deny_except_one_user_blocks_others` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | ResourcePolicy | - |
| `scenarios/bucket_policy_deny_except_one_user_spares_that_user` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `scenarios/bucket_policy_role_grant_is_limited_by_the_boundary` | IMPLICIT_DENY | ALLOW | simulator limit | - | ResourcePolicy | AllowedByPermissionsBoundary: False |
| `scenarios/bucket_policy_user_grant_is_not_limited_by_the_boundary` | ALLOW | ALLOW | agrees | - | ResourcePolicy | AllowedByPermissionsBoundary: False |
| `scenarios/campus_log_question_mark_wildcard` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `scenarios/condition_bool_if_exists_denies_access_keys` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | documented: EXPLICIT_DENY |
| `scenarios/condition_for_all_values_holds_when_the_key_is_missing` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | documented: ALLOW |
| `scenarios/identity_deny_beats_bucket_policy_allow` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.1 | - |
| `scenarios/incomplete_arn_allow_is_completed_with_wildcards` | ALLOW | IMPLICIT_DENY | simulator limit | - | - | - |
| `scenarios/incomplete_arn_is_completed_with_wildcards` | EXPLICIT_DENY | ALLOW | simulator limit | - | PolicyInputList.1 | - |
| `scenarios/policy_variable_default_when_tag_is_absent` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | documented: ALLOW |
| `scenarios/policy_variable_fills_in_username` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `scenarios/policy_variable_other_users_folder` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |
| `scenarios/scp_allow_list_blocks_unlisted_service` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | AllowedByOrganizations: False |
| `scenarios/scp_deny_beats_admin` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | - | AllowedByOrganizations: False |
| `scenarios/scp_region_lock_allows_approved_region` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | AllowedByOrganizations: True |
| `scenarios/scp_region_lock_blocks_other_regions` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | - | AllowedByOrganizations: False |
| `scenarios/scp_skips_service_linked_role` | ALLOW | IMPLICIT_DENY | simulator limit | - | - | AllowedByOrganizations: False |
| `scenarios/substitute_guardrail_allows_read` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `scenarios/substitute_guardrail_blocks_write` | EXPLICIT_DENY | EXPLICIT_DENY | agrees | - | PolicyInputList.2 | - |
| `scenarios/substitute_guardrail_ignores_other_buckets` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `scenarios/teacher_can_read_roster` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `scenarios/teacher_cannot_write_roster` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | - |

## Differences and decisions

This section covers every case marked `differs`, `simulator limit` or `analyzer refuses`, and the
decision for each, made on 2026-10-25 and 2026-10-26. The engine follows a decision once its
section says "Done".

The decisions follow the project's rule for AWS's docs:
- where AWS's docs clearly settle a question, the analyzer follows them, even when the simulator
  disagrees;
- where they contradict each other or don't say, a recorded simulator answer can settle it.

### 1. Wildcards match colons (9 cases, which now agree)
- **What the simulator did:**

  | Pattern | Request | Where | Answer |
  |---|---|---|---|
  | `function:*-prod` | the alias `function:billing:canary-prod` | `Resource` | ALLOW |
  | `arn:aws:s3:::district-logs/*.json` | the key `2026-10-25T10:00:00.json` | `Resource`, in an Allow and in a Deny | ALLOW, and the Deny applied |
  | `campus?01` | `campus:01` | `Resource` | ALLOW |
  | the same three patterns | the same values | `ArnLike` | each ALLOW |
  | `arn:aws:lambda:us-*3:function:billing:canary` | the alias `billing:canary` in us-east-1, account 111122223333 | `Resource` (second follow-up) | ALLOW: the `*` in the region field ran across the colon to the account ID's final `3` |
  | `arn:aws:lambda:us-east-1?111122223333:function:billing:canary` | the same alias | `Resource` (third follow-up) | ALLOW: the `?` in the region field matched the colon before the account ID |

  The controls agree with the analyzer:
  - a `*` at the end of a segment runs past colons;
  - `StringLike` crosses colons;
  - the patterns still match values with no colon;
  - `us-*-1` and `us-east-?` match `us-east-1` (`mid_field_star_control`,
    `mid_field_question_mark_control`);
  - in `ArnLike`, `arn:aws:lambda:*:function:billing:canary` doesn't match the alias, although the
    same pattern does in `Resource`: the `*` that ends the region field stays in its field
    (`arn_like_star_ending_the_region_field`, third follow-up). Its control, whose six fields line
    up with the alias's ARN, matches.
- **What AWS says:**
  - [Resource element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html#reference_policies_elements_resource_wildcards):
    "You can use wildcard characters (`*` and `?`) within the individual segments of an ARN (the
    parts separated by colons) ... If the `*` wildcard is the last character of a resource ARN
    segment, it can expand to match beyond the colon boundaries. We recommend you use wildcards
    (`*` and `?`) within ARN segments separated by a colon."
  - [ARN operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_ARN):
    "Each of the six colon-delimited components of the ARN is checked separately."
  - The `Resource` page only implies that a wildcard stays inside its segment. The `ArnLike` page
    says outright that each of the six components "is checked separately". Review finding F6
    split at every colon instead.
- **Why it matters:**
  - In eight cases the analyzer misses an `Allow`, so it says someone can't get in when AWS would
    let them. That's the unsafe direction.
  - In one it misses a `Deny`, such as `arn:aws:s3:::district-logs/*.json` on keys with colons,
    so it reports access AWS would deny. That's wrong too, but it errs on the safe side.
- **Decision (2026-10-25):** follow the simulator.
  - Split an ARN at its first five colons, and let `*` and `?` match colons in the resource part,
    in `Resource` and `ArnLike`.
  - Keep the documented run-on for a `*` that ends one of the first five fields:
    - in `star_ending_the_region_field`, the pattern `arn:aws:lambda:*:function:billing:canary`
      matched an alias in us-east-1;
    - AWS documents it: "If the `*` wildcard is the last character of a resource ARN segment, it
      can expand to match beyond the colon boundaries";
    - the analyzer does it today.
- **What the follow-ups settled:**
  - **`Resource`:** the page only implies segments, so by the rule above the recorded answers
    settle it. In the middle of one of the first five fields, a `*` crosses colons (second
    follow-up, `mid_field_star_crossing_a_colon`) and so does a `?` (third follow-up,
    `mid_field_question_mark_crossing_a_colon`). So `Resource` and `NotResource` are a plain glob
    over the whole ARN, which also covers the documented run-on. This replaces "split at the first
    five colons" for `Resource`.
  - **`ArnLike`:** "Each of the six colon-delimited components of the ARN is checked separately"
    settles the split at the first five colons, and the third follow-up agrees
    (`arn_like_star_ending_the_region_field` and its control). Each field is matched as a plain
    glob, so only the resource part can match a colon.
- **Short patterns:** `short_pattern_star_across_fields` ran across fields only because the
  simulator doesn't complete short ARNs, which is a simulator limit (section 4). Completion stays
  as AWS documents it.
- **Done (2026-10-26):** the nine cases now agree.
  - `matching.py` no longer has a segmented mode: a resource pattern is a plain glob, completed
    first if it's a short ARN.
  - `conditions._arn_like` matches each of the six fields as a plain glob.
  - Tests: `test_matching.py` (`test_wildcards_match_colons_anywhere`,
    `test_the_patterns_still_need_the_rest_to_match`) and `test_conditions.py`
    (`test_arn_like_checks_the_six_fields_separately`).

### 2. A bucket policy naming the account (2 cases, simulator limit)
- **What the simulator did:**
  - `star_grant_and_boundary/account_principal`: the identity policy allows kwong's read, the
    boundary allows only `ec2:*`, and the bucket policy names account 111122223333. Answer: ALLOW,
    with `AllowedByPermissionsBoundary` false.
  - `star_grant_and_boundary/account_principal_without_identity_allow`, the follow-up probe: the
    same, but no identity policy allows the read. Answer: still ALLOW.
- **So:** the simulator treats naming the account as a grant to everyone in it. AWS says it
  "delegates authority to the account"
  ([Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-accounts)).
- **Decision:** a simulator limit, since the follow-up came back ALLOW. The analyzer's
  reading stands: naming the account delegates to the identity policies, which the boundary
  limits. No engine change.

### 3. A short ARN in an SCP (1 case, which the analyzer now refuses)
- **What the simulator did:** in `scp_short_arn/short_arn_in_an_scp_deny`, an SCP denies `s3:*` on
  `arn:aws:s3`. The simulator allowed the read; the analyzer completes the ARN and denies.
- **Why this is weak evidence:** the simulator doesn't complete short ARNs in identity-based
  policies either, where AWS documents that it should (section 4).
- **What AWS says:** completion is documented only "in an identity-based policy"
  ([ARNs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html#arns-paths-wildcards)).
- **Decision:**
  - Refuse a short ARN in an SCP or a resource-based policy.
  - Keep completing short ARNs in identity-based policies, as AWS documents. A boundary is an
    identity-based policy.
- **Done (2026-10-26):** the loader refuses a short ARN in `Resource` or `NotResource` when it
  loads an SCP or a resource-based policy (`loader._check_full_arns`), and organization files load
  their SCPs with `kind=PolicyType.SCP`. The case is now `analyzer refuses`.

### 4. Simulator limits (9 cases)
In each case, AWS documents a behavior that the simulator doesn't follow. `verdicts.json` keeps the
quote and the link.

| Case | AWS documents | The simulator |
|---|---|---|
| `scenarios/incomplete_arn_allow_is_completed_with_wildcards`, `scenarios/incomplete_arn_is_completed_with_wildcards`, `wildcards_and_colons/short_pattern_star_across_fields` | "When you specify an incomplete ARN (one with fewer than the standard six fields) in an identity-based policy, AWS automatically completes the ARN by adding wildcard characters (\*) to all missing fields. For example, specifying arn:aws:sqs is equivalent to arn:aws:sqs:\*:\*:\*" ([ARNs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html#arns-paths-wildcards)) | doesn't complete them, and then globs across fields |
| `scenarios/bucket_policy_role_grant_is_limited_by_the_boundary` | "Resource-based policies that grant permissions to an IAM role ARN are limited by an implicit deny in a permissions boundary or session policy." ([evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)) | allows the grant to the role although its boundary doesn't |
| `star_grant_and_boundary/account_principal`, `star_grant_and_boundary/account_principal_without_identity_allow` | "This delegates authority to the account." ([Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-accounts)) | treats naming the account as a grant to everyone in it |
| `scenarios/scp_skips_service_linked_role` | "SCPs do not affect any service-linked role." ([SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html#scp-effects-on-permissions)) | applies the SCPs to a service-linked role |
| `not_principal/names_the_account_and_the_caller` | "The NotPrincipal element uses "Effect":"Deny" to deny access to all principals except the principal specified in the NotPrincipal element." ([NotPrincipal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html)) | denies kwong although the element names kwong and kwong's account, as AWS recommends |
| `list_all_my_buckets/allowed_on_every_bucket_arn` | "The AllowS3ListRead statement in this policy allows Carlos to view a list of all of the buckets in the account." That statement allows `s3:ListAllMyBuckets` on `arn:aws:s3:::*`. ([evaluation example](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html#reference_policies_evaluation-logic_policies_evaluation_example)) | denies, because it matches the request as `*` |

**Decision:**
- No engine change for these. The analyzer already does what AWS documents, and the fixtures keep
  the evidence.
- `ListAllMyBuckets` (review open question 3) is the exception. Both sides deny, but the
  analyzer's answer contradicts AWS's example too. So the analyzer will refuse a request on `*`
  whose answer depends on a statement with a resource ARN.
  - Narrowed on 2026-10-26: only for `s3:ListAllMyBuckets`. For any other action with no resource
    type, the Service Authorization Reference settles it: "you must specify all resources ("\*")
    in your policy", and "If you specify a resource that is not valid for the action, any request
    to use that action fails, and the statement's `Effect` does not apply"
    ([actions table](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html#actions_table)).
  - **Done (2026-10-26):** `evaluator._resource_matches` marks a statement that names resource
    ARNs as unsettled for `s3:ListAllMyBuckets` on `*`. Evaluation then works the answer out with
    every unsettled Allow and no unsettled Deny, and the other way round. It answers when the two
    agree, and refuses otherwise. This case now gives `refused`.

### 5. Refusals that AWS answered (41 cases)
Each row is a case the analyzer refuses because AWS's docs don't settle it, with what the
simulator answered and the decision. "Adopt" means the engine gives the simulator's answer
instead of refusing, once the row says "Done". Each adopted row names its fixtures.

| Refusal | Cases | The simulator | Decision | Code |
|---|---|---|---|---|
| A policy variable with no value | `variables_without_a_value/*` (2) | It matches nothing: a Deny with `NotResource` applied, and an Allow didn't. The "Policy variables with no value" section says the same | Adopt. Done (2026-10-26) | `variables.resolve`, `evaluator._resource_patterns`, `conditions.holds` |
| A variable from a multivalued key | `variables_with_several_values/*` (6) | In `Resource`, neither value was used. In `NotResource`, the Deny covered every bucket, including the one named after a value. In a condition value (third follow-up), `StringEquals` failed for a value of the key, and a `StringNotEquals` Deny applied to one | Adopt, settled by the second and third follow-ups: it matches nothing, as a variable with no value does, in `Resource`, `NotResource` and condition values. Done (2026-10-26). Such a variable with a default is still refused, since nothing probed it | `variables._value` |
| A `*` in a variable's value or default | `variables_with_wildcards/*` (4) | A literal `*`, in `Resource` and, in the third follow-up, in a `StringLike` value | Adopt: a filled-in value is plain text, in `Resource` and in condition values. Done (2026-10-26) | `variables._value`, `variables.parse` |
| A policy variable in a `Bool` value | `bool_with_a_variable/*` (2) | Not filled in, so the condition fails. AWS accepts the policy | Adopt: the text stays as written, as the policy variables page says. Done (2026-10-26) | `conditions.check`, `conditions._bool_value` |
| A date with no time or no zone | `dates_without_a_time_zone/*` (9) | `2026-08-15` is midnight UTC; `2026-08` is midnight UTC on the 1st; a time with no zone is UTC, with seconds (`07:30:00`) or without (`07:30`); `2026` is epoch seconds | Adopt exactly these forms. `2026-08` and the time without seconds were settled by the follow-up probes. Keep refusing any other form, such as fractional seconds with no zone | `conditions._date` |
| A range with host bits set | `ip_ranges/range_with_host_bits` | The host bits are masked | Adopt | `conditions._network` |
| A bare IPv6 address | `ip_ranges/bare_ipv6_address`, `ip_ranges/bare_ipv6_address_itself` | It covers itself but not `2001:db8::2`: /128 | Adopt /128. AWS's "default prefix value of /32" only makes sense for IPv4, since a /32 in IPv6 covers 2^96 addresses: a doc mismatch (section 6) | `conditions._network` |
| An ARN operator value with fewer than six fields | `short_arns_in_arn_operators/*` (2) | AWS rejects the simulation (`InvalidInput`), though `GetContextKeysForCustomPolicy` accepts the policy | Keep refusing | |
| Several request values with no set operator | `several_values_without_a_set_operator/*` (3) | Never a match: IMPLICIT_DENY for `StringEquals` and `StringNotEquals`, even when no value is `campus` | Adopt for those two operators, settled by the follow-up probe: the condition doesn't hold. Keep refusing other operators | `conditions.holds` |
| A request whose only value is `""` | `empty_values/*` (2) | It counts as a value under `ForAnyValue`, and as present under `Null` | Adopt. Only `ForAllValues` treats `""` as a null dataset, as AWS documents | `conditions.holds` |
| `ForAnyValue…IfExists` on a missing key | `for_any_value_if_exists/key_absent` | ForAnyValue wins: the condition fails | Adopt | `conditions._missing` |
| A set operator on `Null` | `set_operator_on_null/*` (3) | Accepted. With the key present, `ForAllValues:Null` false held. With the key missing, `ForAllValues:Null` false held and `ForAnyValue:Null` true failed | Adopt, settled by the second follow-up: the set operator applies as it does to other operators. On a missing key, `ForAllValues` holds and `ForAnyValue` fails; with the key present, `Null`'s own answer stands | `conditions.parse_operator`, `conditions.holds` |
| A role ARN that matches the caller only if case is ignored | `role_principal_case/role_name_in_lowercase` | Case matters | Keep refusing: a saved policy turns a role ARN into the role's unique ID, which the simulator can't do for an example role | |
| `NotPrincipal` | `not_principal/*` (3) | Always EXPLICIT_DENY | Keep refusing: the simulator's `NotPrincipal` answers contradict AWS's docs (section 4) | |

AWS's NotPrincipal page also warns that "The `NotPrincipal` element with a `Deny` effect will always
deny any IAM principal that has a permissions boundary policy attached, regardless of the values
specified in the `NotPrincipal` element". That belongs in phase 6's list of findings.

### 6. Doc mismatches
These are places where AWS's own documentation says one thing and AWS's evaluator, the simulator,
does another, and the docs can't be taken at their word. The simulator limits in section 4 are the
other way round: there the docs are right, and the simulator is the one that's off.

| AWS's docs say | What the simulator does | Evidence | The analyzer |
|---|---|---|---|
| "If you specify an IP address without the associated routing prefix, IAM uses the default prefix value of /32." ([condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IPAddress)) | Treats a bare IPv6 address as /128 | `ip_ranges/bare_ipv6_address`, `ip_ranges/bare_ipv6_address_itself` | Will follow the simulator (decided 2026-10-25). /32 only makes sense for IPv4, since a /32 in IPv6 covers 2^96 addresses |
| The evaluation table under the `ForAllValues:StringNotLike` example for `aws:ResourceOrgPaths` says the opposite of the operator definitions in all three rows | Follows the definitions | `for_all_values_string_not_like/*` | Follows the definitions (phase 4b) |
| "In statements where the Effect element has a value of Allow, you can specify only "\*" in the Resource element of an SCP. You can't specify individual resource Amazon Resource Names (ARNs)." ([SCP syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html#scp-syntax-resource)) | Honors a resource ARN, and `NotAction`, in an SCP Allow, as AWS's September 2025 announcement says | `scp_allow_statements/*` | Follows the announcement (since phase 3b) |
| "Every SCP must include a Version element with the value "2012-10-17"." (same page, whose own examples leave it out) | Accepts SCPs without a `Version` | the `scenarios/scp_*` fixtures, whose `FullAWSAccess` has none | Doesn't require one (since review fix F7) |
| "The policy simulator evaluates SCPs, including condition keys and resource scoping in deny statements" ([testing page](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)) | Applies resource scoping in an SCP Allow too | `scp_allow_statements/resource_scoped_allow_*` | Nothing to change: this is about the simulator |
| "If you do not provide a value for a context key, the simulation still runs and returns an implicit deny" ([how to simulate](https://docs.aws.amazon.com/IAM/latest/UserGuide/policies_policy-simulator-how-to.html)) | Treats a key left out as absent. It returns an implicit deny only when a statement fails for lack of the key | `calibration_absent_keys/*`, and the three calibration scenarios | Nothing to change: this is about the simulator |
| `EvalResourceName` is "The ARN template for the simulated resource type ... This is not a specific customer-provided resource ARN." ([EvaluationResult](https://docs.aws.amazon.com/IAM/latest/APIReference/API_EvaluationResult.html)) | Returns the requested ARN, or `*` | every fixture with an answer | Nothing to change: this is about the simulator |

## Follow-up probes (recorded 2026-10-25 and 2026-10-26)

### First round

| Probe | Fixtures | The simulator | What it settled |
|---|---|---|---|
| The account as principal, with no identity policy that allows the read | `star_grant_and_boundary/account_principal_without_identity_allow` | ALLOW | Difference 2 is a simulator limit |
| A `*` running across fields | `wildcards_and_colons/short_pattern_star_across_fields`, `wildcards_and_colons/star_ending_the_region_field` | ALLOW, ALLOW | A `*` that ends one of the first five fields runs on, as documented; a short pattern runs across fields only because the simulator doesn't complete it |
| A bare IPv6 address against itself | `ip_ranges/bare_ipv6_address_itself` | ALLOW | /128 |
| `StringNotEquals` on `aws:TagKeys` with [grade, other] | `several_values_without_a_set_operator/string_not_equals_neither_matches` | IMPLICIT_DENY | Several values with no set operator never match |
| A month-only date, and a time without seconds | `dates_without_a_time_zone/month_only_*`, `dates_without_a_time_zone/time_without_seconds_*` | ALLOW just after, IMPLICIT_DENY just before | Midnight UTC at the start of the month; `07:30` is 07:30:00 UTC |

### Second round

| Probe | Fixtures | The simulator | What it settled |
|---|---|---|---|
| A `*` in the middle of the region field that matches only by crossing a colon, with a control that needs no crossing | `wildcards_and_colons/mid_field_star_crossing_a_colon`, `wildcards_and_colons/mid_field_star_control` | ALLOW, ALLOW | In `Resource`, a `*` crosses colons anywhere in the ARN (difference 1) |
| A variable from a multivalued key in `NotResource`, on a bucket named after a value and on one that isn't | `variables_with_several_values/not_resource_on_a_value`, `variables_with_several_values/not_resource_on_another_bucket` | EXPLICIT_DENY, EXPLICIT_DENY | The variable matches nothing. The statement isn't dropped, and no value is used |
| `ForAllValues:Null` false and `ForAnyValue:Null` true, with the key missing | `set_operator_on_null/for_all_values_null_false_key_absent`, `set_operator_on_null/for_any_value_null_true_key_absent` | ALLOW, IMPLICIT_DENY | The set operator applies, as it does to other operators |

### Third round (2026-10-26)

| Probe | Fixtures | The simulator | What it settled |
|---|---|---|---|
| A `?` in the middle of the region field that matches only by standing for a colon, with a control that needs no colon | `wildcards_and_colons/mid_field_question_mark_crossing_a_colon`, `wildcards_and_colons/mid_field_question_mark_control` | ALLOW, ALLOW | In `Resource`, a `?` crosses colons anywhere too: a plain glob over the whole ARN (difference 1) |
| `ArnLike` with `arn:aws:lambda:*:function:billing:canary`, which matched in `Resource`, and a control whose fields line up | `wildcards_and_colons/arn_like_star_ending_the_region_field`, `wildcards_and_colons/arn_like_star_ending_the_region_field_control` | IMPLICIT_DENY, ALLOW | `ArnLike` checks the six fields separately, as AWS documents (difference 1) |
| A `*` from a variable's value and from its default, in a `StringLike` value | `variables_with_wildcards/condition_star_in_a_value`, `variables_with_wildcards/condition_star_in_a_default` | IMPLICIT_DENY, IMPLICIT_DENY | A filled-in `*` is literal in a condition value too |
| A variable from a multivalued key, in a `StringEquals` Allow and a `StringNotEquals` Deny, with the request's value one of the key's values | `variables_with_several_values/condition_string_equals`, `variables_with_several_values/condition_string_not_equals_deny` | IMPLICIT_DENY, EXPLICIT_DENY | The variable matches nothing in a condition value too: the statement isn't dropped, and no value is used |

## Recording again
Recording calls AWS, through the `iam-simulator` profile.

```sh
pip install -e ".[dev,simulator]"
python -m simulator_check.record --dry-run             # the requests and the analyzer's answers, without AWS
python -m simulator_check.record --only GROUP/CASE     # record cases that have no fixture yet
python -m simulator_check.record --only GROUP --force  # record again over existing fixtures
python -m simulator_check.report                       # the results tables above
```

After recording, update `verdicts.json`, run `pytest`, and regenerate the tables.
