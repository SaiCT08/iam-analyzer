# Checking the analyzer against AWS's IAM policy simulator

Recorded on 2026-10-25. For 98 cases, the analyzer and AWS's IAM policy simulator
(`iam:SimulateCustomPolicy`) were given the same policies and the same request, and their answers
were compared.
- **Fixtures:** each request and AWS's raw response is a fixture in
  [`tests/simulator_fixtures`](../tests/simulator_fixtures), with AWS's request IDs and the date.
- **Offline replay:** [`tests/test_simulator_fixtures.py`](../tests/test_simulator_fixtures.py)
  replays the fixtures without AWS, so the comparison keeps running after the AWS account is
  closed.
- **No engine changes:** the differences below are still open.

## Summary

| Verdict | Cases | Meaning |
|---|---|---|
| agrees | 56 | Both sides gave the same answer. |
| differs | 9 | A real mismatch. |
| simulator limit | 6 | AWS documents a behavior that the simulator doesn't follow. |
| analyzer refuses | 27 | AWS answered a case the analyzer refuses because AWS's docs don't settle it. |
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
  - Every existing scenario the simulator can express agrees, except the four that simulator
    limits explain.
- **The main difference: wildcards can match a colon in the resource part of an ARN.** In
  `Resource` and in `ArnLike`, a `*` in the middle of the resource part, or a `?`, matches a
  colon (7 cases).
  - The analyzer says it can't, so in six cases it misses an `Allow`. It says someone can't get
    in when AWS would let them: the unsafe direction.
  - In the seventh it misses a `Deny` written as `*.json` for S3 keys that contain colons. That
    over-reports access, which is wrong but errs on the safe side.
- **The simulator's own limits.** Against AWS's documentation, it:
  - doesn't complete short ARNs;
  - doesn't exempt service-linked roles from SCPs;
  - doesn't limit a grant to a role ARN by that role's boundary;
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

The six simulator limits below are differences found in this check. Each quotes the AWS
documentation that the simulator doesn't follow.

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
| `wildcards_and_colons/arn_like_mid_segment_star` | IMPLICIT_DENY | ALLOW | differs | - | PolicyInputList.1 | - |
| `wildcards_and_colons/arn_like_question_mark` | IMPLICIT_DENY | ALLOW | differs | - | PolicyInputList.1 | - |
| `wildcards_and_colons/arn_like_s3_key_colon_star` | IMPLICIT_DENY | ALLOW | differs | - | PolicyInputList.1 | - |
| `wildcards_and_colons/lambda_alias_end_of_segment_star` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/lambda_alias_mid_segment_star` | IMPLICIT_DENY | ALLOW | differs | - | PolicyInputList.1 | - |
| `wildcards_and_colons/lambda_mid_segment_star_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/s3_key_colon_end_of_segment_star` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `wildcards_and_colons/s3_key_colon_mid_segment_star` | IMPLICIT_DENY | ALLOW | differs | - | PolicyInputList.1 | - |
| `wildcards_and_colons/s3_key_colon_mid_segment_star_deny` | ALLOW | EXPLICIT_DENY | differs | - | PolicyInputList.2 | - |
| `wildcards_and_colons/s3_key_colon_question_mark` | IMPLICIT_DENY | ALLOW | differs | - | PolicyInputList.1 | - |
| `wildcards_and_colons/s3_key_question_mark_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
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
| `star_grant_and_boundary/account_principal` | IMPLICIT_DENY | ALLOW | differs | - | PolicyInputList.1, ResourcePolicy | AllowedByPermissionsBoundary: False |
| `star_grant_and_boundary/aws_star_principal` | ALLOW | ALLOW | agrees | - | ResourcePolicy | AllowedByPermissionsBoundary: False |
| `star_grant_and_boundary/star_principal` | ALLOW | ALLOW | agrees | - | ResourcePolicy | AllowedByPermissionsBoundary: False |
| `star_grant_and_boundary/star_principal_no_boundary_control` | ALLOW | ALLOW | agrees | - | ResourcePolicy | - |
| `star_grant_and_boundary/star_principal_role_caller` | ALLOW | ALLOW | agrees | - | ResourcePolicy | AllowedByPermissionsBoundary: False |
| `star_grant_and_boundary/star_principal_with_principal_arn_condition` | ALLOW | ALLOW | agrees | - | ResourcePolicy | AllowedByPermissionsBoundary: False |

### Part 4. The other refusals

| Case | Analyzer | Simulator | Verdict | Missing context values | Matched | Details |
|---|---|---|---|---|---|---|
| `variables_without_a_value/allow_control` | refused | IMPLICIT_DENY | analyzer refuses | aws:PrincipalTag/team | - | - |
| `variables_without_a_value/deny_not_resource` | refused | EXPLICIT_DENY | analyzer refuses | - | PolicyInputList.2 | - |
| `variables_with_several_values/first_value` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `variables_with_several_values/second_value` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `variables_with_wildcards/star_in_a_default` | refused | IMPLICIT_DENY | analyzer refuses | aws:PrincipalTag/team | - | - |
| `variables_with_wildcards/star_in_a_value` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `bool_with_a_variable/mfa_false` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `bool_with_a_variable/mfa_true` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `dates_without_a_time_zone/date_only_just_after_midnight_utc` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `dates_without_a_time_zone/date_only_just_before_midnight_utc` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `dates_without_a_time_zone/four_digits` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `dates_without_a_time_zone/time_without_a_zone_just_after` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `dates_without_a_time_zone/time_without_a_zone_just_before` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `ip_ranges/bare_ipv6_address` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `ip_ranges/range_with_host_bits` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `short_arns_in_arn_operators/four_fields_ending_in_star` | refused | rejected | analyzer refuses | - | - | - |
| `short_arns_in_arn_operators/three_fields` | refused | rejected | analyzer refuses | - | - | - |
| `several_values_without_a_set_operator/string_equals` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `several_values_without_a_set_operator/string_not_equals` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `empty_values/for_any_value` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
| `empty_values/null_true` | refused | IMPLICIT_DENY | analyzer refuses | - | - | - |
| `for_any_value_if_exists/key_absent` | refused | IMPLICIT_DENY | analyzer refuses | aws:TagKeys | - | - |
| `set_operator_on_null/for_all_values_null_false` | refused | ALLOW | analyzer refuses | - | PolicyInputList.1 | - |
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
| `list_all_my_buckets/allowed_on_every_bucket_arn` | IMPLICIT_DENY | IMPLICIT_DENY | simulator limit | - | - | - |
| `list_all_my_buckets/allowed_on_star_control` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | - |
| `scp_allow_statements/not_action_allow_ec2` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | AllowedByOrganizations: False |
| `scp_allow_statements/not_action_allow_s3` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | AllowedByOrganizations: True |
| `scp_allow_statements/resource_scoped_allow_inside` | ALLOW | ALLOW | agrees | - | PolicyInputList.1 | AllowedByOrganizations: True |
| `scp_allow_statements/resource_scoped_allow_outside` | IMPLICIT_DENY | IMPLICIT_DENY | agrees | - | - | AllowedByOrganizations: False |
| `scp_short_arn/short_arn_in_an_scp_deny` | EXPLICIT_DENY | ALLOW | differs | - | PolicyInputList.1 | AllowedByOrganizations: True |

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

## Open differences

This section covers every case marked `differs`, `simulator limit` or `analyzer refuses`. For
each there is the evidence, the options, a recommendation, and the code a change would touch.
The engine hasn't changed.

### 1. Wildcards match colons in the resource part of an ARN (7 cases, differs)
- **What the simulator did:**

  | Pattern | Request | Where | Answer |
  |---|---|---|---|
  | `function:*-prod` | the alias `function:billing:canary-prod` | `Resource` | ALLOW |
  | `arn:aws:s3:::district-logs/*.json` | the key `2026-10-25T10:00:00.json` | `Resource`, in an Allow and in a Deny | ALLOW, and the Deny applied |
  | `campus?01` | `campus:01` | `Resource` | ALLOW |
  | the same three patterns | the same values | `ArnLike` | each ALLOW |

  The controls agree with the analyzer: a `*` at the end of a segment runs past colons,
  `StringLike` crosses colons, and the patterns still match values with no colon.
- **What AWS says:**
  - [Resource element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html#reference_policies_elements_resource_wildcards):
    "You can use wildcard characters (`*` and `?`) within the individual segments of an ARN (the
    parts separated by colons) ... If the `*` wildcard is the last character of a resource ARN
    segment, it can expand to match beyond the colon boundaries. We recommend you use wildcards
    (`*` and `?`) within ARN segments separated by a colon."
  - [ARN operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_ARN):
    "Each of the six colon-delimited components of the ARN is checked separately."
  - The simulator fits the reading that the segments are the six ARN fields. Colons inside the
    resource part, after the fifth colon, then aren't segment boundaries. Review finding F6 split
    at every colon instead.
- **Why it matters:**
  - In six cases the analyzer misses an `Allow`, so it says someone can't get in when AWS would
    let them. That's the unsafe direction.
  - In one it misses a `Deny`, such as `arn:aws:s3:::district-logs/*.json` on keys with colons,
    so it reports access AWS would deny. That's wrong too, but it errs on the safe side.
- **Options:**
  - **(a)** Follow the simulator. Split an ARN at its first five colons only, and let `*` and `?`
    match any character in the resource part, colons included.
  - **(b)** Keep today's rule.
  - **(c)** Refuse a request whose answer depends on a wildcard matching a colon in the resource
    part.
- **Recommendation: (a).** Two AWS pages are consistent with it, the simulator shows it seven
  times, and today's rule misses Allows, the unsafe direction.
  - **Not probed:** whether a wildcard in one of the first five fields can run on into the next.
    That's a follow-up probe below.
- **Code:**
  - `matching.py`: the segmented mode of `_compile`, and the module docstring;
  - `conditions._arn_like`, which already splits six fields but then segments each one;
  - tests: `test_matching.py` (`test_star_inside_a_segment_does_not_cross_colons`,
    `test_question_mark_does_not_match_a_colon`) and `test_conditions.py`
    (`test_arn_wildcards_follow_the_resource_segment_rule`);
  - the README's Status section.

### 2. A bucket policy naming the account, with a boundary that doesn't allow (1 case, differs)
- **What the simulator did:** `star_grant_and_boundary/account_principal` is a read by kwong.
  - The identity policy allows it.
  - The boundary allows only `ec2:*`.
  - The bucket policy names account 111122223333.

  The simulator: allowed, with the identity policy and the bucket policy both matched, and
  `AllowedByPermissionsBoundary` false. The analyzer: IMPLICIT_DENY.
- **What AWS says:** [Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-accounts):
  "This delegates authority to the account." Nothing says whether the boundary then limits the
  request.
- **Options:**
  - **(a)** Keep the judgment call: naming the account delegates to the identity policies, which
    the boundary limits.
  - **(b)** Follow the simulator: a grant to the account isn't limited by the boundary.
  - **(c)** Refuse, since the docs don't say.
- **Recommendation:** first run the follow-up probe below: the same bucket policy with no identity
  policy that allows the read.
  - If the simulator still allows it, it treats naming the account as a grant to everyone in the
    account. That contradicts "delegates authority to the account", so this case would be a
    simulator limit, and (a) stands.
  - Until then, keep (a).
- **Code:** `evaluator._needed` and `models.PrincipalMatch.direct`.

### 3. A short ARN in an SCP (1 case, differs)
- **What the simulator did:** `scp_short_arn/short_arn_in_an_scp_deny` has an SCP that denies
  `s3:*` on `arn:aws:s3`. The simulator allowed the read; the analyzer completes the ARN and
  denies.
- **Why this is weak evidence:** the simulator doesn't complete short ARNs in identity-based
  policies either, where AWS documents that it should (simulator limits, below).
- **What AWS says:** completion is documented only "in an identity-based policy"
  ([ARNs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html#arns-paths-wildcards)).
- **Options:**
  - **(a)** Keep completing short ARNs in every layer, as today.
  - **(b)** Refuse a short ARN in an SCP or a resource-based policy, as the project's rule says to do when
    the docs don't settle a case. A boundary is an identity-based policy, so it keeps
    completion.
- **Recommendation: (b).** The simulator can't settle the question.
- **Code:** `matching._complete_arn` is shared by every layer, so the loader or the evaluator
  would need to know the policy's kind. The organization loader would load SCPs with
  `kind=PolicyType.SCP`.

### 4. Simulator limits (6 cases)
In each case, AWS documents a behavior that the simulator doesn't follow.
`verdicts.json` keeps the quote and the link.

| Case | AWS documents | The simulator |
|---|---|---|
| `scenarios/incomplete_arn_allow_is_completed_with_wildcards`, `scenarios/incomplete_arn_is_completed_with_wildcards` | "When you specify an incomplete ARN (one with fewer than the standard six fields) in an identity-based policy, AWS automatically completes the ARN by adding wildcard characters (\*) to all missing fields. For example, specifying arn:aws:sqs is equivalent to arn:aws:sqs:\*:\*:\*" ([ARNs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html#arns-paths-wildcards)) | doesn't complete them |
| `scenarios/bucket_policy_role_grant_is_limited_by_the_boundary` | "Resource-based policies that grant permissions to an IAM role ARN are limited by an implicit deny in a permissions boundary or session policy." ([evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)) | allows the grant to the role although its boundary doesn't |
| `scenarios/scp_skips_service_linked_role` | "SCPs do not affect any service-linked role." ([SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html#scp-effects-on-permissions)) | applies the SCPs to a service-linked role |
| `not_principal/names_the_account_and_the_caller` | "The NotPrincipal element uses "Effect":"Deny" to deny access to all principals except the principal specified in the NotPrincipal element." ([NotPrincipal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html)) | denies kwong although the element names kwong and kwong's account, as AWS recommends |
| `list_all_my_buckets/allowed_on_every_bucket_arn` | "The AllowS3ListRead statement in this policy allows Carlos to view a list of all of the buckets in the account." That statement allows `s3:ListAllMyBuckets` on `arn:aws:s3:::*`. ([evaluation example](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html#reference_policies_evaluation-logic_policies_evaluation_example)) | denies, because it matches the request as `*` |

- **Recommendation for the first four rows:** no change. The analyzer already does what AWS
  documents, and the fixtures keep the evidence.
- **`ListAllMyBuckets` (review open question 3):** both sides deny, but that's not agreement. The
  analyzer's answer also contradicts AWS's example. Options:
  - **(a)** Keep it.
  - **(b)** Match a request on `*`, for an action with no resource type, against patterns like
    `arn:aws:s3:::*`. That needs the Service Authorization Reference's list of such actions.
  - **(c)** Refuse a request on `*` whose answer depends on a statement with a resource ARN.

  **Recommendation: (c),** until there's a way to check how real requests match. Code:
  `evaluator.statement_matches` and `_applies`.

### 5. Refusals that AWS answered (27 cases)
Each row is a case the analyzer refuses because AWS's docs don't settle it, and what the
simulator answered.

| Refusal | Cases | The simulator | Recommendation | Code |
|---|---|---|---|---|
| A policy variable with no value | 2 | It matches nothing: a Deny with `NotResource` applied, and an Allow didn't | Adopt "matches nothing". The "Policy variables with no value" section says the same | `variables._value` |
| A variable from a multivalued key | 2 | Neither value was used | Keep refusing: the probes only covered an Allow | `variables._value` |
| A `*` in a variable's value or default | 2 | A literal `*` | Adopt: a filled-in value is plain text | `variables._value`, `variables.parse` |
| A policy variable in a `Bool` value | 2 | Not filled in, so the condition fails. AWS accepts the policy | Adopt the policy variables page: the text stays as written | `conditions.check` |
| A date with no time or no zone | 5 | `2026-08-15` is midnight UTC, a time with no zone is UTC, and `2026` is epoch seconds | Adopt for those forms. Keep refusing the unprobed forms, such as `2026-08` and `2026-08-15T07:30` | `conditions._date` |
| A bare IPv6 address; a range with host bits set | 2 | Not /32, consistent with /128; the host bits are masked | Adopt masking. Probe a bare IPv6 address against itself before adopting /128 | `conditions._network` |
| An ARN operator value with fewer than six fields | 2 | AWS rejects the simulation (`InvalidInput`), though `GetContextKeysForCustomPolicy` accepts the policy | Keep refusing: AWS can't evaluate it either | none |
| Several request values with no set operator | 2 | IMPLICIT_DENY for both `StringEquals` and `StringNotEquals` | Keep refusing: this fits ForAllValues and also never matching. A follow-up probe tells them apart | `conditions.holds` |
| A request whose only value is `""` | 2 | It counts as a value under `ForAnyValue`, and as present under `Null` | Adopt. Only `ForAllValues` treats `""` as a null dataset, as AWS documents | `conditions.holds` |
| `ForAnyValue…IfExists` on a missing key | 1 | ForAnyValue wins: the condition fails | Adopt | `conditions._missing` |
| A set operator on `Null` | 1 | Accepted. With the key present, `Null` false held | Keep refusing: one probe can't show what the set operator does | `conditions.parse_operator` |
| A role ARN that matches the caller only if case is ignored | 1 | Case matters | Keep refusing: a saved policy turns a role ARN into the role's unique ID, which the simulator can't do for an example role | `principals._match` |
| `NotPrincipal` | 3 | Always EXPLICIT_DENY | Keep refusing: the simulator's `NotPrincipal` answers contradict AWS's docs (simulator limits) | `loader._principals` |

AWS's NotPrincipal page also warns that "The `NotPrincipal` element with a `Deny` effect will always
deny any IAM principal that has a permissions boundary policy attached, regardless of the values
specified in the `NotPrincipal` element". That belongs in phase 6's list of findings.

## Follow-up probes
None of these has been run. Each one needs another call to AWS.
- **The account as principal, with no identity policy that allows the read.** Decides difference 2.
- **A `*` that would have to run from the region field into the account field**, such as
  `arn:aws:sqs:us-*-alerts` against a full queue ARN. Shows whether wildcards cross colons only in
  the resource part (difference 1).
- **A bare IPv6 address against itself**, to settle /128.
- **`StringNotEquals` on `aws:TagKeys` with [grade, other]**, which tells ForAllValues apart from
  never matching.
- **A month-only date (`2026-08`), and a time without seconds.**

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
