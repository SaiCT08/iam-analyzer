# Design decisions

This page records the rules the analyzer follows where AWS's documentation leaves room for a
choice, and the evidence behind each one. The code, the tests and the README point here for them.
- [AWS doc findings](aws-doc-findings.md) lists the places where AWS's documentation contradicts
  itself or doesn't match what AWS's IAM policy simulator did.
- [Checking the analyzer against AWS's IAM policy simulator](simulator-check.md) has every case
  recorded from the simulator, with AWS's answer. The fixtures named below, such as
  `ip_ranges/bare_ipv6_address`, are in [`tests/simulator_fixtures`](../tests/simulator_fixtures).

AWS quotes were checked against the live pages on 2026-11-12.

## Principles

### Refuse rather than guess
When the analyzer can't evaluate something the way AWS would, it refuses
(`UnsupportedPolicyFeature`, exit code 2) and says why, instead of answering. A skipped Deny would
report access AWS denies, and a skipped Allow would hide access AWS grants.
[Every refusal](#every-refusal) lists them.

### Which evidence settles a question
- Where AWS's documentation clearly settles a question, the analyzer follows it, even when AWS's
  IAM policy simulator disagrees. Those cases are the
  [simulator limits](aws-doc-findings.md#simulator-limits-not-doc-problems).
- Where the documentation contradicts itself or doesn't say, the analyzer refuses, unless the rest
  of the documentation clearly settles it, or a recorded simulator answer does. Each judgment call
  below names its evidence: AWS's words, or the fixtures.
- A rule that draws a line between two places that behave differently, such as `Resource` and
  `ArnLike`, rests on recorded simulator answers for both sides, not on a doc sentence for one side
  and a guess for the other.

### Unknown is not empty
A fact the input doesn't state is unknown, not empty, and the analyzer stops and asks instead of
assuming one:
- a condition key nobody gave a value or marked absent (see
  [The request context](#the-request-context));
- a resource nobody described, since its ARN doesn't say whether it has a resource-based policy or
  which account it's in (see [Resources](#resources));
- whether SCPs apply: `iam-analyzer report` needs `--org` or `--no-org`, and `Account.evaluate`'s
  `organization` argument has no default.

### When unsure whether a value can happen, try it
When it's unclear whether a request can carry a condition key's value, a report tries that value
anyway. An impossible value can only add a false alarm, while skipping a possible one could hide
real access. [MFA and roles](#mfa-and-roles) is the main case.

### Which way a wrong answer errs
For a tool that finds who can get in, missing an Allow is the unsafe direction: it says someone
can't get in when AWS would let them. Missing a Deny over-reports access, which is also wrong but
errs on the safe side.

### Where the rules live
AWS's rules live in the engine, `src/iam_analyzer`. `cli.py` only parses arguments and prints
results, so every other caller, such as a compliance report, gets the same rules. Where data came
from stays in typed fields, such as `via_group` on a policy and `layer`, `index` and
`principal_match` on a matched statement, and becomes text only when it's printed. Reports group
results by source without parsing strings.

## The request context
A request carries condition keys, such as `aws:SourceIp` or `aws:username`. Each key has values, is
absent (the request doesn't include it), or is unknown (nobody said). AWS's rules for a missing key
apply to an absent key. When a statement that matches the request needs an unknown key, the
analyzer stops and names every such key, so a forgotten `--context` can't quietly turn a Deny off.

- **What an account file fills in:** `aws:username`, `aws:PrincipalType`, `aws:PrincipalArn`,
  `aws:PrincipalAccount` and `aws:PrincipalTag/*` for the principal. A request can't change them.
- **A role's tags are unknown** until they're given, or the session is known to carry no session
  tags, because session tags can override a role's own tags and add new ones. A session tag can't
  remove a role's tag, so a role's own tag can't be made absent.
- **When a trust policy rules session tags out.** Passing session tags needs `sts:TagSession` in the
  trust policy: "For roles without this permission in the trust policy, the AssumeRole operation
  fails" ([session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)).
  But a chained session "inherits any transitive session tags from the calling session"
  ([AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)), and no
  page says whether that needs `sts:TagSession` too. So a role's own tags count as complete only
  when no Allow in its trust policy covers `sts:TagSession`, and every Allow for an assume action
  names only IAM users or SAML or OIDC providers, which start a session without a calling session
  (`resources.session_tags_possible`).
- **Dates in the request** are read the way AWS reads dates in a policy (see [Dates](#dates)). The
  request context is the analyzer's own input, so this is a choice of format, not a reading of
  AWS's rules.
- **One action per request.** A request names one concrete action, with a service prefix and no
  wildcard, as a real AWS request does.

## Policy variables
AWS fills in policy variables such as `${aws:username}` only in a policy with
`"Version": "2012-10-17"`. Without it, `${...}` is plain text, and the analyzer treats it the same
way. A variable may only appear in the resource part of an ARN, after the fifth colon, as AWS
requires, and `${*}`, `${?}` and `${$}` stand for a literal `*`, `?` and `$`.

- **A variable with no value matches nothing.** Its key is absent and it has no default, as
  `${aws:username}` has for a role. In `Resource`, the pattern covers no resource. In
  `NotResource`, it excludes nothing, so a Deny with it applies. In a condition value,
  `StringEquals` and `StringLike` fail while `StringNotEquals` and `StringNotLike` hold, and the ARN
  operators work the same way.
  - Evidence: the [policy variables](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html)
    page says "the resource that includes a policy variable with no value will not match any
    resource", and "Inverted condition operators like StringNotEquals or StringNotLike do match
    against a null value". The simulator agreed (`variables_without_a_value/*`).
  - The same page's note that such a variable "might cause the entire statement to be invalid"
    isn't followed: in the simulator, a `NotResource` Deny with one applied
    (`variables_without_a_value/deny_not_resource`).
- **A variable whose key has several values matches nothing too,** in `Resource`, `NotResource` and
  condition values (`variables_with_several_values/*`). AWS says "You can't use a multivalued
  condition key as a variable", but not what happens if one is used. With a default, such a
  variable is refused: nothing probed it, and AWS may treat several values as no value, which would
  use the default.
- **A `*` or `?` filled in from a value or a default is a literal character,** in `Resource` and in
  condition values (`variables_with_wildcards/*`).
- **In a `Bool` value, a variable isn't filled in.** The value stays as written, so it matches
  nothing (`bool_with_a_variable/*`). The policy variables page says variables can't be used with
  Boolean operators, while the condition operators page says they can; the simulator sided with the
  first.
- **Judgment call: ARN operator values follow the String ones,** although only String values were
  probed. AWS fills variables into both the same way, and the String probes behaved exactly as
  `Resource` did.

## Resource patterns and ARNs
- **`Resource` and `NotResource` are a plain glob over the whole ARN.** `*` and `?` match any
  characters, colons included, in any of the ARN's fields. The
  [Resource element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html#reference_policies_elements_resource_wildcards)
  page says to use wildcards "within the individual segments of an ARN (the parts separated by
  colons)", which implies they stay inside a segment but doesn't say so, and the simulator let them
  cross colons:
  - a `*` in the middle of the resource part (`wildcards_and_colons/lambda_alias_mid_segment_star`,
    `s3_key_colon_mid_segment_star`, and the Deny `s3_key_colon_mid_segment_star_deny`);
  - a `?` (`s3_key_colon_question_mark`);
  - a `*` or a `?` in the middle of the region field (`mid_field_star_crossing_a_colon`,
    `mid_field_question_mark_crossing_a_colon`, each with a control that needs no crossing).

  A `*` that ends a field still runs on into the next, as AWS documents: "If the * wildcard is the
  last character of a resource ARN segment, it can expand to match beyond the colon boundaries"
  (`star_ending_the_region_field`). An earlier version of the analyzer kept wildcards inside a
  segment, following the page's implication; the simulator showed that missed Allows.
- **The ARN condition operators compare six fields.** `ArnLike` and the other ARN operators split an
  ARN at its first five colons and match the six fields one by one, each as a plain glob, so only
  the resource part can match a colon. The
  [condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_ARN)
  page says "Each of the six colon-delimited components of the ARN is checked separately", and the
  simulator agreed. The pattern that matched in `Resource` by running a `*` from the region field
  into the account field didn't match in `ArnLike` (`arn_like_star_ending_the_region_field`), while
  its control, whose fields line up, did. In the resource part, a `*` or a `?` matches a colon
  (`arn_like_mid_segment_star`, `arn_like_question_mark`, `arn_like_s3_key_colon_star`).
  - `ArnEquals` takes wildcards too: "The ArnEquals and ArnLike condition operators behave
    identically."
  - An ARN operator value with fewer than six fields is refused. AWS doesn't say how one matches,
    and the simulator rejected the call (`short_arns_in_arn_operators/*`).
- **Short ARNs.** AWS completes "an incomplete ARN (one with fewer than the standard six fields) in an
  identity-based policy" with `*` fields
  ([ARNs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html#arns-paths-wildcards)),
  so `arn:aws:s3` means `arn:aws:s3:*:*:*` in identity policies and permissions boundaries. In an
  SCP or a resource-based policy, where nothing documents it, a short ARN in `Resource` or
  `NotResource` is refused. The simulator can't settle it: it doesn't complete short ARNs anywhere,
  not even where AWS documents that it should (`scenarios/incomplete_arn_*`).
- **Case.** Actions match case-insensitively, and resources case-sensitively.
- **A request on `"*"`** is covered by a statement whose `Resource` is `"*"`, and not by one that
  names resource ARNs. For an action with no resource type, the
  [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html#actions_table)
  says "If the column is empty, then the action does not support resource-level permissions and
  you must specify all resources ("*") in your policy", and "If you specify a resource that is not
  valid for the action, any request to use that action fails, and the statement's Effect does not
  apply".
- **Judgment call: `s3:ListAllMyBuckets` on `"*"` is matched as `arn:aws:s3:::`,** a bucket ARN with
  an empty name. A statement covers it when its `Resource` covers every bucket, as `"*"` and
  `arn:aws:s3:::*` do, and not when it names a bucket or needs characters in the name.
  - Evidence: in AWS's
    [evaluation example](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html#reference_policies_evaluation-logic_policies_evaluation_example),
    "The AllowS3ListRead statement in this policy allows Carlos to view a list of all of the
    buckets in the account". That statement is an Allow on `arn:aws:s3:::*`. The same policy's
    `DenyS3Logs` statement, `s3:*` on `arn:aws:s3:::*log*`, "denies Carlos access to any S3 bucket
    with log in its name", and doesn't stop the listing.
  - The simulator denied the listing (`list_all_my_buckets/allowed_on_every_bucket_arn`), but it
    only compared the patterns with the `*` it was sent, which says nothing about the resource a
    real request carries. The request is read in the `aws` partition, which account files already
    assume for every principal.

## Conditions
The analyzer supports every condition operator AWS documents, with `...IfExists` and the
`ForAllValues` and `ForAnyValue` set operators. Operator names must be spelled exactly as AWS
documents them (the simulator rejected a lowercase one too, `operator_name_case/*`), and `IfExists`
isn't allowed on `Null`, as AWS says.

- **A refused condition only matters when every other condition holds.** One condition that fails
  is enough for the statement not to apply, whatever AWS would do with the refused one.
- **Set operators work with every operator family,** not only the String, Bool and ARN ones the
  examples show, since AWS defines `ForAllValues` and `ForAnyValue` for whatever operator follows
  them. The simulator agreed for a Numeric operator
  (`set_operators_on_numbers/for_any_value_numeric_less_than`).
- **A missing key with a set operator:** `ForAllValues` holds and `ForAnyValue` fails, whatever the
  operator.
  - `ForAnyValue` wins over `IfExists`. Their definitions give opposite answers for a missing key,
    and the simulator's condition failed (`for_any_value_if_exists/key_absent`).
  - Set operators load on `Null` and apply as they do on other operators. On a missing key,
    `ForAllValues:Null` false held and `ForAnyValue:Null` true failed. With the key present,
    `Null`'s own answer stands (`set_operator_on_null/*`).
- **Several request values and no set operator.** AWS says such keys need `ForAllValues` or
  `ForAnyValue`, but not what happens without one. `StringEquals` and `StringNotEquals` never hold
  then, even when no request value is one of `StringNotEquals`'s
  (`several_values_without_a_set_operator/*`). Their `IfExists` forms follow them, by AWS's
  definition of `IfExists`: "If the condition key is present in the context of the request, process
  the key as specified in the policy." Every other operator is refused.
- **An empty value.** A request whose only value is `""` has a value under `ForAnyValue` and `Null`
  (`empty_values/*`). Only `ForAllValues` treats it as having none, as AWS documents. Where those two
  rules meet, in `ForAllValues:Null` with `"true"`, the analyzer refuses.
- **Judgment call: `ForAllValues:StringNotLike` follows its definitions,** not the evaluation table
  under AWS's `aws:ResourceOrgPaths` example, whose three rows say the opposite. The example's own
  description, a policy that "denies access to Amazon S3 actions unless the resource being accessed
  is in a specific set of organizational units", only works with the definitions, and the simulator
  agreed (`for_all_values_string_not_like/*`). `tests/test_conditions.py` turns the table's rows
  into tests that expect the definitions' results.

### Dates
A date value is ISO 8601, such as `2026-08-15T07:30:00Z`, or epoch seconds. AWS asks for "one of
the W3C implementations of the ISO 8601 date formats or in epoch (UNIX) time", but doesn't say which
moment a value with no time zone stands for. The simulator answered for these forms, each probed
just before and just after its moment (`dates_without_a_time_zone/*`):
- a month, `2026-08`, is midnight UTC on its first day;
- a day, `2026-08-15`, is midnight UTC;
- a day and a time with no zone, to the minute or the second (`2026-08-15T07:30`,
  `2026-08-15T07:30:00`), is UTC;
- a number is epoch seconds, four digits included, so `2026` is a moment in 1970, not the year
  (`four_digits`).

The one other form with no time zone, a time with fractions of a second, wasn't probed, and is
refused.

### IP addresses
- A bare address is just that address: `/32` for IPv4 and `/128` for IPv6. AWS says "IAM uses the
  default prefix value of /32", which only makes sense for IPv4, since a /32 in IPv6 covers 2^96
  addresses. The simulator used /128 (`ip_ranges/bare_ipv6_address`,
  `ip_ranges/bare_ipv6_address_itself`).
- A range with host bits set, such as `203.0.113.5/24`, means `203.0.113.0/24`
  (`ip_ranges/range_with_host_bits`).

## Resources
AWS also consults a policy on the resource a request is on, and a resource's ARN doesn't say
whether it has one, or which account it's in: an S3 ARN names no account at all. So every request on
a specific resource needs that resource described, and without a description the analyzer stops
(`MissingResourceError`). For an S3 object, that's its bucket, whose policy covers its objects.

- **No description needed** for `"*"`, IAM resources and STS resources. AWS says "The IAM
  resource-based policy type is a role trust policy"
  ([Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)),
  and a role's trust policy goes on the role itself. Its table of services that work with IAM lists
  STS with no resource-based policies. These ARNs name an account, so a request on one needs
  `aws:PrincipalAccount`.
- **No other exemptions from that table.** It rates services, not ARN namespaces: EC2 says No,
  while VPC, whose resources also have `ec2:` ARNs, says Partial, and it never defines Partial for
  that column.
- **What a description says:** the resource is in the principal's own account, and has the given
  resource-based policy or none.
- **Judgment call: describing a bucket also says its ACLs are disabled** (Object Ownership "Bucket
  owner enforced"), which makes the bucket policy the only resource-based control on its objects.
  The analyzer states this instead of relying on the default, because AWS's pages disagree on what a
  bucket created without the setting gets (see [AWS doc findings](aws-doc-findings.md)). With ACLs
  on, ACL grants can add access and objects can belong to other accounts, and neither is modeled.
- **Refused:**
  - a resource in another account, since cross-account requests also need the other account's
    policies;
  - KMS keys, since every key has a key policy that must allow the request;
  - S3 resources other than buckets and objects, such as access points;
  - resource-based policies of services other than S3 and IAM roles, since AWS says those "may also
    require an explicit Allow statement within the same account"
    ([evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)).

## Bucket policies and the Principal element
Within one account, a bucket policy's Allow can grant a request on its own. Whom its `Principal`
names decides what else must allow. A Deny anywhere still wins, and every SCP level must still
allow.

| The bucket policy's Allow names… | Identity policy also needed? | Boundary must also allow? |
|---|---|---|
| the caller's user ARN | no | no |
| everyone (`"*"`) | no | no |
| the caller's role ARN | no | yes |
| the caller's account | yes | yes |
| no one who matches | yes | yes |

- **The user and role rows are AWS's.** On the
  [evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)
  page, grants to an IAM user ARN "are not limited by an implicit deny in an identity-based policy
  or permissions boundary", and grants to an IAM role ARN "are limited by an implicit deny in a
  permissions boundary or session policy". The simulator didn't limit a grant to a role by the
  role's boundary (`scenarios/bucket_policy_role_grant_is_limited_by_the_boundary`), which is a
  simulator limit.
- **Judgment call: naming the account delegates to the account.** It grants nothing by itself, so an
  identity policy must also allow, and in a Deny it covers everyone in the account. Evidence:
  - the [Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-accounts)
    page: "This delegates authority to the account";
  - the [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
    page's two ways within one account: "Attach a policy to the user that allows the user to call
    AssumeRole (as long as the role's trust policy trusts the account)", or "Add the user as a
    principal directly in the role's trust policy";
  - the [default key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html):
    "the policy statement doesn't give any IAM principal permission", and "it allows the account to
    use IAM policies to delegate".

  The simulator treated naming the account as a grant to everyone in it
  (`star_grant_and_boundary/account_principal`, `account_principal_without_identity_allow`), which
  is a simulator limit.
- **Judgment call: `"*"` is a direct grant, which a boundary doesn't limit.** The Principal page says
  "For IAM users and role principals within your account, no other permissions are required", and
  the evaluation logic page says "Permissions boundaries and session policies do not limit
  permissions granted using the aws:PrincipalArn condition key with a wildcard(*) in the Principal
  element". What kind of grant a statement makes depends on its `Principal`; a condition only
  decides whether the statement applies. The simulator agreed, for a user and for a role
  (`star_grant_and_boundary/star_principal`, `star_principal_role_caller`).
- **Refused, because the account file can't settle them:** a role session's ARN for the caller's
  role (the session's name isn't known), S3 canonical user IDs, IAM unique IDs (which AWS shows for a
  principal that was deleted), and a role ARN that matches the caller's role only if case is
  ignored. AWS says "In a Principal element, the user name part of the Amazon Resource Name (ARN) is
  case sensitive", but says nothing about role names, and the simulator can't settle it for an
  example role (`role_principal_case/role_name_in_lowercase`).
- **`NotPrincipal`** loads in a resource-based policy's Deny, and is refused once its statement's
  action and resource match and its conditions hold. Other requests on the same resource are
  answered as usual. AWS's [NotPrincipal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html)
  page says that, depending on the service, "AWS might validate the account first, then the role,
  and then the assumed-role user", and recommends `aws:PrincipalArn` conditions instead. The
  simulator's answers contradict that page (`not_principal/*`), so they can't settle it either. With
  Allow, `NotPrincipal` is a parse error.
- **Not modeled:** S3 Block Public Access and ACLs.

## Trust policies
- **A trust policy must allow.** AWS: "IAM role trust policies and KMS key policies are exceptions to
  this logic, because they must explicitly allow access for principals" (evaluation logic page).
  When the trust policy trusts the account, an identity policy must allow `sts:AssumeRole` too, as
  the AssumeRole page's two ways within one account show (above).
- **Judgment call: a trust policy has no `Resource`.** The trust policy examples on AWS's role pages
  leave it out, although the Resource page says "Statements must include either a Resource or a
  NotResource element". A trust policy with `Resource`, `NotResource` or `NotPrincipal` is a parse
  error.
- **It covers six STS actions,** the ones whose resource type is `role` in the
  [STS page](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sts.html) of the
  Service Authorization Reference: `AssumeRole`, `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity`,
  `SetContext`, `SetSourceIdentity` and `TagSession`.
- **Refused:**
  - A trust policy that names the caller directly, as a user ARN or `"*"`, when the caller's
    permissions boundary doesn't allow the request. The trust policy page says "If a permissions
    boundary is set for the user, then it must allow the sts:AssumeRole action", while the
    evaluation logic page says a boundary doesn't limit a grant to a user ARN. The simulator can't
    simulate trust policies, so nothing settles it.
  - `sts:AssumeRoleWithSAML` and `sts:AssumeRoleWithWebIdentity`, which SAML and OIDC users call.
    Only IAM users and role sessions are modeled.

## SCPs
- Every level from the organization root down to the account must allow, a Deny at any level wins,
  and SCPs never grant. Any SCP at a level can give that level's Allow. Every root, OU and account
  needs at least one SCP, as in AWS.
- **Exempt:** the management account, and service-linked roles: "SCPs do not affect any
  service-linked role"
  ([SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html#scp-effects-on-permissions)).
  A role is service-linked when its `Path` starts with `/aws-service-role/`. That's the field AWS
  itself returns, so real data can be copied straight across, and a role's name doesn't count. The
  simulator applied SCPs to such a role (`scenarios/scp_skips_service_linked_role`), which is a
  simulator limit.
- **SCP `Allow` statements honor resource ARNs and `NotAction`,** as AWS's September 2025
  announcement says, although the SCP syntax page still says an Allow may only use `"*"` in
  `Resource`. The simulator agreed with the announcement (`scp_allow_statements/*`).
- **An SCP doesn't need a `Version`.** The syntax page says every SCP must include one, but some of
  its own complete examples leave it out.
- **A short ARN in an SCP is refused** (see [Resource patterns and ARNs](#resource-patterns-and-arns)).

## Policy documents
Policies are checked the way AWS checks them when they're saved, and one that AWS would reject is
an input error instead of being evaluated: a repeated JSON key, an unknown `Version`, an unknown
top-level key, `Id` outside a resource-based policy, an empty `Statement`, a `Sid` with characters
other than letters and digits or used twice, or an action without a service prefix. `Principal` and
`NotPrincipal` are only allowed in resource-based policies. AWS's quotas aren't checked.

## What an answer cites
- **`reasons`** lists every statement that matched, from every layer.
- **`grants`** lists the Allows on a way in that works by itself: an identity policy's Allow when the
  boundary, if any, allows too; a resource-based grant to the user or to everyone, or to the role
  when its boundary allows; and a trust policy's Allow, which every way into a role needs. A grant to
  the account only delegates, so it grants nothing itself, and boundary and SCP statements only
  limit, so they never grant. Which layers a grant needs is AWS's rule, so it lives in the engine.
- **`overridden`**, for an explicit Deny, lists the Allows it overrode that would grant the request,
  by the same rules.
- **`without_denies`**, for an explicit Deny, says what the request would get with every Deny taken
  out: allowed, still denied by the layers it names, or can't tell, with the reason.

## Compliance reports
- **A framework is data:** a JSON file of checks, requirements and mappings. Adding one never changes
  the engine, which stays domain-neutral.
- **Results.** `only` and `requires` checks forbid access. They FAIL when any value tried allows the
  request, PASS when every value is denied, and are CAN'T TELL otherwise, so DEPENDS never softens a
  prohibition. `can` checks expect access, and give DEPENDS when the answer depends on a value. A
  question the engine refuses is CAN'T TELL with the engine's reason, never a PASS. A check takes its
  worst item: FAIL, then DEPENDS, then CAN'T TELL, then PASS.
- **The values tried.** A check states only what its question fixes. When a statement needs a key the
  check doesn't give, the report tries every value AWS documents for that key, from a table in the
  engine that quotes AWS's "Availability" line for each (`condition_keys.py`):
  `aws:MultiFactorAuthPresent` true, false and absent, and `aws:SecureTransport` and
  `aws:ViaAWSService` true and false. Any other key has too many values to try, so the item is CAN'T
  TELL until the check gives it one. The alternatives were one fixed context per check, values listed
  by the framework's author, and values worked out from the policies.
- **Outsiders.** When a resource or trust policy lets someone outside the account file do the action,
  such as `"*"`, another account, a service or an identity provider, the check gets a CAN'T TELL entry
  that cites the statement. Conditions aren't read for this, so it never passes on a guess.
- **A `can` PASS is weaker** than an `only` or `requires` PASS. Session policies, resource control
  policies and VPC endpoint policies aren't modeled, and they can only take access away.
- **Exit codes:** `1` for a FAIL or a high or critical finding, `3` when nothing failed but something
  is DEPENDS or CAN'T TELL, `2` for input errors, and `0` otherwise.

### MFA and roles
AWS's [Secure API access with MFA](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html)
page says a role's own requests carry no MFA information:
- "The temporary credentials returned by AssumeRole do not include MFA information in the context,
  so you cannot check individual API operations for MFA."
- "Once the user has assumed the role, no further MFA checks are made."
- "Although the user can provide MFA information to assume a role, the temporary credentials returned
  by AssumeRole don't include the MFA information."

So AWS checks MFA for a role when the role is assumed.

- **Judgment call: `true` is still tried for a role's own requests.** If those quotes describe real
  role sessions, `true` can't happen, and trying it can only add a false alarm. If they don't,
  skipping it could let a check that forbids access PASS when it should FAIL, for a role whose own
  policy grants access only with MFA. A false alarm is the cheaper mistake.
- **A second question for roles.** In a `requires` check on a key AWS checks when a role is assumed,
  a role allowed without the key passes only if no one in the account file can do `sts:AssumeRole`
  on it with the key's other values (MFA false or absent), and no one outside the file is trusted.
  If someone in the file can, the item fails and names who. The key's entry in `condition_keys.py`
  carries AWS's quote and link, so the report doesn't name MFA itself.
- **Judgment call: SAML and OIDC users count as outsiders here,** not only `sts:AssumeRole` callers,
  since for them "AWS cannot determine whether that provider required MFA". A role they can assume
  is CAN'T TELL, never a PASS.
- **Judgment call: the second question goes one level deep.** A role that can assume the role without
  MFA counts, even if it needs MFA to be assumed itself. That can only add a false alarm.
- **MFA conditions belong in users' policies and in trust policies,** not in a role's own policies,
  where a Deny on missing MFA could lock the role out. The district framework's advice and the
  findings' fixes say so.

### Policy findings
- **Severity:** high when the surprise can let in a request the policy's author meant to stop, such as
  a Deny that never applies or an Allow that always applies, and low when it can only stop a request
  the author meant to let in. A high or critical finding fails the report, like a FAIL.
- **Judgment calls for public bucket policies,** which follow S3's
  ["The meaning of public"](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html#access-control-block-public-access-policy-status):
  - S3 names `aws:PrincipalOrgID` only as an example of "An AWS principal, user, role, or service
    principal". So a grant pinned only by another principal key, such as `aws:PrincipalArn`, is still
    reported, and the finding says the page doesn't settle it. Over-reporting is the safe side.
  - Negated operators, `...IfExists`, `ForAllValues` and `Null` hold for requests without the key or
    with other values, so they don't pin a key to fixed values.
  - A `*` in a `StringEquals` value counts as a wildcard: S3 says fixed values have no wildcard, and
    makes no exception for operators that read `*` literally.
- **A date with no time zone** is always low, since which way it errs depends on the author's time
  zone, which the analyzer can't know.
- **Only what the account file says.** A policy variable with no value for some principals is
  reported only for keys the file knows, never for a role's tags while session tags are possible.

### Mapping checks to requirements
A requirement is only a framework, an ID, a short title and a link. The title is at most 60
characters on one line, so it can't hold pasted framework text, and each ID is checked against its
source before it's added:
- FERPA 34 CFR § 99.31(a)(1)(ii), checked against Cornell LII's copy, because eCFR blocks automated
  reads;
- NIST SP 800-53 Rev. 5 controls, checked against NIST SP 800-53B's baseline tables.

CIS recommendations aren't mapped, since their IDs change between benchmark versions and their text
is licensed. TEA requirements wait until one is checked.

## Every refusal
Each of these raises `UnsupportedPolicyFeature`, exit code 2, with its reason. A compliance report
shows it as CAN'T TELL.

| Refused | Why |
|---|---|
| A request on a resource in another account | Cross-account requests also need the other account's policies, which aren't modeled yet |
| `sts:AssumeRoleWithSAML` and `sts:AssumeRoleWithWebIdentity` | SAML and OIDC users call them, and only IAM users and role sessions are modeled |
| A resource-based policy, when the caller's `aws:PrincipalArn` isn't an IAM user or role ARN | The same reason |
| A request on a KMS key | Every key has a key policy that must allow the request, and key policies aren't evaluated |
| An S3 resource other than a bucket or an object, such as an access point | Not supported yet |
| A resource-based policy on anything but an S3 bucket or an IAM role | AWS says other services' policies "may also require an explicit Allow statement within the same account" |
| A role ARN whose name matches a role in the account file only if case is ignored | IAM role names ignore case, and AWS doesn't say whether a role ARN does too |
| In a `Principal`: a session of the caller's role, an S3 canonical user ID, an IAM unique ID, or a role ARN that matches the caller's role only if case is ignored | The account file doesn't record session names, canonical IDs or unique IDs, and AWS doesn't say whether role names in a principal are case sensitive |
| `NotPrincipal`, once its statement applies | AWS says which principals it checks depends on the service |
| A trust policy that names the caller directly, when the caller's boundary doesn't allow the request | AWS's trust policy and evaluation logic pages disagree |
| A short ARN in the `Resource` or `NotResource` of an SCP or a resource-based policy | AWS documents completing one only in identity-based policies |
| An ARN operator value with fewer than six fields | AWS doesn't say how it matches, and the simulator rejected it |
| A time with fractions of a second and no time zone | AWS doesn't say which moment it stands for, and it wasn't probed |
| Several request values for one key, with no set operator, under an operator other than `StringEquals` or `StringNotEquals` | AWS requires a set operator, but doesn't say what happens without one |
| `ForAllValues:Null` with `"true"`, when the request's only value is `""` | ForAllValues's null-dataset rule and Null's "present" disagree |
| A policy variable with a default, whose key has several values | Nothing probed whether the default is used |

The analyzer also stops, with exit code 2, when it needs input it wasn't given: a condition key a
matching statement needs (`MissingContextError`), or a description of the request's resource
(`MissingResourceError`). Those aren't refusals, since giving the input settles them.
