# Review: policy evaluation vs AWS documentation

Reviewed on 2026-10-21 against commit `e10119a` ("Add service control policy (SCP) support"). Line
numbers refer to that commit.

## Scope and method
- **Files:** `src/iam_analyzer/evaluator.py`, `account.py` and `organization.py`, plus the code they
  call: `matching.py`, `loader.py`, `models.py`, `_validation.py` and `cli.py`.
- **Checked against:** AWS's documentation on policy evaluation logic, permissions boundaries and
  service control policies, read from the live pages on 2026-10-21.
- **Areas:** identity policy evaluation, NotAction/NotResource, group inheritance, permissions
  boundaries, and SCPs, including the management account exemption.
- **Confirmation:** every difference below was reproduced by running the code. The review changed
  no code.

## Severity scale
- **Critical:** a wrong allow/deny decision for a common, realistic configuration.
- **High:** a wrong decision for a realistic but less common configuration, or an AWS rule in a
  supported area that is missing entirely and changes decisions.
- **Medium:** a wrong decision only in edge cases, or a correct decision blamed on the wrong layer
  or statement in a way that would mislead a report.
- **Low:** accepting input AWS would reject without a wrong decision in practice, cosmetic
  differences in the explanation, or very rare cases.

**Direction:** *over* means the tool says allowed where AWS denies; *under* means the tool says
denied where AWS allows.

## Summary
The decision engine itself matches AWS:
- A Deny anywhere wins.
- Every layer must allow: identity policies, the boundary, and each SCP level from the root down.
- NotAction/NotResource, group inheritance, boundaries and the management account exemption all
  behave as AWS documents.

The differences are elsewhere:
- How resource patterns are matched (F1, F3, F6).
- One missing SCP exemption (F2).
- Input checks (F4, F5, F7).

F1, F3 and F4 also break the project's own rule of refusing rather than guessing. Like a skipped
`Condition`, these inputs get a silent, wrong answer instead of an error.

| # | Severity | Direction | Difference from AWS | Where |
|---|---|---|---|---|
| F1 | Critical | both | Policy variables like `${aws:username}` are matched as literal text | `matching.py`, `loader.py` |
| F2 | High | under | SCPs are applied to service-linked roles | `organization.py`, `account.py` |
| F3 | Medium | both | Incomplete ARNs (`arn:aws:s3`) aren't completed with wildcards | `matching.py` |
| F4 | Low | both | Duplicate JSON keys are silently dropped (last one wins) | all three loaders |
| F5 | Low | over | CLI accepts a wildcard `--action`; a second `--boundary` silently replaces the first | `cli.py` |
| F6 | Low | both | `*` and `?` match across `:` anywhere; AWS limits them to one ARN segment | `matching.py` |
| F7 | Low | mostly none | Policy-document rules AWS enforces aren't checked | `loader.py` and the file loaders |

## Findings

### F1. Policy variables are treated as literal text (Critical)

**AWS:**
- With `"Version": "2012-10-17"`, AWS replaces `${aws:username}` and similar variables with values
  from the request before matching. Without that Version, they are literal text.
- `${*}`, `${?}` and `${$}` stand for a literal `*`, `?` and `$`.
- Variables work in boundaries and SCPs too.
- Source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html

**Why it's common:**
- AWS's own managed policy `IAMUserChangePassword` uses `arn:aws:iam::*:user/${aws:username}`.
- Per-user S3 home folders use `home/${aws:username}/*`.

**Code:**
- `matching.py:20-26` escapes `$`, `{` and `}`, so the pattern only matches those exact characters.
- `loader.py:40-52` never reads `Version`.
- Nothing rejects variables. All three layers share this matcher.

**Effect:**
- An Allow with a variable never matches (under-reports).
- A Deny with a variable in `Resource` never matches (over-reports).
- For roles, `aws:username` has no value, so AWS matches nothing. Today's literal handling happens
  to agree.

**Test** (`tests/test_cli.py`; add `import json`):
```python
def test_aws_username_is_replaced_by_the_callers_name(capsys, tmp_path):
    own_password = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "iam:ChangePassword",
        "Resource": "arn:aws:iam::*:user/${aws:username}"}]}
    path = tmp_path / "acct.json"
    path.write_text(json.dumps({"Policies": {"ChangeOwnPassword": own_password},
                                "Users": {"jsmith": {"Policies": ["ChangeOwnPassword"]}}}))
    code, _, _ = run(capsys, "--account", str(path), "--principal", "user/jsmith",
                     "--action", "iam:ChangePassword",
                     "--resource", "arn:aws:iam::111122223333:user/jsmith")
    assert code == EXIT_ALLOWED  # today: EXIT_DENIED (IMPLICIT_DENY)
```

**Deny variant:**
- Setup: user `alee` has Allow `*` plus Deny `iam:DeleteUser` on
  `arn:aws:iam::*:user/${aws:username}`.
- Request: `iam:DeleteUser` on `user/alee`.
- AWS: EXPLICIT_DENY. Today: **ALLOW**.

### F2. SCPs are applied to service-linked roles (High)

**AWS:** "SCPs do not affect any service-linked role." The only principals SCPs don't reach are
those in the management account and service-linked roles. Sources:
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-reqcontext.html

**Code:**
- `organization.py:62-63` exempts only the management account.
- `Role` (`account.py:51-54`) has no path or "service-linked" marker, so a role can't be described
  as one.
- `README.md:29-30` already notes this, but nothing warns at runtime.

**Severity:** High under the scale above, because an AWS rule is missing from a supported area. In
practice it bites once real service-linked roles arrive, for example through the planned importer.

**Test** (`tests/test_cli.py`). The role is named by AWS convention for now; a fix would also set
whatever marker it adds, such as the `/aws-service-role/` path.
```python
def test_scps_do_not_apply_to_service_linked_roles(capsys, tmp_path):
    path = tmp_path / "acct.json"
    path.write_text(json.dumps({
        "AccountId": "111122223333",
        "Policies": {"SupportPermissions": {"Statement": [
            {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}},
        "Roles": {"AWSServiceRoleForSupport": {"Policies": ["SupportPermissions"]}}}))
    code, _, _ = run(capsys, "--account", str(path), "--org", ORG,
                     "--principal", "role/AWSServiceRoleForSupport",
                     "--action", "ec2:DescribeInstances", "--resource", "*")
    assert code == EXIT_ALLOWED  # today: EXIT_DENIED ("No SCP attached to OU Schools allows this.")
```

### F3. Incomplete ARNs aren't completed (Medium)

**AWS:** "When you specify an incomplete ARN (one with fewer than the standard six fields) in an
identity-based policy, AWS automatically completes the ARN by adding wildcard characters (*) to all
missing fields." For example, `arn:aws:sqs` means `arn:aws:sqs:*:*:*`. Sources:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html

**Code:** `matching.py:31-33` matches the pattern exactly as written.

**Test:** `tests/scenarios/incomplete_arn_is_completed_with_wildcards.json`
```json
{
  "description": "AWS completes \"arn:aws:s3\" to \"arn:aws:s3:*:*:*\", so this Deny covers every S3 object.",
  "policies": {
    "admin.json": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    "no_s3.json": {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3"}]}
  },
  "request": {"action": "s3:GetObject", "resource": "arn:aws:s3:::district-student-records/2026/roster.csv"},
  "expected": "EXPLICIT_DENY"
}
```
- Today this returns **ALLOW**.
- The mirror case: Allow `sqs:SendMessage` on `arn:aws:sqs`, asking about a real queue ARN. AWS:
  ALLOW. Today: IMPLICIT_DENY.

### F4. Duplicate JSON keys are silently dropped (Low)

**AWS:** "Individual elements must not contain multiple instances of the same key." Source: the
policy grammar page above.

**Code:**
- `json.loads` (`loader.py:34`, `account.py:104`, `organization.py:71`) keeps only the last copy.
- The "appears more than once" check (`organization.py:97-101`) can't see two copies of an account
  under the same parent.

**Test** (`tests/test_loader.py`):
```python
def test_duplicate_key_in_a_statement_is_rejected():
    text = '{"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Effect": "Allow"}]}'
    with pytest.raises(PolicyParseError, match="Effect"):
        load_policy(text, name="p")  # today: loads as an Allow
```
- Org variant: list one account twice under Root, with the first copy carrying a Deny-all SCP.
- Today the file loads, the Deny disappears, and requests are allowed.

### F5. CLI input gaps (Low, `cli.py`)
`IT_ADMIN`, `NO_DELETE`, `VENDOR_BOUNDARY` and `ROSTER` are the constants in `tests/test_cli.py`.

**Wildcard action:**
- AWS requests name one concrete action, but `--action 's3:*'` is accepted.
- The policy wildcard then matches the literal `*`.
- `--policy IT_ADMIN --policy NO_DELETE --action 's3:*' --resource ROSTER` gives **ALLOW**, even
  though `s3:DeleteObject` on that object is an EXPLICIT_DENY.
- Test: assert `EXIT_INPUT_ERROR`.

**Two `--boundary` flags:**
- AWS allows exactly one boundary, but argparse keeps only the last flag.
- `--boundary VENDOR_BOUNDARY --boundary IT_ADMIN` evaluates as if only `IT_ADMIN` were the
  boundary, and gives ALLOW.
- Test: expect a usage error (`SystemExit` code 2).

### F6. Wildcards cross ARN segment boundaries (Low)

**AWS:** wildcards work "within the individual segments of an ARN (the parts separated by colons)".
Only a `*` that is "the last character of a resource ARN segment ... can expand to match beyond the
colon boundaries". Source:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html

**Code:** `matching.py:21-24` turns the whole ARN into one regex, so every `*` and `?` can cross
`:`.

**Test** (`tests/test_matching.py`):
```python
def test_star_inside_a_segment_does_not_cross_colons():
    pattern = "arn:aws:lambda:us-east-1:111122223333:function:*-prod"
    assert not match_resource(pattern, "arn:aws:lambda:us-east-1:111122223333:function:billing:canary-prod")  # today: matches
    assert match_resource(pattern, "arn:aws:lambda:us-east-1:111122223333:function:billing-prod")
```
- Also, `arn:aws:s3:::b?c` matches `arn:aws:s3:::b:c` today.
- The docs imply this rule rather than state it outright (see open question 1).

### F7. Policy-document rules that aren't checked (Low)

**What isn't checked:**
- `Version` values.
- `"Statement": []`, which AWS rejects. As a boundary or SCP it denies everything.
- Unknown top-level keys, such as the typo `"Statment"`.
- `Id` in identity policies.
- Sid characters and uniqueness.
- Actions without a `service:` prefix. For example, `s3*` also matches `s3control:` actions.
- AWS quotas: groups per user, SCPs per target, OU depth.

**Cosmetic:** `Principal` in an SCP is reported as "not supported yet", but AWS never allows it
there.

**Test:** add rows to `test_invalid_policies` in `tests/test_loader.py`, with
`READ = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}`:
```python
({"Version": "2012-10-18", "Statement": [READ]}, "'Version'"),
({"Version": "2012-10-17", "Statement": []}, "'Statement'"),
({"Version": "2012-10-17", "Statement": [{**READ, "Action": "s3*"}]}, "'Action'"),
```

## Checked and matches AWS
- **Decision order:** explicit deny, then allow, then implicit deny, in any statement or policy
  order and across all layers.
- **Actions:** matched case-insensitively; `*` and `?` work anywhere in the action.
- **Resources:**
  - Matched case-sensitively; `*` spans `/`.
  - `[` and `]` are literal; the matcher doesn't use fnmatch.
- **Effect:** case-sensitive and required.
- **Element shapes:** a single value or a list both work. Exactly one of Action/NotAction and one of
  Resource/NotResource is required.
- **NotAction/NotResource:**
  - Negation covers the whole list.
  - Allow+NotAction stays limited to its `Resource`.
  - Deny+NotResource and the combined form match AWS's examples.
- **Groups:**
  - Users inherit every group's policies, and a Deny in a group policy applies to the user.
  - Nested groups, roles in groups and group boundaries are all rejected, as in AWS.
- **Boundaries:**
  - Only users and roles can have one.
  - The boundary intersects with all identity policies, including group policies.
  - A boundary never grants on its own, and a Deny in it is an explicit deny.
- **SCPs:**
  - Every level needs an Allow, so FullAWSAccess at the root doesn't satisfy an OU allow-list.
  - Any SCP at a level can provide the Allow.
  - A Deny at any level wins, and SCPs never grant.
  - Every root, OU and account must have at least one SCP, as in AWS.
  - All seven worked examples on AWS's SCP evaluation page reproduce.
- **SCP scope:**
  - The management account is exempt even inside an OU with a Deny.
  - Delegated-admin accounts are correctly not exempt.
  - An account in two parents is rejected.
  - A missing account or `AccountId` is an input error (exit 2).
- **2025 SCP syntax:** SCPs now use the full IAM policy language (NotAction in Allow, resource ARNs,
  NotResource), and all of it loads and evaluates correctly.

## Open questions
Settling these needs AWS access: the IAM policy simulator, or test SCPs in a sandbox organization.
1. **Wildcards and colons (F6):** can a `*` in the middle of an ARN segment, or a `?`, ever match
   `:`? `aws iam simulate-custom-policy` would settle it.
2. **SCP syntax page:** it still says SCP Allow statements may only use `"*"` in `Resource`. That
   contradicts AWS's September 2025 announcement that SCPs support the full IAM policy language
   (https://aws.amazon.com/about-aws/whats-new/2025/09/aws-organizations-iam-language-service-control-policies/).
   The code follows the announcement.
3. **Actions with no resource type, like `s3:ListAllMyBuckets`:** AWS's examples grant it with
   `arn:aws:s3:::*`. The tool says ALLOW or IMPLICIT_DENY depending on whether you pass that or `*`
   as the resource.

Two narrower questions only matter when fixing F1 and F3:
- **Variables with no value (F1):** AWS's docs say both that this "might cause the entire statement
  to be invalid" and that it "will not match any resource". This decides how a fix treats roles,
  which have no `aws:username`.
- **Incomplete ARNs in SCPs (F3):** the completion rule is documented only for identity-based
  policies.

## Known roadmap gaps
Not counted as findings.
- **Condition:** rejected.
- **Resource-based policies:** not evaluated. This includes the rule that a boundary's implicit deny
  doesn't limit a resource policy that names an IAM user ARN.
- **Not modeled yet:**
  - Session policies.
  - RCPs.
  - The root user. SCPs do apply to it in member accounts.
  - Cross-account requests.
  - Requests that cover several resources at once.
