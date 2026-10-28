# iam-analyzer

An AWS IAM effective-permissions analyzer, written in Python. Given a set of policies, it answers
"can this principal perform this action on this resource?" using AWS's policy evaluation logic, and
explains *which statements* produced the answer. It's general-purpose and works with any AWS account.
Texas school districts (TEA/FERPA) are the first showcase use case, so the examples use district
policies. Compliance reports grade an account against a framework's checks, and a framework is a
data file, so new ones need no code (see [Compliance reports](#compliance-reports)).

It works entirely on local policy JSON files. No AWS account or credentials are needed.

## Status

The analyzer currently covers **identity policies**, **permissions boundaries**, **service control
policies (SCPs)**, **S3 bucket policies** and **role trust policies**:
- Allow/Deny statements, where an explicit deny always wins and the default is an implicit deny.
- `*` / `?` wildcards in actions and resources. In a resource ARN they match colons too, as AWS's
  IAM policy simulator does, so `function:*-prod` covers the Lambda alias
  `function:billing:canary-prod`. A short ARN such as `arn:aws:s3` is completed with wildcards
  (`arn:aws:s3:*:*:*`) in identity policies and boundaries, as AWS documents. In an SCP or a bucket
  policy, where AWS doesn't say what happens, a short ARN is refused. The ARN condition operators,
  such as `ArnLike`, compare an ARN's six colon-separated fields one by one instead.
- `NotAction` / `NotResource`, which mean "everything except these". For example, a Deny with
  `NotAction: ["s3:Get*"]` is a read-only guardrail.
- Permissions boundaries. A boundary caps what a user or role can do: a request needs an Allow in
  an identity policy **and** in the boundary, and a Deny in either one wins. A boundary never
  grants access on its own.
- SCPs from AWS Organizations. A request must be allowed at every level from the organization root
  down to the account, and a Deny in any SCP wins. Like boundaries, SCPs never grant access.
- S3 bucket policies, with their `Principal` element. Within one account, a bucket policy can allow
  a request on its own. Who its `Principal` names decides whether the identity policies and the
  boundary must allow too (see [Resource-based policies](#resource-based-policies)).
- Role trust policies, for `sts:AssumeRole` and the other STS actions on a role. A trust policy
  must allow the request, and when it trusts the account, an identity policy must allow it too
  (see [Trust policies](#trust-policies)).
- Policy variables such as `${aws:username}` in `Resource` and `NotResource`, filled in from the
  request context. The analyzer never guesses a value: if a statement needs one that nobody gave,
  it says which.
- `Condition`, with every operator AWS documents, `...IfExists`, `Null`, and the `ForAllValues` /
  `ForAnyValue` set operators.
- Policies are checked the way AWS checks them when they're saved. A policy AWS would reject is
  refused with a clear error instead of being evaluated. Examples: a repeated JSON key, an unknown
  `Version`, a `Sid` with characters other than letters and digits, or an action without a service
  prefix.
- A request on a specific resource needs that resource described: whether it has a resource-based
  policy, and that it's in the principal's own account. The analyzer never assumes either (see
  [Resources](#resources)).
- Compliance reports. `iam-analyzer report` grades an account against a framework's checks:
  PASS, FAIL, DEPENDS or CAN'T TELL, each with the statements behind it. It adds policy findings,
  AWS surprises in the policy text that need no question, and prints Markdown and JSON with exit
  codes for CI. A framework is a data file (see [Compliance reports](#compliance-reports)).

Not supported yet:
- `NotPrincipal` is refused, with a clear error, when its statement applies to the request. Other
  requests on the same resource are answered as usual.
- Resource-based policies other than S3 bucket policies and role trust policies. Another service's
  resource can only be described as having none.
- Cross-account requests, KMS keys, and requests by SAML or OIDC users are refused.

## Setup

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```sh
iam-analyzer check \
  --policy examples/policies/teacher_read_grades.json \
  --policy examples/policies/deny_student_records_delete.json \
  --no-resource-policy \
  --action s3:DeleteObject \
  --resource arn:aws:s3:::district-student-records/2026/roster.csv
```

Output:

```
EXPLICIT_DENY
  Deny   deny_student_records_delete.json  Sid=NoDeleteStudentRecords
```

`--action` names one action, as a real AWS request does. A wildcard such as `s3:*` is an input
error.

`--no-resource-policy` says the bucket is in the same account and has no bucket policy (see
[Resources](#resources)). An S3 ARN doesn't say either, so without the flag the analyzer stops
and asks.

### Permissions boundaries

`--boundary FILE` adds a permissions boundary. Here a gradebook vendor's role has full S3 access,
but its boundary only covers the gradebook app's own bucket, so it can't read student records:

```sh
iam-analyzer check \
  --policy examples/policies/it_admin_full_s3.json \
  --boundary examples/policies/gradebook_vendor_boundary.json \
  --no-resource-policy \
  --action s3:GetObject \
  --resource arn:aws:s3:::district-student-records/2026/roster.csv
```

```
IMPLICIT_DENY
  The permissions boundary does not allow this.
```

When a request is allowed, the output lists the Allow from each layer, and boundary statements are
marked `(permissions boundary)`.

### Asking about a user or role

An account file defines policies once, by name, and attaches them to users, groups and roles. See
[`examples/accounts/district.json`](examples/accounts/district.json) for a full example.

```json
{
  "Policies":  { "TeacherReadGrades": { "Statement": [ ... ] } },
  "Groups":    { "Teachers": { "Policies": ["TeacherReadGrades"] } },
  "Users":     { "jsmith": { "Groups": ["Teachers"], "Policies": [] } },
  "Roles":     { "ITAdmin": { "Policies": ["..."], "PermissionsBoundary": "..." } },
  "Resources": { "arn:aws:s3:::district-student-records": {} }
}
```

Name the principal as `user/NAME` or `role/NAME`:

```sh
iam-analyzer check \
  --account examples/accounts/district.json \
  --principal user/jsmith \
  --action s3:DeleteObject \
  --resource arn:aws:s3:::district-student-records/2026/roster.csv
```

```
EXPLICIT_DENY
  Deny   DenyStudentRecordsDelete (via group Teachers)  Sid=NoDeleteStudentRecords
```

A user gets their own policies plus the policies of every group they're in. As in AWS, roles can't
belong to groups.

Users and roles can name one policy as their `PermissionsBoundary`. The boundary limits every policy
they have, including the ones that come from their groups. As in AWS, groups can't have a boundary.
In the example account, student teacher `dpatel` is in the Teachers group, but a boundary limits
them to campus-01 records.

Users and roles can also have a `Path`, as in AWS, and the default is `/`. AWS creates
service-linked roles for its own services under `/aws-service-role/`, for example
`/aws-service-role/support.amazonaws.com/`. SCPs never apply to those roles, so give a
service-linked role its real path. A role's name alone doesn't make it service-linked.

Users and roles can have `Tags` too, in AWS's own shape. Policies read them as
`aws:PrincipalTag/KEY` (see [Policy variables](#policy-variables-and-the-request-context)). As in
IAM, groups can't be tagged.

```json
"rnguyen": { "Groups": ["Registrars"], "Tags": [{ "Key": "campus", "Value": "campus-02" }] }
```

### Resources

AWS also consults a policy attached to the resource a request is on, such as an S3 bucket policy.
That policy can allow a request the identity policies don't, or deny one they allow. A resource's
ARN doesn't say whether it has such a policy, or which account the resource is in: an S3 ARN names
no account at all. So a request on a specific resource needs the resource *described*, and without
a description the analyzer stops instead of assuming it has none.

In an account file, `Resources` describes resources by ARN. `{}` says the resource is in this
account and has no resource-based policy, and `Policy` gives a bucket its bucket policy (see
[Resource-based policies](#resource-based-policies)):

```json
"Resources": {
  "arn:aws:s3:::district-student-records": { "Policy": { "Statement": [ ... ] } },
  "arn:aws:s3:::district-staff-files": {}
}
```

For an S3 object, describe its bucket: a bucket policy covers the bucket's objects. With
`--policy`, `--resource-policy FILE` gives the request's resource its resource-based policy, and
`--no-resource-policy` says it has none. Either flag also says the resource is in the same account.

Describing a bucket also says its ACLs are disabled, meaning its Object Ownership setting is
"Bucket owner enforced". That has been S3's default for new buckets since April 2023, and it makes
the bucket policy the only resource-based control on the bucket's objects. With ACLs on, ACL grants
can add access, and objects can be owned by other accounts. The analyzer models neither. Check the
setting (`aws s3api get-bucket-ownership-controls`) rather than assume the default: AWS's
create-bucket page also says the AWS CLI creates buckets with ACLs enabled when the setting isn't
given.

Without a description, the check stops:

```sh
iam-analyzer check \
  --account examples/accounts/district.json \
  --principal user/jsmith \
  --action s3:GetObject \
  --resource arn:aws:s3:::district-lesson-plans/week1.pdf
```

```
error: nothing describes arn:aws:s3:::district-lesson-plans: it can have a resource-based policy, and the analyzer can't tell whether it has one, or which account it is in
hint: describe it in the account file's Resources, as {} if it has no resource-based policy
```

Some requests need no description:
- `"*"`, which names no resource, as for `s3:ListAllMyBuckets`.
- IAM and STS resources. AWS says the only IAM resource-based policy is a role's trust policy, and
  STS has none. Their ARNs name an account, so the analyzer needs the principal's account,
  `aws:PrincipalAccount`. With `--account`, the file's `AccountId` fills it in; with `--policy`,
  give it with `--context`.

A request on `"*"` is covered by a statement whose `Resource` is `"*"`, and not by one that names
resource ARNs. For an action with no resource type, the Service Authorization Reference says "you
must specify all resources ("*") in your policy".

`s3:ListAllMyBuckets` is the exception, and AWS's own evaluation example shows how it works:
- an Allow on `arn:aws:s3:::*` lets Carlos list all buckets;
- a Deny on `arn:aws:s3:::*log*`, which denies him "any S3 bucket with `log` in its name", doesn't
  stop that.

So the analyzer matches that request as `arn:aws:s3:::`, a bucket ARN with an empty name. A
statement covers it when its `Resource` covers every bucket, as `"*"` and `arn:aws:s3:::*` do. It
doesn't when its `Resource` names a bucket, or needs characters in the name, as `*log*` does.

The analyzer refuses:
- A request on a resource in another account. Cross-account requests also need the other
  account's policies, which aren't modeled yet.
- Requests on KMS keys, because every key has a key policy that must allow the request.
- S3 resources other than buckets and objects, such as access points.
- Resource-based policies of services other than S3 and IAM roles. AWS says they "may also require
  an explicit Allow statement within the same account", and the analyzer doesn't know which ones
  do.

A role isn't described in `Resources`. Its trust policy goes on the role itself (see
[Trust policies](#trust-policies)).

### Resource-based policies

A bucket policy is evaluated alongside the identity policies. A Deny in either one wins, as
always. Within one account, an Allow in the bucket policy can grant the request even when no
identity policy allows it. Whom the statement's `Principal` names decides what else still has to
allow:

| The bucket policy's Allow names… | Identity policy also needed? | Boundary must also allow? |
|---|---|---|
| the caller's user ARN | no | no |
| everyone (`"*"`) | no | no |
| the caller's role ARN | no | yes |
| the caller's account (`111122223333` or `arn:aws:iam::111122223333:root`) | yes | yes |
| no one who matches | yes | yes |

Naming the account "delegates authority to the account", in AWS's words: the account's own
identity policies decide, as if the bucket policy said nothing. Every SCP level must still allow,
whatever the bucket policy says.

The example account's `district-student-records` bucket policy lets counselor `kwong` read
counseling notes, although `kwong` has no identity policies at all:

```sh
iam-analyzer check \
  --account examples/accounts/district.json \
  --principal user/kwong \
  --action s3:GetObject \
  --resource arn:aws:s3:::district-student-records/counseling/2026/notes.pdf
```

```
ALLOW
  Allow  arn:aws:s3:::district-student-records (resource-based policy, names the user)  Sid=CounselorsReadCounselingNotes
```

The same bucket policy stops everyone but the IT admin role from changing the bucket's policy. It
uses AWS's recommended pattern, a Deny for `"*"` with an `ArnNotEquals` condition on
`aws:PrincipalArn`:

```sh
iam-analyzer check \
  --account examples/accounts/district.json \
  --principal user/alee \
  --action s3:PutBucketPolicy \
  --resource arn:aws:s3:::district-student-records
```

```
EXPLICIT_DENY
  Deny   arn:aws:s3:::district-student-records (resource-based policy, names everyone)  Sid=OnlyITAdminChangesThePolicy
         ArnNotEquals aws:PrincipalArn: arn:aws:iam::111122223333:role/ITAdmin (request: arn:aws:iam::111122223333:user/alee)
```

The analyzer reads the caller from `aws:PrincipalArn`. With `--account`, the file fills it in,
which needs the file's `AccountId`. With `--policy`, give it with `--context`, and give the bucket
policy with `--resource-policy`:

```sh
iam-analyzer check \
  --policy examples/policies/teacher_read_grades.json \
  --resource-policy examples/policies/student_records_bucket_policy.json \
  --context aws:PrincipalArn=arn:aws:iam::111122223333:user/kwong \
  --action s3:GetObject \
  --resource arn:aws:s3:::district-student-records/counseling/2026/notes.pdf
```

```
ALLOW
  Allow  teacher_read_grades.json  Sid=ReadStudentRecords
  Allow  student_records_bucket_policy.json (resource-based policy on arn:aws:s3:::district-student-records, names the user)  Sid=CounselorsReadCounselingNotes
```

`Principal` can name `"*"`, accounts, users, roles, role sessions, federated users, services,
federated identity providers and S3 canonical users, as AWS allows. Services and identity
providers never name an IAM user or role. The analyzer refuses what the account file can't settle:
- a role session's ARN for the caller's role, because the session's name isn't known;
- S3 canonical user IDs, and IAM unique IDs, which AWS shows for a principal that was deleted;
- a role ARN that matches the caller's only if case is ignored, since AWS doesn't say whether role
  names are case sensitive there;
- `NotPrincipal`, when its statement covers the request and its conditions hold. AWS says which
  principals it leaves out depends on the service, and recommends `aws:PrincipalArn` conditions
  instead. A NotPrincipal Deny on one bucket action doesn't stop the analyzer from answering
  others.

Treating `"*"` as a direct grant is a judgment call: AWS says that for "IAM users and role
principals within your account, no other permissions are required", and that boundaries "do not
limit permissions granted using the aws:PrincipalArn condition key with a wildcard(*) in the
Principal element". S3 Block Public Access isn't modeled. Its `RestrictPublicBuckets` setting can
block grants in a public bucket policy.

### Trust policies

A role's trust policy says who can assume the role. In an account file it is the role's
`AssumeRolePolicyDocument`, AWS's own name for it:

```json
"ITAdmin": {
  "Policies": ["ITAdminFullS3", "DenyStudentRecordsDelete"],
  "AssumeRolePolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "AccountWithMfa",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
      "Action": "sts:AssumeRole",
      "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } }
    }]
  }
}
```

A trust policy has no `Resource`: it covers its own role. It applies to the six STS actions whose
resource is a role: `sts:AssumeRole`, `sts:AssumeRoleWithSAML`, `sts:AssumeRoleWithWebIdentity`,
`sts:TagSession`, `sts:SetSourceIdentity` and `sts:SetContext`. Unlike a bucket policy, AWS says a
trust policy "must explicitly allow access", so the request is denied without an Allow from it.
The [table above](#resource-based-policies) then says what else has to allow. AWS's AssumeRole
page gives the two ways within one account: "Attach a policy to the user that allows the user to
call AssumeRole (as long as the role's trust policy trusts the account)", or "Add the user as a
principal directly in the role's trust policy".

The example's `ITAdmin` trusts the account when the caller signed in with MFA, and the ITStaff
group's `AssumeITAdminRole` policy lets IT staff call `sts:AssumeRole` on it:

```sh
iam-analyzer check \
  --account examples/accounts/district.json \
  --principal user/alee \
  --action sts:AssumeRole \
  --resource arn:aws:iam::111122223333:role/ITAdmin \
  --context aws:MultiFactorAuthPresent=true
```

```
ALLOW
  Allow  AssumeITAdminRole (via group ITStaff)  Sid=AssumeITAdmin
  Allow  arn:aws:iam::111122223333:role/ITAdmin (trust policy, names the account)  Sid=AccountWithMfa
         Bool aws:MultiFactorAuthPresent: true (request: true)
```

With `--absent aws:MultiFactorAuthPresent` instead, which describes a request made with access
keys, the answer is `IMPLICIT_DENY`, because the trust policy doesn't allow it. A teacher such as
`user/jsmith` gets `IMPLICIT_DENY` even with MFA: trusting the account leaves the decision to the
teacher's identity policies, and none of them allows `sts:AssumeRole`.

A role in an account file without an `AssumeRolePolicyDocument` can't be assumed in a check: the
analyzer says it needs the trust policy. With `--policy`, give one with `--resource-policy`.

The analyzer refuses:
- A trust policy that names the caller directly, as a user ARN or `"*"`, when the caller's
  permissions boundary doesn't allow the request. AWS's trust policy page says "If a permissions
  boundary is set for the user, then it must allow the sts:AssumeRole action", but its evaluation
  logic page says a boundary doesn't limit a grant to a user ARN.
- `sts:AssumeRoleWithSAML` and `sts:AssumeRoleWithWebIdentity` requests. SAML and OIDC users make
  them, and the analyzer only models IAM users and role sessions.
- `NotPrincipal` or `Resource` in a trust policy, which AWS doesn't allow.

A trust policy can also settle a role's session tags. Passing session tags needs `sts:TagSession`
in the trust policy. A session made by role chaining "inherits any transitive session tags from
the calling session", though, and AWS doesn't say whether that needs `sts:TagSession` too. So the
analyzer counts a role's own tags as complete only when its trust policy allows no
`sts:TagSession`, and only IAM users and SAML or OIDC providers can assume it. The example's
`TeacherSignIn` role, assumed through the district's SAML provider and tagged `campus=campus-01`,
reads its own campus's records with no `--no-session-tags`.

### Organizations and SCPs

SCPs go in a separate organization file, because in AWS they belong to the organization, not to any
one account. The file defines SCPs by name and attaches them to the root, to OUs (which can contain
more OUs) and to accounts. See
[`examples/organizations/district.json`](examples/organizations/district.json).

```json
{
  "ManagementAccountId": "999988887777",
  "ServiceControlPolicies": { "FullAWSAccess": { "Statement": [ ... ] }, "...": { ... } },
  "Root": {
    "ServiceControlPolicies": ["FullAWSAccess"],
    "OrganizationalUnits": {
      "Schools": {
        "ServiceControlPolicies": ["SchoolServicesOnly", "ProtectStudentRecords"],
        "Accounts": { "111122223333": { "ServiceControlPolicies": ["FullAWSAccess"] } }
      }
    },
    "Accounts": { "999988887777": { "ServiceControlPolicies": ["FullAWSAccess"] } }
  }
}
```

Add `--org FILE` to an `--account` check. The account file's `AccountId` says where the account sits
in the organization. The IT admin role's own policies allow `s3:*`, but an SCP on the Schools OU
stops anyone in that OU from changing the student records bucket policy:

```sh
iam-analyzer check \
  --account examples/accounts/district.json \
  --org examples/organizations/district.json \
  --principal role/ITAdmin \
  --action s3:PutBucketPolicy \
  --resource arn:aws:s3:::district-student-records
```

```
EXPLICIT_DENY
  Deny   ProtectStudentRecords (SCP on OU Schools)  Sid=NoDeletesOrPolicyChanges
```

The rules follow AWS:
- Every level must allow the request: the root, each OU on the way down, and the account itself.
  The SCPs at one level combine, so any one of them can allow it.
- A Deny in any SCP wins.
- Every root, OU and account needs at least one SCP. AWS attaches `FullAWSAccess` by default.
- SCPs never apply to the management account, or to service-linked roles (roles whose `Path`
  starts with `/aws-service-role/`) in any account.
- A short ARN such as `arn:aws:s3` in an SCP is refused. AWS documents completing one with
  wildcards only in identity-based policies.

The Schools OU's `SchoolServicesOnly` SCP is an allow list that leaves out EC2. So `user/alee` can't
call `ec2:DescribeInstances` in that account, even though their IAM policy allows it:

```
IMPLICIT_DENY
  No SCP attached to OU Schools allows this.
```

### Policy variables and the request context

In a policy with `"Version": "2012-10-17"`, AWS fills in policy variables from the request.
`${aws:username}` is the caller's user name, so one policy can give every teacher their own home
folder:

```json
"Resource": "arn:aws:s3:::district-staff-files/home/${aws:username}/*"
```

The values come from the *request context*: the condition keys a request carries, such as
`aws:username` or `aws:SourceIp`. Each key is in one of three states:
- It has a value. Give one with `--context KEY=VALUE`, and repeat the flag to give a key several
  values.
- It's absent: the request really doesn't include it. Say so with `--absent KEY`.
- It's unknown: nobody said. If a statement that matches the request needs an unknown key, the
  analyzer stops and names it, instead of guessing.

```sh
iam-analyzer check \
  --policy examples/policies/staff_home_folder.json \
  --no-resource-policy \
  --action s3:PutObject \
  --resource arn:aws:s3:::district-staff-files/home/jsmith/lesson-plan.docx
```

```
error: the request context says nothing about these condition keys:
  aws:username, used by staff_home_folder.json statement 0 (Sid=OwnHomeFolder)
hint: give each key a value with --context KEY=VALUE, or use --absent KEY if the request doesn't include it
```

With `--context aws:username=jsmith` the answer is `ALLOW`. With `--context aws:username=mgarcia`
it's `IMPLICIT_DENY`, because that folder belongs to someone else.

With `--account`, the account file fills in what it knows about the principal. You can't change
those keys with `--context` or `--absent`.

| Key | User | Role |
|---|---|---|
| `aws:username` | the user's name | absent, because roles have none |
| `aws:PrincipalType` | `User` | `AssumedRole` |
| `aws:PrincipalArn` | the user's ARN | the role's ARN, not the session's |
| `aws:PrincipalAccount` | the file's `AccountId` | the file's `AccountId` |
| `aws:PrincipalTag/KEY` | the user's `Tags`; any other tag is absent | unknown (see below) |

`aws:PrincipalArn` and `aws:PrincipalAccount` need the file's `AccountId`. Registrar `rnguyen`'s
policy covers `district-student-records/${aws:PrincipalTag/campus}/*`, and their `campus` tag is
`campus-02`:

```sh
iam-analyzer check \
  --account examples/accounts/district.json \
  --principal user/rnguyen \
  --action s3:GetObject \
  --resource arn:aws:s3:::district-student-records/campus-02/transcript.pdf
```

```
ALLOW
  Allow  RegistrarCampusRecords (via group Registrars)  Sid=ManageOwnCampusRecords
```

The same request for `campus-01` gives `IMPLICIT_DENY`.

A role's session can carry *session tags*, which override the role's own tags and can add new ones.
So for a role, every `aws:PrincipalTag/` key is unknown until you give it with `--context` or
`--absent`. `--no-session-tags` says the session has none, so the role's own tags are all there
is. A session tag can't remove one of the role's tags, so `--absent` is refused for those. A role's
trust policy can rule session tags out, and then no flag is needed (see
[Trust policies](#trust-policies)).

A default, as in `${aws:PrincipalTag/team, 'company-wide'}`, is used when the key is absent.
Without one, the variable has no value, as `${aws:username}` has for a role. AWS says such a
variable matches nothing, and the analyzer agrees:
- In `Resource`, the ARN with it covers no resource. In `NotResource`, it excludes nothing, so a
  Deny with it applies.
- In a condition, `StringEquals` and `StringLike` don't match it, while `StringNotEquals` and
  `StringNotLike` do.

Where AWS's docs leave a case open, AWS's IAM policy simulator answered it, and the analyzer does
the same:
- A variable whose key has several values, such as `aws:TagKeys`, matches nothing too. If it has a
  default, the analyzer refuses, since nothing settles whether the default is used.
- A `*` or `?` filled in from a value or a default is a literal character, not a wildcard.
- In a `Bool` value, a variable isn't filled in. The value stays as written, so it matches
  nothing.

As AWS requires, a variable can only appear in the resource part of an ARN, after the fifth colon.
Without `"Version": "2012-10-17"`, AWS treats `${...}` as plain text, and so does the analyzer.

### Conditions

A statement with a `Condition` only applies when every condition holds. Conditions read the request
context too, so the same three states apply. Registrars may change their campus's records only
when they signed in with MFA:

```json
{
  "Sid": "RequireMfaForChanges",
  "Effect": "Deny",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::district-student-records/*",
  "Condition": { "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" } }
}
```

```sh
iam-analyzer check \
  --account examples/accounts/district.json \
  --principal user/rnguyen \
  --action s3:PutObject \
  --resource arn:aws:s3:::district-student-records/campus-02/transcript.pdf \
  --absent aws:MultiFactorAuthPresent
```

```
EXPLICIT_DENY
  Deny   RegistrarCampusRecords (via group Registrars)  Sid=RequireMfaForChanges
         BoolIfExists aws:MultiFactorAuthPresent: false (request: not present)
```

The indented line shows each condition, with the value the request had. AWS leaves
`aws:MultiFactorAuthPresent` out of requests made with access keys, so `--absent` describes such a
request. `BoolIfExists` treats a missing key as passing, so the Deny applies. With
`--context aws:MultiFactorAuthPresent=true` the answer is `ALLOW`, and with no flag at all the
analyzer asks for the key.

The rules follow AWS:
- Several conditions, or several keys under one operator: every one must hold.
- Several values for one key: any one can match. A negated operator, such as `StringNotEquals` or
  `NotIpAddress`, holds only when none match.
- A key the request doesn't include: a negated operator holds and any other doesn't. An operator
  ending in `IfExists` holds, and `Null` tests exactly that.
- `ForAllValues` needs every request value to pass, and also holds when the key is missing.
  `ForAnyValue` needs at least one, and fails when the key is missing, even with `IfExists` or on
  `Null`.
- Policy variables can be used in String and ARN values.

Supported operators: `String(Not)Equals(IgnoreCase)`, `String(Not)Like`, the six `Numeric` and six
`Date` comparisons, `Bool`, `BinaryEquals`, `(Not)IpAddress`, `Arn(Not)Equals`, `Arn(Not)Like` and
`Null`, each with the `ForAllValues` and `ForAnyValue` set operators.

Where AWS's documentation leaves a case open, the analyzer does what AWS's IAM policy simulator did
when it was asked, and refuses otherwise:
- **Dates:** ISO 8601, such as `2026-08-15T07:30:00Z`, or epoch seconds. With no time zone, a
  month, a day, or a day and a time to the minute or second is UTC: `2026-08` is midnight UTC on
  August 1. A number is epoch seconds, four digits included, so `2026` isn't the year. A time with
  fractions of a second and no time zone is refused.
- **IP addresses:** a bare address is just that address, `/32` for IPv4 and `/128` for IPv6. A
  range with host bits set, such as `203.0.113.5/24`, means `203.0.113.0/24`.
- **Several values with no set operator:** `StringEquals` and `StringNotEquals` never hold. Any
  other operator is refused.
- **An empty value:** a request whose only value is `""` has a value, except under
  `ForAllValues`, which AWS documents treats it as having none. Where those two rules disagree,
  in `ForAllValues:Null` with `"true"`, the analyzer refuses.

[docs/simulator-check.md](docs/simulator-check.md) has each case with AWS's answer.

Exit codes: `0` = allowed, `1` = denied (explicit or implicit), `2` = input error.

## Compliance reports

`iam-analyzer report` grades an account against a framework's checks, and prints a report someone
can act on:

```sh
iam-analyzer report \
  --account examples/accounts/district.json \
  --org examples/organizations/district.json \
  --framework examples/frameworks/district.json \
  --json report.json
```

The Markdown report goes to the screen, and `--json` writes the same report as JSON. `--org` gives
the SCPs, and `--no-org` says the account isn't in an AWS organization. One of them is required:
leaving SCPs out without saying so could allow what they deny.

Part of the district report ([the whole report](tests/golden/district_report.md)):

```
## FAIL: Only counselors can read counseling notes (high)

Asked: Can anyone but user/kwong do s3:GetObject on
arn:aws:s3:::district-student-records/counseling/2026/notes.pdf?

- user/jsmith can. Granted by TeacherReadGrades, Sid ReadStudentRecords, through group Teachers.
- user/mgarcia can. Granted by TeacherReadGrades, Sid ReadStudentRecords, through group Substitutes.
- user/alee, role/ITAdmin can. Granted by ITAdminFullS3, Sid FullS3Access, attached directly.
- Can't: user/dpatel, user/rnguyen, user/tbrooks, role/GradebookVendor, role/TeacherSignIn.
- Not asked: user/kwong.
```

### Results

Every check gets one of four results:
- **PASS:** the answer the check expects, for every question it asked.
- **FAIL:** a principal gets the access a check forbids, or doesn't get the access a check
  expects. Each principal that gets access is listed with every statement that grants it: the
  policy, its Sid (or its position, such as "statement 0"), and how the principal gets it, such as
  "through group Teachers" or "attached directly".
- **DEPENDS:** only for checks that expect access. The answer depends on a condition key, such as
  `aws:MultiFactorAuthPresent`, and the report lists its values with each answer.
- **CAN'T TELL:** the analyzer refused, with its reason and what would settle it, such as a
  bucket the account file doesn't describe. A refusal is never a PASS.

In a check that forbids access, any value that allows the request is a FAIL, never DEPENDS: an
MFA Deny that skips requests made with access keys fails the check, and the report lists
`absent` as the value that gets in. A check takes the worst result of its questions: FAIL, then
DEPENDS, then CAN'T TELL, then PASS.

Exit codes:
- `0`: every check passes, and no finding is high or critical;
- `1`: a check fails, or a finding is high or critical (see [Policy findings](#policy-findings));
- `3`: nothing failed, but some check is DEPENDS or CAN'T TELL;
- `2`: input errors.

CI can fail on `1`, and decide for itself what `3` means.

### Framework files

A framework is a JSON file, so adding one never changes the analyzer. See
[`examples/frameworks/district.json`](examples/frameworks/district.json).

```json
{
  "Framework": { "Id": "district-student-records", "Title": "Texas school district student records" },
  "Requirements": {
    "NIST AC-6": {
      "Framework": "NIST SP 800-53 Rev. 5", "Id": "AC-6", "Title": "Least Privilege",
      "Link": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"
    }
  },
  "Checks": [{
    "Id": "counseling-notes-counselors-only",
    "Title": "Only counselors can read counseling notes",
    "Severity": "high",
    "Type": "only",
    "Principals": ["user/kwong"],
    "Actions": ["s3:GetObject"],
    "Resources": ["arn:aws:s3:::district-student-records/counseling/2026/notes.pdf"],
    "Fix": "Narrow TeacherReadGrades from district-student-records/* to the folders teachers need.",
    "MapsTo": ["NIST AC-6"]
  }]
}
```

Every check has an `Id`, a `Title`, a `Severity` (`critical`, `high`, `medium` or `low`), the
`Actions` and `Resources` it asks about, and a `Fix`. `MapsTo` and `Context` are optional. There
are three types:

| `Type` | Asks | Expects |
|---|---|---|
| `only` | can anyone outside `Principals` do it? (`[]` means anyone at all) | no |
| `requires` | can anyone do it unless `Key` has `Value`? `Except` leaves principals out | no |
| `can` | can each of `Principals` do it? | yes |

- Principals are `user/NAME`, `role/NAME` or `group/NAME`, where a group stands for its members.
  `only` and `requires` ask every user and role in the account file except the ones they name.
- A check asks about exactly the actions and resources it lists. A resource is `"*"` or one full
  ARN, with no wildcards, as in a real request.
- `requires` takes a key whose every value AWS documents, such as `aws:MultiFactorAuthPresent`
  with `"Value": "true"`. The report then asks with each other value: `false` and absent.
- `Context` gives condition keys the check's question fixes, such as
  `{"aws:SourceIp": "203.0.113.5"}`. A list gives a key several values in one request, and `null`
  says the request doesn't include it. It can't change what the account file says, such as
  `aws:username`.

The file is checked when it loads, as account files are: unknown or repeated keys, wildcard
actions, resources that aren't one full ARN, and references to undefined requirements are input
errors.

### The values the report tries

A check states only what its question fixes. When a statement needs a condition key the check
doesn't give, the report tries each value AWS documents for that key:
`aws:MultiFactorAuthPresent` (true, false or absent), `aws:SecureTransport` and
`aws:ViaAWSService` (true or false). For example, ITAdmin's trust policy needs MFA, so "can a
teacher assume ITAdmin?" is asked three times, and the answer is no every time. Any other key, such
as `aws:SourceIp`, has too many values to try. The report is CAN'T TELL and names the key until the
check gives it a value in `Context`.

`aws:MultiFactorAuthPresent` can be absent for any principal. AWS says it's missing for requests
made with long-term access keys and for federated users. For a role's session, AWS's docs
contradict each other: "The temporary credentials returned by `AssumeRole` do not include MFA
information in the context", and also that a role assumed "without MFA information" has a session
that "does not indicate that the user authenticated with MFA". So a role's item in a check that
requires MFA carries a note. It says MFA for a role is checked when the role is assumed, and
points to the trust policy statements that say how.

### Who a report can't ask about

The report asks about the users and roles in the account file. When a bucket policy or trust
policy allows the action for someone else, such as `"*"`, another account, a service or a
federated provider, the check is CAN'T TELL and cites the statement. The analyzer doesn't evaluate
requests from outside the account yet.

A `can` check is weaker than the other two. Session policies, resource control policies and VPC
endpoint policies aren't modeled, and they can only take access away. So a `can` PASS means the
files allow it, while an `only` or `requires` PASS stays true whatever those policies say.

### Policy findings

Some AWS surprises need no question: they're in the policy text. Every report scans all of the
account file's policies for them: identity policies and boundaries, bucket policies, trust
policies, and with `--org`, SCPs. Each finding names the statement and where its policy is used,
says why it matters and how to fix it, and cites its evidence. That evidence is either answers
recorded from AWS's IAM policy simulator (in `tests/simulator_fixtures`, and the tests check that
AWS's recorded answer is the one claimed) or AWS's documentation.

A finding is high when it can let a request through that the policy's author meant to stop, such
as a Deny that never applies or an Allow that always applies. It's low when it can only stop a
request the author meant to let through.

| Finding | Fires on | Evidence |
|---|---|---|
| A four-digit date is read as epoch seconds | a date condition with a value such as `2027`, which AWS reads as a moment in 1970 | simulator: `dates_without_a_time_zone/four_digits` |
| A Bool value with a policy variable never matches | `Bool` with a value such as `${aws:MultiFactorAuthPresent}` | simulator: `bool_with_a_variable/*`; AWS's policy variables page |
| A bucket policy grants access to everyone | an Allow for `"*"` that no condition limits to fixed values of a key S3 names | S3's "The meaning of public" |
| A trust policy lets everyone assume the role | an Allow for `"*"` (critical without a condition) | the Principal page: "Do not leave your role accessible to everyone!" |
| Another account can assume the role without an external ID | an `sts:AssumeRole` Allow for an account outside the organization, with no `sts:ExternalId` condition | the third-party access page |
| A principal is shown as a unique ID, so it was deleted | an AWS principal such as `AIDAEXAMPLEEXAMPLE123` | the Principal page |
| An MFA Deny skips requests made with access keys | a Deny with plain `Bool aws:MultiFactorAuthPresent: false`, which fails when the key is missing | the global condition keys page, which recommends `...IfExists` |
| A ForAllValues Allow also applies when the key is missing | an Allow with `ForAllValues:` and no `Null` false check on the key | simulator: `scenarios/condition_for_all_values_holds_when_the_key_is_missing`; the condition operators page |
| IfExists does nothing with ForAnyValue | `ForAnyValue:...IfExists`, which still fails on a missing key | simulator: `for_any_value_if_exists/key_absent` |
| A set operator turns a Null check around | `ForAnyValue:Null` true, which never holds, or `ForAllValues:Null` false, which holds on a missing key | simulator: `set_operator_on_null/*` |
| A date with no time zone is read as UTC (always low) | a date such as `2026-08-15` or `2026-08-15T07:30` | simulator: `dates_without_a_time_zone/*` |
| An IP range with host bits covers the whole network | a range such as `203.0.113.5/24` | simulator: `ip_ranges/range_with_host_bits` |
| A policy variable has no value for some principals | a variable with no default whose key the account file says some principals never have, such as `${aws:username}` for a role, or a tag a user lacks | simulator: `variables_without_a_value/*`; the policy variables page |
| A Deny uses NotPrincipal (medium) | any `NotPrincipal` | the NotPrincipal page, which recommends `aws:PrincipalArn` conditions instead |
| A NotPrincipal Deny always denies principals with a boundary (low) | a `NotPrincipal` Deny, when users or roles in the file have a permissions boundary | the NotPrincipal page: it "will always deny any IAM principal that has a permissions boundary policy attached" |

The district account has two of these mistakes on purpose:
- `SummerSchoolRecords` allows reads "until 2027", but `DateLessThan` compares against early 1970,
  so the Allow never applies and `tbrooks` can't read anything.
- `district-roster-exports` was opened to everyone to share a roster with a vendor. Its
  `ShareRosterWithVendor` statement allows `"*"`, so the roster check fails for every principal in
  the file and is CAN'T TELL for everyone outside it.

A public bucket follows S3's definition: a grant to `"*"` is public unless a condition pins one of
these keys to fixed values, with no wildcard and no policy variable:
- `aws:SourceIp`, no broader than /8 for IPv4 or /32 for IPv6;
- `aws:SourceArn`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:SourceOwner` or `aws:SourceAccount`;
- `aws:userid`;
- `s3:DataAccessPointArn` (the access point's name may have a wildcard) or
  `s3:DataAccessPointAccount`;
- `aws:PrincipalOrgID`.

Negated operators, `...IfExists` and `ForAllValues` don't pin a key, since they also hold for
requests without it. S3 names `aws:PrincipalOrgID` only as an example of a principal key. So a
grant pinned only by another principal key, such as `aws:PrincipalArn`, is still reported, and the
finding says S3's page doesn't settle it.

### Mapping checks to requirements

A requirement gives the framework, the requirement's ID, a short title and a link:
- never the framework's own text (the title is at most 60 characters, on one line);
- never an ID that hasn't been checked against its source.

The district framework maps to two:
- FERPA 34 CFR § 99.31(a)(1)(ii), checked against Cornell LII's copy, since eCFR blocks automated
  reads;
- NIST SP 800-53 Rev. 5 controls, checked against NIST SP 800-53B's baseline tables.

It maps no CIS recommendations, because their IDs change between benchmark versions and their text
is licensed. It maps no TEA requirements yet, since none has been checked.

## Tests

```sh
pytest                                   # everything
pytest tests/test_matching.py            # one file
pytest tests/test_evaluator.py -k deny   # tests whose name matches "deny"
```

Data-driven scenarios live in `tests/scenarios/*.json`. Each one holds policies, a request and the
expected decision, plus an optional request `context` (`null` marks a key as absent). A request on a
specific resource also needs `"resource_policy": null`, which describes the resource as having no
resource-based policy, as `--no-resource-policy` does. To add a case, drop in a new file.

`tests/simulator_fixtures/` holds answers recorded from AWS's IAM policy simulator, and
`tests/test_simulator_fixtures.py` replays them against the analyzer without AWS.
[docs/simulator-check.md](docs/simulator-check.md) has the results and the differences found.
Recording new answers calls AWS and needs boto3 (`pip install -e ".[dev,simulator]"`). The
analyzer itself doesn't need boto3. See `simulator_check/__init__.py`.

`tests/golden/district_report.md` is the district report, exactly as `iam-analyzer report` prints
it, and `tests/test_report.py` checks that the report still matches it. After an intended change
to the report, regenerate it with the command in that test's docstring and review the diff.
