# iam-analyzer

An AWS IAM effective-permissions analyzer, written in Python. Given a set of policies, it answers
"can this principal perform this action on this resource?" using AWS's policy evaluation logic, and
explains *which statements* produced the answer. It's general-purpose and works with any AWS account.
Texas school districts (TEA/FERPA) are the first showcase use case, so the examples use district
policies. Compliance reporting will support pluggable frameworks.

It works entirely on local policy JSON files. No AWS account or credentials are needed.

## Status

The analyzer currently covers **identity policies**, **permissions boundaries** and **service control
policies (SCPs)**:
- Allow/Deny statements, where an explicit deny always wins and the default is an implicit deny.
- `*` / `?` wildcards in actions and resources. In a resource ARN, a wildcard stays inside one
  colon-separated part, except a `*` at the end of a part, which can run on past colons. So
  `function:*` covers Lambda aliases such as `function:billing:canary`. A short ARN such as
  `arn:aws:s3` is completed with wildcards (`arn:aws:s3:*:*:*`), as AWS does.
- `NotAction` / `NotResource`, which mean "everything except these". For example, a Deny with
  `NotAction: ["s3:Get*"]` is a read-only guardrail.
- Permissions boundaries. A boundary caps what a user or role can do: a request needs an Allow in
  an identity policy **and** in the boundary, and a Deny in either one wins. A boundary never
  grants access on its own.
- SCPs from AWS Organizations. A request must be allowed at every level from the organization root
  down to the account, and a Deny in any SCP wins. Like boundaries, SCPs never grant access.
- Policies are checked the way AWS checks them when they're saved. A policy AWS would reject is
  refused with a clear error instead of being evaluated. Examples: a repeated JSON key, an unknown
  `Version`, a `Sid` with characters other than letters and digits, or an action without a service
  prefix.

Not supported yet:
- `Condition`, `Principal` and `NotPrincipal` are rejected with a clear error. Most real-world SCPs
  use conditions, so many of them can't be loaded yet.
- Policy variables such as `${aws:username}` are rejected in policies with
  `"Version": "2012-10-17"`, where AWS fills them in from the request. Without that `Version`, AWS
  treats them as plain text, and so does the analyzer.
- Resource-based policies, such as S3 bucket policies, aren't evaluated.

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

### Permissions boundaries

`--boundary FILE` adds a permissions boundary. Here a gradebook vendor's role has full S3 access,
but its boundary only covers the gradebook app's own bucket, so it can't read student records:

```sh
iam-analyzer check \
  --policy examples/policies/it_admin_full_s3.json \
  --boundary examples/policies/gradebook_vendor_boundary.json \
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
  "Policies": { "TeacherReadGrades": { "Statement": [ ... ] } },
  "Groups":   { "Teachers": { "Policies": ["TeacherReadGrades"] } },
  "Users":    { "jsmith": { "Groups": ["Teachers"], "Policies": [] } },
  "Roles":    { "ITAdmin": { "Policies": ["..."], "PermissionsBoundary": "..." } }
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

Roles can also have a `Path`, as in AWS, and the default is `/`. AWS creates service-linked roles
for its own services under `/aws-service-role/`, for example
`/aws-service-role/support.amazonaws.com/`. SCPs never apply to those roles, so give a
service-linked role its real path. A role's name alone doesn't make it service-linked.

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

The Schools OU's `SchoolServicesOnly` SCP is an allow list that leaves out EC2. So `user/alee` can't
call `ec2:DescribeInstances` in that account, even though their IAM policy allows it:

```
IMPLICIT_DENY
  No SCP attached to OU Schools allows this.
```

Exit codes: `0` = allowed, `1` = denied (explicit or implicit), `2` = input error.

## Tests

```sh
pytest                                   # everything
pytest tests/test_matching.py            # one file
pytest tests/test_evaluator.py -k deny   # tests whose name matches "deny"
```

Data-driven scenarios live in `tests/scenarios/*.json`. Each one holds policies, a request and the
expected decision. To add a case, drop in a new file.
