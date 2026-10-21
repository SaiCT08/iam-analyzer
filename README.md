# iam-analyzer

An AWS IAM effective-permissions analyzer, written in Python. Given a set of policies, it answers
"can this principal perform this action on this resource?" using AWS's policy evaluation logic, and
explains *which statements* produced the answer. It's general-purpose and works with any AWS account.
Texas school districts (TEA/FERPA) are the first showcase use case, so the examples use district
policies. Compliance reporting will support pluggable frameworks.

It works entirely on local policy JSON files. No AWS account or credentials are needed.

## Status

The analyzer currently covers **identity policies** and **permissions boundaries**:
- Allow/Deny statements, where an explicit deny always wins and the default is an implicit deny.
- `*` / `?` wildcards in actions and resources.
- `NotAction` / `NotResource`, which mean "everything except these". For example, a Deny with
  `NotAction: ["s3:Get*"]` is a read-only guardrail.
- Permissions boundaries. A boundary caps what a user or role can do: a request needs an Allow in
  an identity policy **and** in the boundary, and a Deny in either one wins. A boundary never
  grants access on its own.

Policies that use `Condition`, `Principal` or `NotPrincipal` are rejected with a clear error.
Resource-based policies (such as S3 bucket policies) aren't evaluated yet. Support for these comes
in later phases.

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

Exit codes: `0` = allowed, `1` = denied (explicit or implicit), `2` = input error.

## Tests

```sh
pytest                                   # everything
pytest tests/test_matching.py            # one file
pytest tests/test_evaluator.py -k deny   # tests whose name matches "deny"
```

Data-driven scenarios live in `tests/scenarios/*.json`. Each one holds policies, a request and the
expected decision. To add a case, drop in a new file.
