# iam-analyzer

An AWS IAM effective-permissions analyzer, written in Python. Given a set of policies, it answers
"can this principal perform this action on this resource?" using AWS's policy evaluation logic, and
explains *which statements* produced the answer. It's general-purpose and works with any AWS account.
Texas school districts (TEA/FERPA) are the first showcase use case, so the examples use district
policies. Compliance reporting will support pluggable frameworks.

It works entirely on local policy JSON files. No AWS account or credentials are needed.

## Status

Phase 1 covers **identity policies**: Allow/Deny statements, explicit deny always winning, default
(implicit) deny, and `*` / `?` wildcards in actions and resources. Policies that use `Condition`,
`NotAction`, `NotResource` or `Principal` are rejected with a clear error. Support for these comes
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

Exit codes: `0` = allowed, `1` = denied (explicit or implicit), `2` = input error.

## Tests

```sh
pytest                                   # everything
pytest tests/test_matching.py            # one file
pytest tests/test_evaluator.py -k deny   # tests whose name matches "deny"
```

Data-driven scenarios live in `tests/scenarios/*.json`. Each one holds policies, a request and the
expected decision. To add a case, drop in a new file.
