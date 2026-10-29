# Compliance report: Texas school district student records

- Framework: district.json (district-student-records), 7 checks.
- Account: district.json (111122223333), 7 users and 3 roles.
- Organization: district.json, whose SCPs are applied.

| Result | Checks |
|---|---|
| FAIL | 3 |
| DEPENDS | 1 |
| CAN'T TELL | 1 |
| PASS | 2 |

Findings: 1 high, 1 low.

## FAIL: Only counselors can read counseling notes (high)

Asked: Can anyone but user/kwong do s3:GetObject on
arn:aws:s3:::district-student-records/counseling/2026/notes.pdf?

- user/jsmith can. Granted by TeacherReadGrades, Sid ReadStudentRecords, through group Teachers.
- user/mgarcia can. Granted by TeacherReadGrades, Sid ReadStudentRecords, through group Substitutes.
- user/alee, role/ITAdmin can. Granted by ITAdminFullS3, Sid FullS3Access, attached directly.
- Can't: user/dpatel, user/rnguyen, user/tbrooks, role/GradebookVendor, role/TeacherSignIn.
- Not asked: user/kwong.

Fix: Narrow TeacherReadGrades from district-student-records/* to the folders teachers need, and add
a bucket policy Deny on counseling/* for everyone but counselors, using aws:PrincipalArn as
OnlyITAdminChangesThePolicy does.

Maps to:
- FERPA (34 CFR Part 99) 34 CFR 99.31(a)(1)(ii): Reasonable methods to limit school officials'
  access. https://www.law.cornell.edu/cfr/text/34/99.31
- NIST SP 800-53 Rev. 5 AC-6: Least Privilege. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

## FAIL: Only registrars can read roster exports (high)

Asked: Can anyone but group/Registrars do s3:GetObject on
arn:aws:s3:::district-roster-exports/2026/roster.csv?

- user/jsmith, user/mgarcia, user/dpatel, user/kwong, user/tbrooks, role/GradebookVendor,
  role/TeacherSignIn can. Granted by the resource policy on arn:aws:s3:::district-roster-exports,
  Sid ShareRosterWithVendor, which names everyone.
- user/alee, role/ITAdmin can. Granted by ITAdminFullS3, Sid FullS3Access, attached directly; the
  resource policy on arn:aws:s3:::district-roster-exports, Sid ShareRosterWithVendor, which names
  everyone.
- Can't tell for principals outside district.json: the resource policy on
  arn:aws:s3:::district-roster-exports, Sid ShareRosterWithVendor, allows s3:GetObject for everyone
  ("*"), and the analyzer doesn't evaluate requests from outside the account file yet.
- Not asked: user/rnguyen.

Fix: Replace "*" in ShareRosterWithVendor with the vendor's account or role ARN, or share the export
with a presigned URL, and turn on S3 Block Public Access.

Maps to:
- FERPA (34 CFR Part 99) 34 CFR 99.31(a)(1)(ii): Reasonable methods to limit school officials'
  access. https://www.law.cornell.edu/cfr/text/34/99.31
- NIST SP 800-53 Rev. 5 AC-22: Publicly Accessible Content.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

## FAIL: Changing student records needs MFA (high)

Asked: Can anyone do s3:PutObject on arn:aws:s3:::district-student-records/campus-02/transcript.pdf
when aws:MultiFactorAuthPresent is false or absent?

- user/alee can. Granted by ITAdminFullS3, Sid FullS3Access, attached directly.
- user/rnguyen can't. Denied by RegistrarCampusRecords, Sid RequireMfaForChanges, through group
  Registrars. The Deny overrides RegistrarCampusRecords, Sid ManageOwnCampusRecords, through group
  Registrars.
- role/ITAdmin passes: its own policies allow the request, but AWS checks MFA for a role when it's
  assumed, and no one can assume it without MFA (trust policy Sid AccountWithMfa).
  - AWS: "The temporary credentials returned by AssumeRole do not include MFA information in the
    context, so you cannot check individual API operations for MFA."
    https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html#scenarios
- Can't: user/jsmith, user/mgarcia, user/dpatel, user/kwong, user/tbrooks, role/GradebookVendor,
  role/TeacherSignIn.

Fix: Take ITAdminFullS3 off user alee, so IT staff change records only through the ITAdmin role,
whose trust policy requires MFA. MFA conditions belong in users' policies and in trust policies, not
in a role's own policies: AWS says a role's credentials carry no MFA information, so an MFA Deny
there could lock the role out.

Maps to:
- NIST SP 800-53 Rev. 5 IA-2(1): Multi-factor Authentication to Privileged Accounts.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-53 Rev. 5 IA-2(2): Multi-factor Authentication to Non-privileged Accounts.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

## DEPENDS: Registrars can update their own campus's records (medium)

Asked: Can group/Registrars do s3:PutObject on
arn:aws:s3:::district-student-records/campus-02/transcript.pdf?

- user/rnguyen, depending on aws:MultiFactorAuthPresent:
  - true: can. Granted by RegistrarCampusRecords, Sid ManageOwnCampusRecords, through group
    Registrars.
  - false, absent: can't. Denied by RegistrarCampusRecords, Sid RequireMfaForChanges, through group
    Registrars. The Deny overrides RegistrarCampusRecords, Sid ManageOwnCampusRecords, through group
    Registrars.

Fix: Registrars change records with MFA, by design. If they can't even with MFA, check
RegistrarCampusRecords and each registrar's campus tag.

## CAN'T TELL: Only teachers can read lesson plans (medium)

Asked: Can anyone but group/Teachers do s3:GetObject on
arn:aws:s3:::district-lesson-plans/week1.pdf?

- Can't tell for everyone asked: nothing describes arn:aws:s3:::district-lesson-plans: it can have a
  resource-based policy, and the analyzer can't tell whether it has one, or which account it is in.
  Describe it in the account file's Resources, as {} if it has no resource-based policy.
- Not asked: user/jsmith, user/dpatel.

Fix: Describe district-lesson-plans in the account file's Resources, with its bucket policy or as {}
if it has none, so the analyzer can answer.

Maps to:
- NIST SP 800-53 Rev. 5 AC-3: Access Enforcement. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

## PASS: No one can delete student records (high)

Asked: Can anyone do s3:DeleteObject or s3:DeleteObjectVersion on
arn:aws:s3:::district-student-records/campus-02/transcript.pdf?

- user/alee can't. Denied by DenyStudentRecordsDelete, Sid NoDeleteStudentRecords, through group
  ITStaff; ProtectStudentRecords, Sid NoDeletesOrPolicyChanges, an SCP on OU Schools. The Denies
  override ITAdminFullS3, Sid FullS3Access, attached directly.
- role/ITAdmin can't. Denied by DenyStudentRecordsDelete, Sid NoDeleteStudentRecords, attached
  directly; ProtectStudentRecords, Sid NoDeletesOrPolicyChanges, an SCP on OU Schools. The Denies
  override ITAdminFullS3, Sid FullS3Access, attached directly.
- Can't: user/jsmith, user/mgarcia, user/dpatel, user/rnguyen, user/kwong, user/tbrooks,
  role/GradebookVendor, role/TeacherSignIn.

Keep: DenyStudentRecordsDelete on every group and role that can write student records, and the
ProtectStudentRecords SCP on the Schools OU.

Maps to:
- NIST SP 800-53 Rev. 5 AC-3: Access Enforcement. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

## PASS: Assuming the IT admin role needs MFA (high)

Asked: Can anyone do sts:AssumeRole on arn:aws:iam::111122223333:role/ITAdmin when
aws:MultiFactorAuthPresent is false or absent?

- Can't: user/jsmith, user/mgarcia, user/alee, user/dpatel, user/rnguyen, user/kwong, user/tbrooks,
  role/ITAdmin, role/GradebookVendor, role/TeacherSignIn.

Keep: The Bool aws:MultiFactorAuthPresent true condition in ITAdmin's trust policy.

Maps to:
- NIST SP 800-53 Rev. 5 IA-2(1): Multi-factor Authentication to Privileged Accounts.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

## Findings

### HIGH: A bucket policy grants access to everyone

- In: the resource policy on arn:aws:s3:::district-roster-exports, Sid ShareRosterWithVendor.
- Principal: everyone ("*").
- Impact: It lets anyone do s3:GetObject on arn:aws:s3:::district-roster-exports/*, with credentials
  from any AWS account or with none.
- Why: The statement allows "*", and no condition limits it to fixed values of a key that S3 names,
  such as aws:SourceVpce or aws:PrincipalOrgID, so S3 counts the policy as public: anyone on the
  internet can make the request, unless S3 Block Public Access stops it, which the analyzer doesn't
  model.
- Evidence: AWS: "When evaluating a bucket policy, Amazon S3 begins by assuming that the policy is
  public. It then evaluates the policy to determine whether it qualifies as non-public."
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html#access-control-block-public-access-policy-status
- Fix: Name the account or role that needs access instead of "*", or limit the grant with a fixed
  aws:SourceVpce or aws:PrincipalOrgID, and turn on S3 Block Public Access.

### LOW: A four-digit date is read as epoch seconds

- In: SummerSchoolRecords, Sid ReadCampus01UntilNextYear: an identity policy attached to
  group/SummerSchool.
- Condition: DateLessThan aws:CurrentTime: 2027.
- Impact: The Allow never applies, so it never lets group/SummerSchool do s3:GetObject on
  arn:aws:s3:::district-student-records/campus-01/*.
- Why: AWS reads a number in a date condition as epoch seconds, four digits included, so a value
  such as 2027 is a moment early on January 1, 1970, not the year.
- Evidence: AWS's IAM policy simulator answered ALLOW in dates_without_a_time_zone/four_digits
  (tests/simulator_fixtures).
- Fix: Write the date in ISO 8601 with a time zone, such as 2027-01-01T00:00:00Z.

## Scope and limits

- A PASS covers only the 7 users and 3 roles in district.json. Requests from other accounts,
  anonymous requests and federated users aren't evaluated; a policy that lets them in makes a check
  CAN'T TELL.
- Each check covers exactly the requests it lists: its actions, its resources, and the condition
  keys it gives.
- Keys whose every value AWS documents are tried with each one: aws:MultiFactorAuthPresent (true,
  false, absent); aws:SecureTransport (true, false); aws:ViaAWSService (true, false). Any other key
  a statement needs is CAN'T TELL until a check gives it a value.
- SCPs come from district.json.
- Not modeled: session policies, resource control policies and VPC endpoint policies, which can only
  take access away, so a PASS of a "can" check means the files allow it; S3 Block Public Access; and
  ACLs, which described buckets have disabled.
- A role's requests are asked about as they are. The one exception is a check that requires MFA: AWS
  checks MFA for a role when it's assumed, so a role allowed without MFA is asked who can assume it
  without MFA. That second question goes one level deep.
