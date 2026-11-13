# Compliance report: AnyCompany production access

- Framework: anycompany.json (anycompany-production), 8 checks.
- Account: anycompany-production.json (111122223333), 6 users and 4 roles.
- Organization: anycompany.json, whose SCPs are applied.

| Result | Checks |
|---|---|
| FAIL | 3 |
| DEPENDS | 1 |
| CAN'T TELL | 1 |
| PASS | 3 |

Findings: 1 high, 1 medium.

## FAIL: Only the on-call admin role can read database backups (high)

Asked: Can anyone but role/OnCallAdmin do s3:GetObject on
arn:aws:s3:::anycompany-prod-db-backups/2026-11-12/app.sql.gz?

- user/jsouza, user/nwolf can. Granted by SupportAccess, Sid ReadSupportBuckets, through group
  Support.
- role/VendorMonitoring can. Granted by VendorReadOnly, Sid ReadMetricsAndLogs, attached directly.
- Can't: user/mrivera, user/psantos, user/ssarkar, user/mjackson, role/CIDeploy, role/DataPipeline.
- Not asked: role/OnCallAdmin.

Fix: Narrow SupportAccess from anycompany-prod-* to the buckets support needs,
anycompany-prod-app-logs and anycompany-prod-support-uploads, and VendorReadOnly's S3 actions from
"*" to anycompany-prod-app-logs. A bucket policy Deny like the customer data bucket's
OnlyTheDataTeam would also stop grants added later.

Maps to:
- NIST SP 800-53 Rev. 5 AC-6: Least Privilege. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-53 Rev. 5 CP-9: System Backup. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- SOC 2 (AICPA TSC 2017) CC6.1: Logical access controls and authentication.
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
- SOC 2 (AICPA TSC 2017) CC6.3: Role-based access and least privilege.
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

## FAIL: Only on-call engineers can assume the on-call admin role (high)

Asked: Can anyone but group/OnCall, role/OnCallAdmin do sts:AssumeRole on
arn:aws:iam::111122223333:role/OnCallAdmin?

- role/CIDeploy can. Granted by the trust policy of arn:aws:iam::111122223333:role/OnCallAdmin, Sid
  DeployMigrations, which names the role.
- Can't: user/psantos, user/ssarkar, user/mjackson, user/jsouza, user/nwolf, role/VendorMonitoring,
  role/DataPipeline.
- Not asked: user/mrivera, role/OnCallAdmin.

Fix: Take DeployMigrations out of OnCallAdmin's trust policy, and give CIDeploy the permissions its
migrations need instead, so the deploy pipeline can't become the admin role.

Maps to:
- NIST SP 800-53 Rev. 5 AC-6(5): Privileged Accounts.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- SOC 2 (AICPA TSC 2017) CC6.3: Role-based access and least privilege.
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

## FAIL: Reading customer data needs MFA (high)

Asked: Can anyone but role/DataPipeline do s3:GetObject on
arn:aws:s3:::anycompany-prod-customer-data/exports/2026-11/accounts.csv when
aws:MultiFactorAuthPresent is false or absent?

- user/jsouza, user/nwolf can't. Denied by the resource policy on
  arn:aws:s3:::anycompany-prod-customer-data, Sid OnlyTheDataTeam, which names everyone. The Deny
  overrides SupportAccess, Sid ReadSupportBuckets, through group Support. Without this Deny, the
  request would be allowed.
- role/OnCallAdmin can't. Denied by the resource policy on
  arn:aws:s3:::anycompany-prod-customer-data, Sid OnlyTheDataTeam, which names everyone. The Deny
  overrides AdministratorAccess, statement 0, attached directly. Without this Deny, the request
  would be allowed.
- role/VendorMonitoring can't. Denied by the resource policy on
  arn:aws:s3:::anycompany-prod-customer-data, Sid OnlyTheDataTeam, which names everyone. The Deny
  overrides VendorReadOnly, Sid ReadMetricsAndLogs, attached directly. Without this Deny, the
  request would be allowed.
- user/ssarkar, depending on aws:MultiFactorAuthPresent:
  - false: can't. Denied by RequireMfaForCustomerData, Sid DenyCustomerDataWithoutMfa, through group
    Data. The Deny overrides CustomerDataAccess, Sid ReadCustomerData, through group Data. Without
    this Deny, the request would be allowed.
  - absent: can. Granted by CustomerDataAccess, Sid ReadCustomerData, through group Data.
- Can't: user/mrivera, user/psantos, user/mjackson, role/CIDeploy.
- Not asked: role/DataPipeline.

Fix: Use BoolIfExists instead of Bool in RequireMfaForCustomerData's DenyCustomerDataWithoutMfa, so
the Deny also stops requests made with access keys, which carry no MFA key.

Maps to:
- NIST SP 800-53 Rev. 5 IA-2(2): Multi-factor Authentication to Non-privileged Accounts.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- SOC 2 (AICPA TSC 2017) CC6.1: Logical access controls and authentication.
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

## DEPENDS: On-call engineers can assume the on-call admin role (medium)

Asked: Can group/OnCall do sts:AssumeRole on arn:aws:iam::111122223333:role/OnCallAdmin?

- user/mrivera, depending on aws:MultiFactorAuthPresent:
  - true: can. Granted by AssumeOnCallAdmin, Sid AssumeOnCallAdmin, through group OnCall; the trust
    policy of arn:aws:iam::111122223333:role/OnCallAdmin, Sid OnCallWithMfa, which names the
    account.
  - false, absent: can't: the trust policy of arn:aws:iam::111122223333:role/OnCallAdmin doesn't
    allow it.

Fix: On-call engineers assume OnCallAdmin with MFA, by design. If they can't even with MFA, check
AssumeOnCallAdmin on the OnCall group and OnCallWithMfa in the role's trust policy.

## CAN'T TELL: Assuming the on-call admin role needs MFA (high)

Asked: Can anyone do sts:AssumeRole on arn:aws:iam::111122223333:role/OnCallAdmin when
aws:MultiFactorAuthPresent is false or absent?

- role/CIDeploy can. Granted by the trust policy of arn:aws:iam::111122223333:role/OnCallAdmin, Sid
  DeployMigrations, which names the role.
  - CAN'T TELL: AWS checks aws:MultiFactorAuthPresent for a role when it's assumed, and the analyzer
    can't tell whether everyone who can assume role/CIDeploy needs aws:MultiFactorAuthPresent true:
    - Can't tell for principals outside anycompany-production.json: the trust policy of
      arn:aws:iam::111122223333:role/CIDeploy, Sid CIRunnerInDevelopment, allows sts:AssumeRole for
      arn:aws:iam::123456789012:role/CIRunner, and the analyzer doesn't evaluate requests from
      outside the account file yet.
- Can't: user/mrivera, user/psantos, user/ssarkar, user/mjackson, user/jsouza, user/nwolf,
  role/OnCallAdmin, role/VendorMonitoring, role/DataPipeline.

Fix: Take DeployMigrations out of OnCallAdmin's trust policy, so only someone who signed in with MFA
can assume the role.

Maps to:
- NIST SP 800-53 Rev. 5 IA-2(1): Multi-factor Authentication to Privileged Accounts.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- SOC 2 (AICPA TSC 2017) CC6.1: Logical access controls and authentication.
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

## PASS: Only the data team can read customer data (high)

Asked: Can anyone but group/Data, role/DataPipeline do s3:GetObject on
arn:aws:s3:::anycompany-prod-customer-data/exports/2026-11/accounts.csv?

- user/jsouza, user/nwolf can't. Denied by the resource policy on
  arn:aws:s3:::anycompany-prod-customer-data, Sid OnlyTheDataTeam, which names everyone. The Deny
  overrides SupportAccess, Sid ReadSupportBuckets, through group Support. Without this Deny, the
  request would be allowed.
- role/OnCallAdmin can't. Denied by the resource policy on
  arn:aws:s3:::anycompany-prod-customer-data, Sid OnlyTheDataTeam, which names everyone. The Deny
  overrides AdministratorAccess, statement 0, attached directly. Without this Deny, the request
  would be allowed.
- role/VendorMonitoring can't. Denied by the resource policy on
  arn:aws:s3:::anycompany-prod-customer-data, Sid OnlyTheDataTeam, which names everyone. The Deny
  overrides VendorReadOnly, Sid ReadMetricsAndLogs, attached directly. Without this Deny, the
  request would be allowed.
- Can't: user/mrivera, user/psantos, role/CIDeploy.
- Not asked: user/ssarkar, user/mjackson, role/DataPipeline.

Keep: OnlyTheDataTeam in the customer data bucket's policy. It's all that stops SupportAccess,
VendorReadOnly and AdministratorAccess here.

Maps to:
- NIST SP 800-53 Rev. 5 AC-3: Access Enforcement. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-53 Rev. 5 AC-6: Least Privilege. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- SOC 2 (AICPA TSC 2017) CC6.1: Logical access controls and authentication.
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
- SOC 2 (AICPA TSC 2017) CC6.3: Role-based access and least privilege.
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

## PASS: Only the on-call admin role can change the customer data bucket's policy (high)

Asked: Can anyone but role/OnCallAdmin do s3:PutBucketPolicy or s3:DeleteBucketPolicy on
arn:aws:s3:::anycompany-prod-customer-data?

- Can't: user/mrivera, user/psantos, user/ssarkar, user/mjackson, user/jsouza, user/nwolf,
  role/CIDeploy, role/VendorMonitoring, role/DataPipeline.
- Not asked: role/OnCallAdmin.

Keep: No policy but OnCallAdmin's AdministratorAccess allows s3:PutBucketPolicy or
s3:DeleteBucketPolicy on anycompany-prod-customer-data.

Maps to:
- NIST SP 800-53 Rev. 5 AC-6(1): Authorize Access to Security Functions.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- SOC 2 (AICPA TSC 2017) CC6.3: Role-based access and least privilege.
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

## PASS: No one can turn off audit logging (high)

Asked: Can anyone do cloudtrail:StopLogging or cloudtrail:DeleteTrail on
arn:aws:cloudtrail:us-east-1:111122223333:trail/prod-audit?

- role/OnCallAdmin can't. Denied by ProtectAuditLogging, Sid NoAuditLoggingChanges, an SCP on the
  root. The Deny overrides AdministratorAccess, statement 0, attached directly. Without this Deny,
  the request would be allowed.
- Can't: user/mrivera, user/psantos, user/ssarkar, user/mjackson, user/jsouza, user/nwolf,
  role/CIDeploy, role/VendorMonitoring, role/DataPipeline.

Keep: ProtectAuditLogging on the organization root, which denies cloudtrail:StopLogging and
cloudtrail:DeleteTrail in every member account, OnCallAdmin included.

Maps to:
- NIST SP 800-53 Rev. 5 AU-9: Protection of Audit Information.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- SOC 2 (AICPA TSC 2017) CC7.2: Monitoring systems for anomalies.
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

## Findings

### HIGH: An MFA Deny skips requests made with access keys

- In: RequireMfaForCustomerData, Sid DenyCustomerDataWithoutMfa: an identity policy attached to
  group/Data.
- Condition: Bool aws:MultiFactorAuthPresent: false.
- Impact: It doesn't stop group/Data from doing s3:GetObject on
  arn:aws:s3:::anycompany-prod-customer-data/* in requests made with long-term access keys.
- Why: The Deny uses Bool on aws:MultiFactorAuthPresent. Requests signed with long-term access keys
  don't include that key at all, and Bool fails on a missing key, so the Deny doesn't apply to them.
- Evidence: AWS: "The aws:MultiFactorAuthPresent key is not present when an API or CLI command is
  called with long-term credentials, such as user access key pairs. Therefore we recommend that when
  you check for this key that you use the ...IfExists versions of the condition operators."
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-multifactorauthpresent
- Fix: In a user's policy, use BoolIfExists aws:MultiFactorAuthPresent false, which also applies
  when the key is missing. Don't put an MFA Deny in a role's own policies: AWS says a role's
  credentials carry no MFA information, so it could lock the role out of everything the Deny covers.
  Require MFA in the role's trust policy instead.

### MEDIUM: Another account can assume the role without an external ID

- In: the trust policy of arn:aws:iam::111122223333:role/VendorMonitoring, Sid MonitoringVendor.
- Principal: arn:aws:iam::444455556666:root.
- Impact: It lets arn:aws:iam::444455556666:root assume
  arn:aws:iam::111122223333:role/VendorMonitoring without giving an external ID.
- Why: The trust policy lets an account outside the organization assume the role with no
  sts:ExternalId condition. If that account is a third party serving several customers, anyone it
  serves could get it to use this role: the confused deputy problem.
- Evidence: AWS: "The primary function of the external ID is to address and prevent The confused
  deputy problem."
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html#id_roles_third-party_external-id
- Fix: Add a condition such as StringEquals sts:ExternalId with the ID the third party gives you.

## Scope and limits

- A PASS covers only the 6 users and 4 roles in anycompany-production.json. Requests from other
  accounts, anonymous requests and federated users aren't evaluated; a policy that lets them in
  makes a check CAN'T TELL.
- Each check covers exactly the requests it lists: its actions, its resources, and the condition
  keys it gives.
- Keys whose every value AWS documents are tried with each one: aws:MultiFactorAuthPresent (true,
  false, absent); aws:SecureTransport (true, false); aws:ViaAWSService (true, false). Any other key
  a statement needs is CAN'T TELL until a check gives it a value.
- SCPs come from anycompany.json.
- Not modeled: session policies, resource control policies and VPC endpoint policies, which can only
  take access away, so a PASS of a "can" check means the files allow it; S3 Block Public Access; and
  ACLs, which described buckets have disabled.
- A role's requests are asked about as they are. The one exception is a check that requires MFA: AWS
  checks MFA for a role when it's assumed, so a role allowed without MFA is asked who can assume it
  without MFA. That second question goes one level deep.
