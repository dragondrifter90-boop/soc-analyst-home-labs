# Tier 1 Investigation Checklist

Use this checklist when investigating failed Windows logons followed by a
successful logon.

## 1. Alert Intake

- Record incident number, title, severity, status, and owner.
- Identify the alert rule that fired.
- Read the rule description and query logic.
- Record the incident creation time and alert time in UTC.

## 2. Entity Review

Record the key entities:

- Account
- Host
- Source IP address

Ask:

- Is the account expected to log on to this host?
- Is the account privileged?
- Is the source IP expected or unusual?
- Is the host internet-exposed or restricted?

## 3. Evidence Validation

Confirm the alert with raw logs:

- Count failed logons.
- Record first and last failure time.
- Confirm the failure reason or `SubStatus`.
- Confirm a later successful logon.
- Confirm account, source IP, and host match.

For this lab, `SubStatus == 0xc000006a` means the username was valid but the
password was incorrect.

## 4. Scope Check

Determine whether the activity is isolated:

- Did the source IP target more than one account?
- Did the source IP target more than one host?
- Did the account fail or succeed from other IP addresses?
- Are there similar incidents around the same time?

## 5. Post-Login Activity

If authentication succeeded, check what happened afterward:

- `4672`: special privileges assigned
- `4688`: process execution
- `4720`: local user created
- `4732`: user added to local group
- `4697`: service installed
- `1102`: security log cleared

Separate normal Windows session activity from suspicious commands or
administrative changes.

## 6. Classification

Choose a classification and explain it:

- True positive, malicious
- True positive, benign authorized activity
- False positive
- Benign positive

## 7. Response

Recommended actions depend on classification:

- Confirm with user or asset owner.
- Reset password if unauthorized.
- Disable account if compromise is likely.
- Block source IP if malicious.
- Escalate if privileged access, suspicious commands, or lateral movement are
  observed.
- Close with clear notes if authorized lab activity.

