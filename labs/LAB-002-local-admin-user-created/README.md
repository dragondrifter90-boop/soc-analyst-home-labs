# LAB-002: Local User Created and Added to Administrators

## Status

Completed

## Objective

Detect and investigate a local Windows user account being created and then
added to the local Administrators group.

This lab simulates a common attacker behavior: creating or enabling a local
account and granting it administrative privileges for persistence or privilege
escalation.

## Lab Metadata

| Field | Value |
|---|---|
| Difficulty | Tier 1 |
| Telemetry level | Current SecurityEvent telemetry |
| Tools used | Native Windows PowerShell |
| Threat-informed focus | Local account persistence and privilege escalation |
| Concepts course | `concepts.md` |

## Required Telemetry

- Sentinel table: `SecurityEvent`
- Windows events: `4720`, `4722`, `4732`
- Optional cleanup events: `4733`, `4726`
- Optional process event: `4688`
- Source and target must be authorized lab assets

## Scenario Story

An administrator-level user creates a new local account on the Windows VM, then
adds that account to the local Administrators group. A SOC analyst must
determine whether this was expected administration, suspicious privilege
escalation, or authorized lab activity.

## Assets

| Role | Placeholder | Notes |
|---|---|---|
| Target host | `<TARGET_VM>` | Windows VM connected to Sentinel |
| Acting user | `<ACTING_USER>` | User that creates the account |
| New user | `soc_lab_admin_test`, `soc_lab_admin_test-2` | Disposable accounts for LAB-002 |
| Privileged group | `Administrators` | Local admin group |

## Preparation

1. Confirm the Windows VM is sending `SecurityEvent` logs.
2. Confirm the current user can run PowerShell as Administrator.
3. Use a dedicated test account name, such as `soc_lab_admin_test`.
4. Record the planned simulation start time in UTC.

## Simulation Plan

Run the simulation from PowerShell as Administrator on the Windows VM:

```powershell
$Password = Read-Host "Enter temporary password" -AsSecureString

New-LocalUser `
  -Name "soc_lab_admin_test" `
  -Password $Password `
  -FullName "SOC LAB-002 Admin Test" `
  -Description "Temporary account for Sentinel LAB-002"

Add-LocalGroupMember `
  -Group "Administrators" `
  -Member "soc_lab_admin_test"
```

Expected event pattern:

```text
4720 - A user account was created
4722 - A user account was enabled
4732 - A member was added to a security-enabled local group
```

Event `4732` should show the user being added to the local Administrators
group.

In this lab environment, event `4732` may show `MemberName` as `-`. The added
account can still be correlated by matching the created user's `TargetSid` from
event `4720` with `MemberSid` from event `4732`.

For the first Tier 1 version of this lab, the analytics rule is intentionally
simple: it alerts when any member is added to the local Administrators group.
During investigation, the analyst reviews nearby `4720` and `4732` events and
manually compares `TargetSid` with `MemberSid`. A future advanced version can
automate this SID correlation.

## Safety Controls

- Run only on the lab Windows VM.
- Use only the disposable account `soc_lab_admin_test`.
- Do not use this account for personal work.
- Remove the account during cleanup.

## Planned Workflow

1. Generate the local account creation and group-add events.
2. Validate the raw Windows account-management events.
3. Review process creation around the event time.
4. Build a simple hunting query.
5. Create a scheduled analytics rule.
6. Trigger and investigate the Sentinel incident.
7. Clean up the account and document the result.

## Queries And Rules

- Hunting query: `detections/hunting-queries/lab-002-local-admin-user-created.kql`
- Analytics rule draft: `detections/analytics-rules/lab-002-local-admin-user-created.yaml`
- Report draft: `labs/LAB-002-local-admin-user-created/investigation-report.md`
- Concepts course: `labs/LAB-002-local-admin-user-created/concepts.md`

## Investigation Questions

- Who created the local account?
- What account was created?
- Was the account enabled?
- Was the account added to Administrators?
- Was the acting user expected to perform this action?
- Was there suspicious command-line activity nearby?
- Was this expected admin activity, malicious, or authorized lab activity?

## Cleanup

Run from PowerShell as Administrator:

```powershell
Remove-LocalGroupMember `
  -Group "Administrators" `
  -Member "soc_lab_admin_test" `
  -ErrorAction SilentlyContinue

Remove-LocalUser `
  -Name "soc_lab_admin_test" `
  -ErrorAction SilentlyContinue
```

Expected cleanup events:

```text
4733 - A member was removed from a security-enabled local group
4726 - A user account was deleted
```

## MITRE ATT&CK

- Tactic: Persistence
- Technique: T1136.001 - Create Account: Local Account
- Tactic: Privilege Escalation
- Technique: T1078 - Valid Accounts

## Success Criteria

- Raw events show a local user was created and added to Administrators.
- The hunting query shows account creation and Administrators group-add events.
- The Sentinel analytics rule creates one understandable alert or incident.
- The investigation report explains the evidence and final verdict.
