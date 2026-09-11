# LAB-002 Investigation Report

## Summary

| Field | Value |
|---|---|
| Incident ID | 12 |
| Title | Local user added to Administrators |
| Severity | Medium |
| Status | Closed |
| Classification | Benign Positive - Suspicious but Expected Activity |
| Analyst | Mohamed Hayyane |
| Investigation start | 2026-07-28 12:02 UTC |
| Investigation end | 2026-07-28 11:36 UTC |

## Scenario and Objective

This lab simulates local account creation followed by adding the account to the
local Administrators group. The objective is to detect and investigate a
possible persistence or privilege-escalation action.

## Telemetry Requirements

| Source | Requirement |
|---|---|
| Sentinel table | `SecurityEvent` |
| User created | `4720` |
| User enabled | `4722` |
| Added to local group | `4732` |
| Optional process creation | `4688` |
| Cleanup events | `4733`, `4726` |

## Detection Logic

Rule draft:
`detections/analytics-rules/lab-002-local-admin-user-created.yaml`

The first Tier 1 detection alerts when a member is added to the local
Administrators group. During investigation, the analyst reviews nearby account
creation events and compares `4720.TargetSid` with `4732.MemberSid`.

## Investigation

### Initial Triage

Questions to answer:

- What account was created?
- Who created the account?
- Was the account added to Administrators?
- Was the action expected or authorized?
- Was suspicious command-line activity observed nearby?

### Timeline

| Time UTC | Event | Entity | Analyst interpretation |
|---|---|---|---|
| 2026-07-26 12:39:34.971 | `4720` | `soc_lab_admin_test` | Local account created by `<ACTING_USER>` |
| 2026-07-26 12:39:34.973 | `4722` | `soc_lab_admin_test` | Local account enabled |
| 2026-07-26 12:39:35.200 | `4732` | `Builtin\Administrators` | Member added to local Administrators group |
| 2026-07-28 10:45:18.498 | `4720` | `soc_lab_admin_test-2` | Local account created by `<ACTING_USER>` |
| 2026-07-28 10:45:18.501 | `4722` | `soc_lab_admin_test-2` | Local account enabled |
| 2026-07-28 10:45:18.734 | `4732` | `Builtin\Administrators` | Created account SID added to Administrators |
| 2026-07-28 11:20:49.417 | `4733` | `soc_lab_admin_test-2` | Test account removed from Administrators |
| 2026-07-28 11:20:49.436 | `4726` | `soc_lab_admin_test-2` | Test account deleted |
| 2026-07-28 11:27:10.662 | `4733` | `soc_lab_admin_test` | Earlier test account removed from Administrators |
| 2026-07-28 11:27:10.672 | `4726` | `soc_lab_admin_test` | Earlier test account deleted |
| 2026-07-28 12:02:33 | Sentinel incident | `<ACTING_USER>`, `<TARGET_VM>` | Analytics rule generated Incident 12 |

### Queries Used

- `detections/hunting-queries/lab-002-local-admin-user-created.kql`
- `Raw account-management.csv`
- `Users-added-to-the-local.csv`
- `Lab_2_query_3.csv`
- `lab-2-validate-the-raw-evidence.csv`
- `lab-2-cleanup.csv`

### Findings

- Event `4720` shows local account `soc_lab_admin_test` was created on
  `<TARGET_VM>`.
- Event `4722` shows local account `soc_lab_admin_test` was enabled.
- Event `4732` shows a member was added to `Builtin\Administrators`.
- The acting account for all three events was `<ACTING_USER>`.
- `4720.TargetSid` for `soc_lab_admin_test` matched `4732.MemberSid`, proving
  the newly created account was the member added to Administrators.
- `4732.MemberName` appeared as `-`, so SID comparison was required.
- Query 4 searched for obvious command-line evidence such as `New-LocalUser`,
  `Add-LocalGroupMember`, `net user`, and `net localgroup`, but returned no
  results.
- This means the account-management events prove the change occurred, but the
  current process query did not identify the exact command or tool used.
- Broader process review was filtered to the acting account to reduce system
  account noise.
- Query 5 returned 17 process-creation events for `<ACTING_USER>` around the
  simulation time.
- `powershell_ise.exe` launched at 2026-07-26 12:37:39 UTC, approximately two
  minutes before the account creation and Administrators group-add events.
- No captured command line directly showed `New-LocalUser`,
  `Add-LocalGroupMember`, `net user`, or `net localgroup`.
- The simplified Sentinel analytics rule generated Incident 12 after the
  `soc_lab_admin_test-2` simulation.
- The incident mapped the acting account and target host as entities.
- Validation for Incident 12 showed the sequence `4720 -> 4722 -> 4732`.
- The action was performed by `<ACTING_USER>`.
- Event `4720` showed `soc_lab_admin_test-2` was created with SID
  `<CREATED_USER_SID>`.
- Event `4732` showed `MemberSid` as the same `<CREATED_USER_SID>`, proving the
  created account was added to `Builtin\Administrators`.
- Cleanup generated `4733` and `4726` events for both test accounts.
- `soc_lab_admin_test-2` was removed from Administrators and deleted.
- `soc_lab_admin_test` was removed from Administrators and deleted.

## Verdict

Benign Positive - Suspicious but Expected Activity.

The analytics rule worked as intended. It detected a member being added to the
local Administrators group on the lab Windows host. Investigation confirmed
that the member SID belonged to a newly created lab account. The activity was
performed as an authorized lab simulation and was cleaned up.

## Response and Recovery

Completed actions:

- Confirm activity was generated by the authorized lab operator.
- Remove the account from Administrators.
- Delete the test account after evidence is collected.
- Removed and deleted both LAB-002 test accounts.
- Closed the incident as `Benign Positive - Suspicious but Expected Activity`.

## Detection Improvements

Potential tuning:

- Exclude known provisioning scripts if they create local admin accounts.
- Alert with higher severity if the acting account is not expected to manage
  local administrators.
- Add process-command review for `net user`, `net localgroup`, PowerShell, or
  suspicious parent processes.
- Add broader process review around the event time when exact command-line
  searches return no results.
- Consider adding PowerShell Script Block Logging for future labs so commands
  entered in PowerShell ISE are easier to review.
- Future advanced tuning: automatically correlate `4720.TargetSid` with
  `4732.MemberSid`.

## MITRE ATT&CK Mapping

| Tactic | Technique | Reason |
|---|---|---|
| Persistence | T1136.001 - Create Account: Local Account | A new local account was created |
| Privilege Escalation | T1078 - Valid Accounts | The account was granted local administrator access |

## Lessons Learned

- Validated local account creation using event `4720`.
- Validated account enablement using event `4722`.
- Validated local Administrators group membership change using event `4732`.
- Learned that `4732.MemberName` can appear as `-`, requiring SID comparison.
- Practiced comparing `4720.TargetSid` with `4732.MemberSid` to prove which
  account was added to Administrators.
- Practiced cleanup validation using `4733` and `4726`.
- Learned to reduce noisy process-review results by filtering to the acting
  user account.
