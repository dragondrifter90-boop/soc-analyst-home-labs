# LAB-001 Investigation Report

## Summary

| Field | Value |
|---|---|
| Incident ID | 5 |
| Title | Failed Windows logons followed by successful logon |
| Severity | Medium |
| Status | Closed |
| Classification | Benign Positive - Suspicious but Expected Activity |
| Analyst | Mohamed Hayyane |
| Investigation start | 2026-07-18 13:46 UTC |
| Investigation end | 2026-07-26 12:10 UTC |

## Scenario and Objective

This lab simulates repeated failed RDP authentication attempts against a
dedicated Windows test account, followed by a successful logon. The objective is
to detect a possible password-guessing sequence and investigate whether the
success represents compromise, benign activity, or expected lab simulation.

## Telemetry Requirements

| Source | Requirement |
|---|---|
| Sentinel table | `SecurityEvent` |
| Failed logon event | `4625` |
| Successful logon event | `4624` |
| Optional privilege event | `4672` |
| Optional process event | `4688` |

## Detection Logic

Rule draft:
`detections/analytics-rules/lab-001-failed-logons-followed-by-success.yaml`

The detection searches for at least five failed logons followed by a successful
logon for the same normalized account, source IP, and target host. The tuned
version requires the failures to occur inside a 10-minute failure window and
the success to occur within 30 minutes after the last failure.

## Investigation

### Initial Triage

Questions to answer:

- Did the failures and success target the same account?
- Did they come from the same source IP?
- Was the successful logon consistent with RDP activity?
- Was there any privileged logon or suspicious process execution afterward?

### Timeline

| Time UTC | Event | Entity | Analyst interpretation |
|---|---|---|---|
| 2026-07-10 09:47:29 | `4624`, LogonType `3` | `<TEST_USER>` on `<TARGET_VM>` | RDP Network Level Authentication succeeded |
| 2026-07-10 09:47:31 | `4624`, LogonType `3` | `<TEST_USER>` on `<TARGET_VM>` | Additional network logon event during RDP setup |
| 2026-07-10 09:47:33 | `4624`, LogonType `10` | `<TEST_USER>` on `<TARGET_VM>` | Remote interactive RDP session created |
| 2026-07-10 09:56:54-09:57:30 | 9 x `4625`, LogonType `3` | `<TEST_USER>` from `<SOURCE_IP>` | Repeated failed RDP/NLA authentication attempts |
| 2026-07-10 09:57:45 | `4624`, LogonType `3` | `<TEST_USER>` from `<SOURCE_IP>` | Successful authentication after failure burst |
| 2026-07-10 09:57:47 | `4624`, LogonType `3` | `<TEST_USER>` from `<SOURCE_IP>` | Additional successful network logon during session setup |
| 2026-07-10 09:57:49 | `4624`, LogonType `7` | `<TEST_USER>` from `<SOURCE_IP>` | Existing session unlocked after successful authentication |
| 2026-07-18 12:10:02 | `4624`, LogonType `10` | `<TEST_USER>` on `<TARGET_VM>` | Baseline successful RDP session confirmed |
| 2026-07-18 12:15:06-12:15:22 | 5 x `4625`, LogonType `3` | `<TEST_USER>` from `<SOURCE_IP>` | Repeated bad-password attempts |
| 2026-07-18 12:15:38 | `4624`, LogonType `3` | `<TEST_USER>` from `<SOURCE_IP>` | Successful authentication after failures |
| 2026-07-18 12:15:43 | `4624`, LogonType `7` | `<TEST_USER>` from `<SOURCE_IP>` | Session unlock/reconnect after successful authentication |
| 2026-07-18 13:46:18-13:53:16 | 6 x `4688` | `<TARGET_VM>` | Post-login process activity reviewed; no suspicious command observed |

### Queries Used

- `detections/hunting-queries/lab-001-failed-logons-followed-by-success.kql`
- `Validate_The_Evidence.csv`
- `Determine_Scope.csv`
- `Check_Post-Login_Activity.csv`

Query results:

- Query 1 returned 15 raw authentication events for the lab user.
- Query 2 summarized 9 failed logons from one source IP to one host.
- Query 3 correlated those failures with later successful logons and returned
  one incident-style row after summarizing multiple success events.
- Sentinel incident entity review showed one account, one host, and one source
  IP address.
- Validation query for the triggered incident returned 11 authentication
  events.
- Scope query showed one source IP, one host, and the test account only.
- Post-login query returned six process-creation events.

### Findings

- Dedicated test user was created successfully.
- A successful RDP login generated `4624` events in Sentinel.
- Observed RDP/NLA pattern: successful authentication created LogonType `3`
  events followed by a LogonType `10` remote interactive session.
- Failed-authentication simulation generated 9 `4625` events.
- All failed attempts used LogonType `3`, AuthenticationPackageName `NTLM`,
  Status `0xc000006d`, and SubStatus `0xc000006a`.
- SubStatus `0xc000006a` indicates the username was valid but the password was
  incorrect.
- The same source then produced successful `4624` events for the same test
  account.
- The final success showed LogonType `7` instead of a new LogonType `10`,
  consistent with unlocking or reconnecting to an existing RDP session.
- Query 3 initially returned three rows because Windows generated multiple
  successful logon events after authentication. The detection was adjusted to
  summarize the success side into one result per account, host, and source IP.
- Final detection result:
  - Failed attempts: 9
  - First failure: 2026-07-10 09:56:54 UTC
  - Last failure: 2026-07-10 09:57:30 UTC
  - First success: 2026-07-10 09:57:45 UTC
  - Successful logon types: `3 - Network`, `7 - Unlock`
- Triggered Sentinel incident result:
  - Failed attempts: 5
  - First failure: 2026-07-18 12:15:06 UTC
  - Last failure: 2026-07-18 12:15:22 UTC
  - First success: 2026-07-18 12:15:38 UTC
  - Scope: one source IP, one host, test account only
  - Post-login review: normal Windows and Azure guest-agent process activity
    observed; no suspicious process, account creation, group change, service
    installation, or security-log clearing was identified in the reviewed data.

## Verdict

Benign Positive - Suspicious but Expected Activity.

The analytics rule worked as intended. It detected repeated failed logons
against the lab test account followed by successful authentication from the
same source IP to the same Windows host. The activity was performed by the lab
owner as an authorized simulation.

## Response and Recovery

Completed actions:

- Confirm activity was generated by the authorized lab source.
- Log off the RDP session.
- Reset or disable the test account if no longer needed.
- Restrict RDP exposure after the test.
- Closed the incident as `Benign Positive - Suspicious but Expected Activity`.

## Detection Improvements

Potential tuning:

- Exclude known scanner or administrator source IPs if needed.
- Require successful `LogonType == 10` when focusing specifically on RDP.
- Add `4672` and `4688` follow-up queries for post-logon behavior.
- Add the Tier 1 investigation checklist to standardize future incident work.
- Current tuning uses fixed 10-minute bins. A future advanced version could use
  a sliding window to avoid missing bursts that cross a bin boundary.

## MITRE ATT&CK Mapping

| Tactic | Technique | Reason |
|---|---|---|
| Credential Access | T1110 - Brute Force | Repeated authentication attempts against one account |

## Lessons Learned

- Validated the alert by reviewing raw `4624` and `4625` events.
- Confirmed how RDP/NLA appears in Windows Security logs.
- Practiced entity review, scope determination, post-login review, and
  classification.
- Learned that successful RDP activity can create multiple `4624` events, so
  analysts should interpret the timeline instead of counting each success as a
  separate user action.
