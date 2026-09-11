# LAB-001: Failed Logons Followed by Successful Logon

## Status

Completed

## Objective

Detect and investigate repeated failed Windows authentication attempts followed
by a successful logon to the same account.

This lab intentionally generates the relevant logon activity during the
exercise. It does not depend on historical Sentinel retention.

## Lab Metadata

| Field | Value |
|---|---|
| Difficulty | Tier 1 |
| Telemetry level | Current SecurityEvent telemetry |
| Tools used | Native Windows RDP |
| Threat-informed focus | Password guessing and suspicious successful logon |
| Concepts course | `concepts.md` |

## Required Telemetry

- Sentinel table: `SecurityEvent`
- Windows events: `4625` and `4624`
- Source and target must be authorized lab assets
- RDP enabled only for the authorized lab source
- Dedicated local test account recommended

## Scenario Story

An external source repeatedly attempts to authenticate to the Windows VM over
RDP. Several attempts fail, then the same account successfully logs on. The SOC
analyst must determine whether this is a password-guessing attempt followed by
compromise, benign user error, or lab activity.

## Assets

| Role | Placeholder | Notes |
|---|---|---|
| Target host | `<TARGET_VM>` | Windows VM connected to Sentinel |
| Test user | `<TEST_USER>` | Local user created only for this lab |
| Source IP | `<SOURCE_IP>` | Authorized public IP or attacker VM |
| Workspace | `<WORKSPACE>` | Log Analytics workspace behind Sentinel |

## Preparation

1. Create a dedicated local Windows test user, such as `soc_test_user`.
2. Give the user only the permissions needed for RDP testing.
3. Confirm the account can log on successfully before the attack simulation.
4. Confirm Sentinel receives recent `4624` and `4625` events from the target.
5. Record the planned start time in UTC.

Do not use a personal or daily-driver account for the final portfolio version
of this lab.

## Simulation Plan

Generate this sequence from an authorized source:

1. One successful RDP logon with the test user to prove the account works.
2. Five to ten failed RDP logons using the correct username and wrong password.
3. One successful RDP logon using the correct password.
4. Optional: log off cleanly after the successful session.

With RDP Network Level Authentication, the failed attempts may appear as
`4625` with `LogonType == 3`, while the successful RDP session may create both
`4624` with `LogonType == 3` and `4624` with `LogonType == 10`.

## Safety Controls

- Run the test only against the lab VM.
- Avoid high-volume brute force. Five to ten failures is enough.
- Use a dedicated test account so lockout and cleanup are safe.
- Restrict inbound RDP to your authorized source where possible.
- Stop the simulation if unexpected accounts or systems appear in the data.

## Planned Workflow

1. Create or confirm a dedicated test account.
2. Generate normal successful authentication activity.
3. Generate repeated failed RDP authentication attempts.
4. Generate one successful RDP logon after the failures.
5. Validate event fields and logon types in Sentinel.
6. Develop a hunting query.
7. Create and test a scheduled analytics rule.
8. Triage and investigate the generated incident.
9. Clean up and document the result.

## Queries And Rules

- Hunting query: `detections/hunting-queries/lab-001-failed-logons-followed-by-success.kql`
- Analytics rule draft: `detections/analytics-rules/lab-001-failed-logons-followed-by-success.yaml`
- Report draft: `labs/LAB-001-failed-logons/investigation-report.md`
- Concepts course: `labs/LAB-001-failed-logons/concepts.md`

The first query version is intentionally simple for Tier 1 learning. The goal
is to understand the event timeline, count the failures, and then correlate a
later success. More advanced tuning can be added after the basic investigation
workflow is clear.

The tuned rule requires at least five failed logons inside a 10-minute failure
window, followed by a successful logon within 30 minutes. This is more realistic
than counting failures across the whole lookup period because it focuses on a
short password-guessing burst.

## Investigation Questions

- Which account was targeted?
- Which source IP generated the failures?
- Did a successful logon occur from the same source after the failures?
- Was the successful logon type consistent with RDP?
- Were privileged rights assigned after logon, such as event `4672`?
- Did the user run suspicious commands after logging on?
- Is this expected lab activity, user error, or a likely compromise?

## Cleanup

- Log off the RDP session.
- Disable or reset the test account if no longer needed.
- Remove temporary firewall or NSG exposure.
- Sanitize screenshots and exported evidence before committing.

## MITRE ATT&CK

- Tactic: Credential Access
- Technique: T1110 - Brute Force

## Success Criteria

- Raw events show repeated `4625` failures and a later `4624` success.
- The hunting query returns the generated sequence.
- The Sentinel analytics rule creates one understandable alert or incident.
- The investigation report explains the evidence and final verdict.
