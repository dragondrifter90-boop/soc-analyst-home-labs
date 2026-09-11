# LAB-003 Investigation Report

## Summary

| Field | Value |
|---|---|
| Incident ID | Hunting investigation |
| Title | Internet-facing RDP brute force attempts |
| Severity | Medium |
| Status | Closed |
| Classification | True Positive - Suspicious Activity |
| Analyst | Mohamed Hayyane |
| Investigation start | 2026-08-01 |
| Investigation end | 2026-08-28 |

## Scenario and Objective

This investigation reviewed real failed RDP authentication attempts against the
lab Windows VM from unknown external IP addresses. The objective was to identify
the suspicious sources, confirm whether any successful authentication occurred,
and document hardening actions.

## Telemetry Requirements

| Source | Requirement |
|---|---|
| Sentinel table | `SecurityEvent` |
| Failed logon event | `4625` |
| Successful logon event | `4624` |
| Optional post-login events | `4672`, `4688`, `4720`, `4732`, `4697`, `1102` |

## Detection Logic

Rule draft:
`detections/analytics-rules/lab-003-internet-facing-rdp-bruteforce.yaml`

The simple detection searches for 20 or more failed logons from the same source
IP within the rule lookup period, excluding the known legitimate public IP.

## Investigation

### Initial Triage

Questions to answer:

- Which source IPs generated repeated failed logons?
- Which usernames were targeted?
- Were the attempts from a known legitimate source?
- Did any suspicious IP successfully authenticate?
- Was there any evidence of post-authentication activity?

### Timeline

| Time UTC | Event | Entity | Analyst interpretation |
|---|---|---|---|
| 2026-07-26 14:13:32-14:14:59 | 74 x `4625` | `<SUSPICIOUS_IP_1>` | Repeated failures against Administrator |
| 2026-07-28 10:45:05-10:45:51 | 37 x `4625` | `<SUSPICIOUS_IP_2>` | Password guessing across many usernames |
| 2026-07-28 11:08:39-11:09:24 | 37 x `4625` | `<SUSPICIOUS_IP_3>` | Password guessing across many usernames |

### Queries Used

- `attacker_ips.csv`
- `failure_pattern.csv`
- `targeted_usernames.csv`
- Successful-logon check for suspicious IPs returned no `4624` events.

### Findings

- Three suspicious external source IPs generated repeated failed logons.
- `<SUSPICIOUS_IP_1>` generated 74 failed attempts against Administrator-style
  account names in under two minutes.
- `<SUSPICIOUS_IP_2>` generated 37 failed attempts across many guessed usernames.
- `<SUSPICIOUS_IP_3>` generated 37 failed attempts across many guessed usernames.
- The legitimate public IP `<LEGITIMATE_IP>` generated only low-volume failed
  attempts for the known user and was separated from suspicious sources.
- No successful `4624` logon events were observed from the suspicious IPs.
- No evidence of compromise was identified from the suspicious sources.

### Observed Indicators

The three external addresses are intentionally represented as placeholders.
They were point-in-time observations, not attribution, and should not be
reused as active threat-intelligence indicators.

## Verdict

True Positive - Suspicious Activity.

The failed logon activity was real and unauthorized. The investigation did not
identify successful authentication or compromise from the suspicious IPs.

## Response and Recovery

Actions and recommendations:

- RDP was restricted to the known legitimate source IP.
- Prefer Azure Bastion, Just-in-Time VM access, or VPN.
- Keep monitoring repeated failed logons from unknown IP addresses.
- Consider disabling or renaming the built-in Administrator account.
- Ensure strong passwords and account lockout policy are configured.

## Detection Improvements

Potential tuning:

- Exclude known legitimate IP addresses.
- Alert only when failures exceed a threshold within a short time window.
- Track distinct usernames attempted by the same source IP.
- Increase severity if a successful logon follows failed attempts from the same
  source IP.

## MITRE ATT&CK Mapping

| Tactic | Technique | Reason |
|---|---|---|
| Credential Access | T1110 - Brute Force | Repeated failed authentication attempts |
| Credential Access | T1110.001 - Password Guessing | Common usernames were guessed over RDP |

## Lessons Learned

- Internet-facing RDP can receive real password-guessing traffic quickly, even
  in a small lab environment.
- Failed logons from unknown IPs should be checked against successful `4624`
  events before deciding whether compromise occurred.
- A true positive suspicious-activity classification can still mean
  unsuccessful activity. True positive means the detection matched real
  suspicious behavior, not necessarily that the attacker succeeded.
- Reducing exposure, such as limiting RDP to a known IP, is a valid response
  action even when no compromise is found.
