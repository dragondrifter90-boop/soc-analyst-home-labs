# SOC Analyst Home Labs

Hands-on Microsoft Sentinel and Windows security investigation portfolio by
Mohamed HAYYANE. This repository documents five completed SOC labs, from raw
Windows telemetry to incident triage, classification, hardening and detection
tuning.

## What this portfolio demonstrates

- Microsoft Sentinel investigation using `SecurityEvent` telemetry and Windows
  Security event IDs.
- Alert validation, entity and scope analysis, post-compromise checks and
  clear incident classification.
- Threat-informed analysis with MITRE ATT&CK mappings.
- Practical detection tuning: reducing noisy Windows service results,
  correlating Windows SIDs, and interpreting RDP/NLA logon types.
- Safe, authorized lab simulations and disciplined cleanup.

## Labs

| Lab | Scenario | Core telemetry | MITRE ATT&CK | Outcome |
|---|---|---|---|---|
| [LAB-001](labs/LAB-001-failed-logons/README.md) | Failed logons followed by success | `4625`, `4624`, `4688` | T1110 | Benign-positive simulation; correlation and post-logon triage |
| [LAB-002](labs/LAB-002-local-admin-user-created/README.md) | Local user created and added to Administrators | `4720`, `4722`, `4732` | T1136.001, T1078 | Benign-positive simulation; SID correlation |
| [LAB-003](labs/LAB-003-internet-facing-rdp-bruteforce/README.md) | Internet-facing RDP password guessing | `4625`, `4624` | T1110, T1110.001 | True-positive suspicious activity; no successful attacker logon |
| [LAB-004](labs/LAB-004-suspicious-powershell-encoded-command/README.md) | Encoded PowerShell command | `4688` | T1059.001, T1027 | Controlled detection and incident investigation |
| [LAB-005](labs/LAB-005-service-installed-for-persistence/README.md) | Windows service persistence | `4697`, `4688` | T1543.003 | Controlled detection, baseline analysis and tuning |

## Visual evidence

Eight privacy-reviewed Sentinel and Defender screenshots show the incident
workflow and KQL evidence behind the labs. See the
[evidence gallery](evidence/README.md).

## Evidence and safety boundaries

All activities were performed on authorized personal lab assets. Host names,
user identities, IP addresses, workspace details and other sensitive values
are replaced with placeholders. LAB-003 records real unsolicited traffic
observed against the isolated lab VM; it does not attribute activity or claim
that an indicator is permanently malicious.

The labs use harmless commands only. They do not include malware, payloads,
credentials, exploit code or live cloud access information.

## Repository scope

Each lab includes its scenario, telemetry requirements, investigation report
and learning notes. LAB-001 also includes a reusable Tier 1 investigation
checklist; LAB-005 includes a threat brief. Several documents reference the
original hunting-query and analytics-rule drafts used during the lab. Those
draft files were not present in this portfolio snapshot, so this repository
does not claim to ship them.

## Reading order

Start with a lab `README.md`, then read `investigation-report.md` to see the
analyst workflow and verdict. Open `concepts.md` for the event-level and KQL
concepts behind the investigation.

## Responsible use

Use these materials only for defensive learning and on systems you own or are
authorized to test. Microsoft Sentinel, Windows and MITRE ATT&CK are trademarks
of their respective owners.
