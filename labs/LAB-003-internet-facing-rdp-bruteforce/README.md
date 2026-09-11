# LAB-003: Internet-Facing RDP Brute Force Attempts

## Status

Completed

## Objective

Investigate real failed RDP authentication attempts against the lab Windows VM,
confirm whether any suspicious source IP successfully authenticated, and
document hardening actions.

This lab is based on real external activity observed in the lab environment.
It should be handled as defensive investigation evidence, not as a simulation
that we intentionally generated.

## Lab Metadata

| Field | Value |
|---|---|
| Difficulty | Tier 1 |
| Telemetry level | Current SecurityEvent telemetry |
| Tools used | Sentinel hunting, Azure NSG hardening |
| Threat-informed focus | Internet-facing RDP password guessing |
| Concepts course | `concepts.md` |

## Required Telemetry

- Sentinel table: `SecurityEvent`
- Failed logon event: `4625`
- Successful logon event: `4624`
- Optional post-login review: `4672`, `4688`, `4720`, `4732`, `4697`, `1102`

## Scenario Story

The Windows VM received repeated failed RDP/NLA authentication attempts from
external IP addresses that were not the lab owner's known public IP. The
attempts targeted common usernames such as `Administrator`, `admin`, and other
guessed account names. The analyst must determine whether the activity remained
unsuccessful or resulted in compromise.

## Indicator Handling

The lab owner's known public IP during this investigation is documented
privately and should be sanitized before publication.

The suspicious source IPs are included as point-in-time indicators observed in
this lab. They should not be treated as attribution or as permanently malicious
infrastructure without fresh threat-intelligence validation.

```text
<LEGITIMATE_IP>
```

## Investigation Workflow

1. Identify source IPs with failed logons.
2. Separate the known legitimate IP from unknown external IPs.
3. Review targeted usernames.
4. Confirm whether suspicious IPs had any successful logons.
5. Check for post-authentication activity.
6. Classify the incident.
7. Apply hardening, especially RDP exposure reduction.

## Queries And Rules

- Hunting query: `detections/hunting-queries/lab-003-internet-facing-rdp-bruteforce.kql`
- Analytics rule draft: `detections/analytics-rules/lab-003-internet-facing-rdp-bruteforce.yaml`
- Report draft: `labs/LAB-003-internet-facing-rdp-bruteforce/investigation-report.md`
- Concepts course: `labs/LAB-003-internet-facing-rdp-bruteforce/concepts.md`

## Investigation Questions

- Which IPs generated the most failed logons?
- Which accounts were targeted?
- Did any suspicious IP produce a successful `4624` event?
- Did any targeted account later log in successfully from another suspicious
  source?
- Was there any privileged logon or suspicious process activity afterward?
- Is RDP exposed to the internet?
- What hardening should be applied?

## Recommended Hardening

- Restrict RDP to the current known public IP.
- Prefer Azure Bastion, Just-in-Time VM access, or VPN over public RDP.
- Disable or rename the built-in Administrator account where appropriate.
- Use strong passwords and account lockout policy.
- Monitor repeated failed logons from unknown IP addresses.

## MITRE ATT&CK

- Tactic: Credential Access
- Technique: T1110 - Brute Force
- Sub-technique: T1110.001 - Password Guessing

## Success Criteria

- Suspicious source IPs are identified.
- Targeted usernames are summarized.
- No successful logons from suspicious IPs are confirmed.
- Hardening recommendations are documented.
- The incident is classified accurately.

Completed result:

- Three suspicious external source IPs were identified.
- No successful `4624` logons from suspicious IPs were observed.
- RDP exposure was reduced by restricting access to the known legitimate
  public IP.
