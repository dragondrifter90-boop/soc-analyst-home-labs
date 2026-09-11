# LAB-005: Service Installed For Persistence

## Status

Completed

## Objective

Detect and investigate a new Windows service installation on the lab VM.

Attackers create Windows services to maintain persistence, run commands with
elevated privileges, or execute payloads remotely. In this lab, the service is
harmless, but the event pattern is realistic and important for SOC work.

## Lab Metadata

| Field | Value |
|---|---|
| Difficulty | Tier 1+ |
| Telemetry level | Current SecurityEvent telemetry |
| Tools used | Native Windows `sc.exe` |
| Threat-informed focus | Windows service creation for persistence |
| Threat brief | `threat-brief.md` |
| Concepts course | `concepts.md` |

## Required Telemetry

- Sentinel table: `SecurityEvent`
- Windows service installation event: `4697`
- Windows process creation event: `4688`
- Command-line logging for `4688` enabled
- Audit Security System Extension success auditing for `4697`

## Scenario Story

An administrator-level user creates a new Windows service on the lab VM. A SOC
analyst must identify who created it, what service was installed, what command
or binary it points to, and whether it is authorized.

## Safety Controls

- Run only on the lab Windows VM.
- Use a harmless command.
- Use a clearly named lab service.
- Do not download or execute payloads.
- Delete the service after the lab.

## Planned Simulation

Run from an elevated PowerShell or Command Prompt on the Windows VM:

```powershell
sc.exe create SOC-LAB-005-PersistenceTest binPath= "C:\Windows\System32\cmd.exe /c echo SOC-LAB-005 service test > C:\Windows\Temp\soc-lab-005-service.txt" start= demand
```

Optional start test:

```powershell
sc.exe start SOC-LAB-005-PersistenceTest
```

Cleanup:

```powershell
sc.exe delete SOC-LAB-005-PersistenceTest
Remove-Item -LiteralPath "C:\Windows\Temp\soc-lab-005-service.txt" -ErrorAction SilentlyContinue
```

## Expected Event Pattern

```text
4697 - A service was installed in the system
4688 - sc.exe process creation
Optional 4688 - cmd.exe if the service is started
```

## Current Evidence

- Defender incident: `46`
- Incident title: `LAB-005 - Windows service installed`
- Incident severity: Medium
- Incident status: Active, unclassified
- First activity: `2026-09-04 09:43:05 UTC`
- Last activity: `2026-09-04 09:51:40 UTC`
- `4697` service-install event arrived in Sentinel.
- Service name: `SOC-LAB-005-PersistenceTest`
- Service account: `LocalSystem`
- Service start type: `3`, manual/demand start
- Service file name: benign lab command using `cmd.exe` and
  `C:\Windows\Temp\soc-lab-005-service.txt`
- Process context: `4688` showed `sc.exe create` launched by the lab user from
  PowerShell ISE.
- Baseline comparison: other `sc.exe` events were created by the machine
  account or Azure Guest Agent and were not related to the lab service.
- Incident-window review: the alert window also contained Windows per-user
  services and a Defender-related `KslD` driver service, which explains why the
  machine account appeared as an incident entity.
- Service-start check: the service returned error `1053` because the configured
  command was not a real Windows service process.
- Execution evidence: despite the `1053` error, `4688` showed `cmd.exe`
  launched by `services.exe` and writing the LAB-005 test file.
- Cleanup evidence: `4688` showed `sc.exe delete
  SOC-LAB-005-PersistenceTest` launched by the lab user.
- Closure classification:
  `Informational, expected activity - Security testing`

## Baseline Note

The first baseline query returned existing `4697` events for Windows per-user
services such as `WpnUserService`, `UserDataSvc`, `UnistoreSvc`, and
`OneSyncSvc`. These were created by the machine account and pointed to expected
Windows service paths like `svchost.exe`.

This is a useful tuning lesson: `4697` means a service was installed, but the
analyst still needs to check the service name, file path, creating account, and
nearby process activity before deciding whether it is suspicious.

For this lab, the broad rule intentionally created a noisy incident. That is
useful for learning: a Tier 1 analyst must separate the real lab service from
normal per-user Windows services and Defender service activity.

## Planned Workflow

1. Read the threat brief.
2. Confirm `4697` is arriving in `SecurityEvent`.
3. Run the harmless service creation command.
4. Validate raw `4697` service-install evidence.
5. Review `4688` events around the same time.
6. Create a simple hunting query.
7. Create a scheduled analytics rule.
8. Trigger and investigate the Defender/Sentinel incident.
9. Clean up the service and temporary file.
10. Write the final investigation report and `concepts.md`.

Completed result:

- Analytics rule generated Defender incident `46`.
- The incident included the lab service and normal machine-account service
  activity in the same window.
- The service was created, started, executed its benign command, and deleted.
- The incident was closed as
  `Informational, expected activity - Security testing`.

## Queries And Rules

- Hunting query: `detections/hunting-queries/lab-005-service-installed-for-persistence.kql`
- Analytics rule draft: `detections/analytics-rules/lab-005-service-installed-for-persistence.yaml`
- Threat brief: `labs/LAB-005-service-installed-for-persistence/threat-brief.md`
- Report draft: `labs/LAB-005-service-installed-for-persistence/investigation-report.md`
- Concepts course: `labs/LAB-005-service-installed-for-persistence/concepts.md`

## Investigation Questions

- Which account installed the service?
- Which host was affected?
- What is the service name?
- What does `ServiceFileName` execute?
- What is the service start type?
- What account will the service run as?
- Was `sc.exe`, PowerShell, or another tool used?
- Was the service started after creation?
- Is this expected security testing or suspicious persistence?

## MITRE ATT&CK

- Tactic: Persistence
- Technique: T1543.003 - Create or Modify System Process: Windows Service
- Tactic: Privilege Escalation
- Technique: T1543.003 - Create or Modify System Process: Windows Service

## Success Criteria

- Raw `4697` event shows the new service installation.
- Raw `4688` event shows `sc.exe` service creation command line.
- The hunting query returns the generated service event.
- The analytics rule creates one understandable alert or incident.
- The investigation report explains the evidence and final verdict.
