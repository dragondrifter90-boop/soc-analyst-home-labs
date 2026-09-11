# LAB-004: Suspicious PowerShell Encoded Command

## Status

Completed

## Objective

Detect and investigate PowerShell execution using an encoded command.

Attackers often use encoded PowerShell commands to hide or obfuscate what they
are running. In this lab, the encoded command is harmless, but the execution
pattern is suspicious and useful for SOC practice.

## Lab Metadata

| Field | Value |
|---|---|
| Difficulty | Tier 1+ |
| Telemetry level | Current SecurityEvent telemetry |
| Tools used | Native Windows PowerShell |
| Threat-informed focus | PowerShell living-off-the-land execution and obfuscation |
| Concepts course | `concepts.md` |

## Required Telemetry

- Sentinel table: `SecurityEvent`
- Windows process creation event: `4688`
- Command-line logging for `4688` enabled
- PowerShell logs `4103` and `4104` are useful later, but not required for the
  first version of this lab

## Scenario Story

A user runs PowerShell with the `-EncodedCommand` parameter on the Windows VM.
The SOC analyst must identify the suspicious PowerShell execution, determine
which account launched it, review the command-line evidence, and decide whether
the activity is malicious, benign, or an authorized lab simulation.

## Simulation Plan

Run this from PowerShell on the Windows VM:

```powershell
$Command = "Write-Output 'SOC-LAB-004 benign encoded command test'; whoami"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$EncodedCommand = [Convert]::ToBase64String($Bytes)
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $EncodedCommand
```

Expected event pattern:

```text
4688 - A new process has been created
Process / NewProcessName contains powershell.exe
CommandLine contains -EncodedCommand
```

## Safety Controls

- Use only the harmless command shown above.
- Run only on the lab Windows VM.
- Do not download or execute external scripts.
- Do not use offensive PowerShell payloads.

## Planned Workflow

1. Run a normal PowerShell command for baseline if desired.
2. Run the benign encoded PowerShell command.
3. Validate raw `4688` process creation telemetry.
4. Build a simple hunting query for encoded PowerShell.
5. Create a scheduled analytics rule.
6. Trigger and investigate the Sentinel incident.
7. Document visibility gaps and future telemetry improvements.

Completed result:

- Analytics rule generated Incident `44`.
- The incident was investigated in the Microsoft Defender portal.
- The incident was closed as
  `Informational, expected activity - Security testing`.

## Queries And Rules

- Hunting query: `detections/hunting-queries/lab-004-suspicious-powershell-encoded-command.kql`
- Analytics rule draft: `detections/analytics-rules/lab-004-suspicious-powershell-encoded-command.yaml`
- Report draft: `labs/LAB-004-suspicious-powershell-encoded-command/investigation-report.md`
- Concepts course: `labs/LAB-004-suspicious-powershell-encoded-command/concepts.md`

## Investigation Questions

- Which account launched PowerShell?
- Which host executed it?
- Did the command line contain `-EncodedCommand` or a short form such as `-enc`?
- Was `ExecutionPolicy Bypass` used?
- What parent process launched PowerShell?
- Was the command expected lab activity?
- What telemetry is missing without PowerShell `4104` script-block logs?

## MITRE ATT&CK

- Tactic: Execution
- Technique: T1059.001 - Command and Scripting Interpreter: PowerShell
- Tactic: Defense Evasion
- Technique: T1027 - Obfuscated Files or Information

## Success Criteria

- `4688` shows PowerShell process creation.
- `CommandLine` contains the encoded command parameter.
- The hunting query returns the generated event.
- The Sentinel analytics rule creates one understandable alert or incident.
- The investigation report explains the evidence and verdict.

## Current Evidence

- Sentinel incident: `44`
- Incident title: `LAB-004 - PowerShell encoded command execution`
- Alert time: `2026-08-27 09:21:36 UTC`
- Host entity: `<TARGET_VM>`
- Account entity: `<ACTING_USER>`
- Raw evidence: one `4688` process creation event for `powershell.exe`
- Closure classification:
  `Informational, expected activity - Security testing`
