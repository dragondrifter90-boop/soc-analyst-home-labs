# LAB-004 Concepts

## What This Lab Taught

This lab taught how to detect and investigate PowerShell encoded command
execution using Windows process creation logs. The main SOC skill is reviewing
the command line, parent process, child process, and decoded command content
before deciding whether the activity is malicious or expected.

## Key SOC Concepts

PowerShell: a legitimate Windows automation tool that attackers also use for
execution, discovery, downloading payloads, and defense evasion.

Encoded command: PowerShell can run Base64-encoded commands using
`-EncodedCommand`. Attackers use this to make commands harder to read.

ExecutionPolicy Bypass: PowerShell option that can bypass normal execution
policy restrictions.

Living off the land: using trusted built-in tools, such as PowerShell, instead
of obvious malware.

Parent process: the process that launched the suspicious process.

Child process: a process launched by the suspicious process. In this lab,
PowerShell launched `whoami.exe`.

Informational expected activity: the behavior matched a suspicious pattern, but
it was authorized security testing.

## Important Windows Event Details

Event ID 4688: a new process was created.

powershell.exe: the process detected by the analytics rule.

whoami.exe: child process observed after the encoded command ran.

PowerShell 4104: script block logging. This was not required for the lab, but
would give better visibility into script content in future labs.

PowerShell 4103: module logging. Useful later for deeper PowerShell telemetry.

## Important Columns

TimeGenerated: when the process creation event was recorded in Sentinel.

EventID: identifies the Windows event type. For this lab, `4688`.

Computer: host where PowerShell ran.

Account: account that launched the process.

Process: short process name, such as `powershell.exe`.

NewProcessName: full path of the new process.

CommandLine: full command line used to launch the process.

ParentProcessName: process that launched the new process.

AccountCustomEntity: account field prepared for Sentinel or Defender entity
mapping.

HostCustomEntity: host field prepared for Sentinel or Defender entity mapping.

## Key KQL Concepts

where EventID == 4688: filters to process creation events.

has_any: checks whether a field contains any value from a list. Example:
searching `CommandLine` for `-EncodedCommand`, `-enc`, or `/enc`.

extend: creates new columns, such as `AccountCustomEntity`.

project: selects the columns needed for investigation and alert enrichment.

order by TimeGenerated asc: creates a process timeline.

between: filters events to a specific time range around the alert.

## Analyst Memory

- Encoded PowerShell is suspicious, but context decides the verdict.
- Always check who ran it, on which host, and with what command line.
- Review the parent process to understand how PowerShell started.
- Review child processes to see what PowerShell caused.
- Decoding the Base64 helps explain the activity, but raw event validation
  comes first.
- In Defender, authorized testing fits
  `Informational, expected activity - Security testing`.

## Interview-Ready Explanation

In this lab, I detected PowerShell encoded command execution using Windows
event `4688` in Microsoft Sentinel. I validated the raw command line, confirmed
`-EncodedCommand` and `-ExecutionPolicy Bypass`, decoded the Base64 command,
reviewed parent and child processes, and closed the Defender incident as
expected security testing because the activity was authorized and benign.
