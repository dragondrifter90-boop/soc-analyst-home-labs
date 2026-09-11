# LAB-005 Concepts

## What This Lab Taught

This lab taught how to detect and investigate Windows service installation as a
possible persistence technique. The main SOC skill is reviewing the service
name, service path, creating account, service account, process context, and
cleanup evidence before deciding whether the activity is malicious or expected.

## Key SOC Concepts

Windows service: a background program managed by the Windows Service Control
Manager.

Service persistence: attackers may create services so code can run again later
or run with elevated privileges.

Service Control Manager: Windows component that starts, stops, and manages
services.

LocalSystem: a very powerful local service account. A malicious service running
as LocalSystem can have high impact on the host.

Benign service creation: administrators, Windows components, Azure agents, and
security tools can create or modify services during normal activity.

Noisy incident: an alert can include unrelated but similar events in the same
time window. The analyst must separate the real signal from normal background
activity.

Expected security testing: suspicious behavior that was authorized for a lab or
assessment.

## Important Windows Event Details

Event ID 4697: a service was installed in the system.

Event ID 4688: a new process was created.

sc.exe: Windows command-line tool for creating, configuring, starting, and
deleting services.

services.exe: parent process that launches service binaries.

ServiceStartType 2: automatic start.

ServiceStartType 3: manual or demand start.

StartService error 1053: the service did not respond to the Service Control
Manager in time. In this lab, the command executed, but `cmd.exe /c echo ...`
was not a real Windows service process.

## Important Columns

TimeGenerated: when the event was recorded in Sentinel.

EventID: identifies the Windows event type, such as `4697` or `4688`.

Computer: host where the service or process event happened.

Account: account responsible for the action. For service execution, this may be
the machine account.

ServiceName: name of the installed service.

ServiceFileName: binary or command configured for the service.

ServiceStartType: how the service is configured to start.

ServiceAccount: account the service is configured to run as.

Process: short process name, such as `sc.exe` or `cmd.exe`.

CommandLine: full command line used by a process.

ParentProcessName: process that launched the new process.

## Key KQL Concepts

where EventID == 4697: filters to service installation events.

where EventID == 4688: filters to process creation events.

project: keeps the fields needed for triage and reporting.

order by TimeGenerated asc: builds an investigation timeline.

between: focuses the query on the incident window.

has: finds a token in fields such as `ServiceName`, `ServiceFileName`, or
`CommandLine`.

in~: case-insensitive match against a list of values.

## Analyst Memory

- `4697` means a service was installed, not automatically that malware exists.
- Check `ServiceFileName`; suspicious services often point to command
  interpreters, scripts, user profile paths, or temporary directories.
- Check `ServiceAccount`; LocalSystem is high impact.
- Use `4688` to understand how the service was created.
- If the incident includes machine-account activity, check whether normal
  Windows or security-tool services were grouped into the alert window.
- A failed service start can still produce process execution evidence.
- Cleanup should be validated, usually with `sc.exe delete` or service-control
  evidence.

## Interview-Ready Explanation

In this lab, I investigated a Windows service installation alert in Microsoft
Defender and Sentinel. I validated event `4697` for the service creation,
reviewed event `4688` process context showing PowerShell launching `sc.exe`,
checked the service name, service path, start type, and LocalSystem service
account, then reviewed the start attempt and cleanup. The incident was closed
as expected security testing because the activity was authorized and benign.
