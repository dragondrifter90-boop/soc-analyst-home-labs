# LAB-005 Threat Brief

## Threat Pattern

Attackers may create or modify Windows services so code runs again after reboot
or runs with elevated privileges. This is a common persistence and privilege
escalation technique because Windows services are trusted operating system
components and often run in the background.

## Why It Matters

A new service on a Windows host should usually be expected and explainable.
Unexpected service creation can indicate persistence, remote execution,
malware installation, or lateral movement tooling.

## Real-World References

- Microsoft Learn: Windows Security event `4697`, "A service was installed in
  the system."
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697
- Microsoft Learn: Audit Security System Extension recommends success auditing
  because service installation is an important security event.
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-system-extension
- Microsoft Security Blog: post-ransomware investigations recommend monitoring
  anomalous service creation, especially services created by administrator
  accounts and services executing as SYSTEM.
  https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/
- MITRE ATT&CK: `T1543.003 - Create or Modify System Process: Windows Service`.
  https://attack.mitre.org/techniques/T1543/003/

## Common Attacker Behavior

- Initial activity: attacker gains access to a Windows host or obtains admin
  rights.
- Tool or technique: creates a service with `sc.exe`, PowerShell, PsExec,
  Impacket, malware, or direct Windows API calls.
- Follow-up activity: starts the service, runs a payload, connects to a remote
  system, or waits for reboot.
- Possible objective: persistence, privilege escalation, remote execution, or
  ransomware staging.

## Lab Version

What this small lab can safely simulate:

- Create a harmless Windows service on the lab VM.
- Point the service to a benign command.
- Validate Windows event `4697`.
- Review related `4688` process creation events for `sc.exe`.
- Delete the service during cleanup.

What this lab cannot simulate yet:

- Real malware payloads.
- Lateral movement with PsExec or Impacket.
- Full service runtime behavior from EDR telemetry.
- Registry/service configuration changes with Sysmon.

## Required Telemetry

- Sentinel or Defender table: `SecurityEvent`
- Event IDs: `4697`, `4688`
- Connector or audit policy: Windows Security Events via AMA; Audit Security
  System Extension success auditing for `4697`; process creation with command
  line for `4688`.
- Optional future telemetry: Sysmon service and registry events, Defender for
  Endpoint device events, PowerShell logs if service creation uses PowerShell.

## Tool Justification

| Field | Value |
|---|---|
| Tool | Native Windows `sc.exe` |
| Why we need it | It safely creates a Windows service and generates realistic telemetry |
| Threat behavior simulated | Windows service creation for persistence |
| Authorized target | Lab Windows VM only |
| Safety boundary | Use a harmless built-in command, do not download payloads, delete the service after testing |
| Expected logs | `4697` service installed, `4688` for `sc.exe` |
| Detection idea | Alert when a new service is installed, especially with suspicious paths or command interpreters |
| Investigation questions | Who created the service, what binary/path was configured, what account will it run as, and was it expected? |

## Tier 1 Investigation Questions

- Who installed the service?
- Which host was affected?
- What was the service name?
- What command or binary did the service point to?
- What account was configured for the service?
- Was `sc.exe` or PowerShell used to create it?
- Was the service started?
- Was this expected admin work, authorized testing, or suspicious activity?

## Detection Idea

First simple query:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4697
| project TimeGenerated, Computer, Account, ServiceName, ServiceFileName, ServiceStartType, ServiceAccount
| order by TimeGenerated desc
```

Later tuned rule idea:

- Alert on any new service installed on the lab VM.
- Increase priority if `ServiceFileName` contains `cmd.exe`, `powershell.exe`,
  `wscript.exe`, a user-writable path, or temporary directory.
- Add custom details for service name, service file name, start type, and
  service account.

## Expected Classification

Microsoft Defender portal:

`Informational, expected activity - Security testing`

Reason: the lab intentionally creates a harmless service on an authorized host.
In a real environment, an unexpected service creation would usually be treated
as suspicious and investigated carefully.
