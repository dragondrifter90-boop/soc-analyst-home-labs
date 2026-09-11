# LAB-001 Concepts

## What This Lab Taught

This lab taught how to investigate repeated Windows failed logons followed by a
successful logon. The main SOC skill is confirming whether the same account,
host, and source IP moved from failed authentication to successful access.

## Key SOC Concepts

Event ID 4625: failed Windows logon. Example: bad password attempts against a
test account.

Event ID 4624: successful Windows logon. Example: the same test account later
authenticated successfully.

RDP authentication: Remote Desktop can produce more than one successful logon
event during one session.

Network Level Authentication: RDP may first authenticate as a network logon
before the full remote interactive session is created.

Brute force pattern: repeated failed logons from the same source, followed by a
success, can indicate password guessing that worked.

Benign positive: the detection was valid, but the activity was expected because
it was generated for the lab.

## Important Windows Event Details

LogonType 3: network logon. In this lab, failed RDP/NLA attempts appeared as
LogonType `3`.

LogonType 10: remote interactive logon. This is commonly associated with an RDP
session.

LogonType 7: unlock. In this lab, a successful authentication later appeared as
a session unlock/reconnect.

SubStatus 0xc000006a: valid username but bad password.

Status 0xc000006d: logon failure.

AuthenticationPackageName NTLM: authentication package used in the observed
events.

## Important Columns

TimeGenerated: when the event was recorded in Sentinel.

EventID: identifies the type of Windows event, such as `4625` or `4624`.

Computer: host where the logon event happened.

Account: account involved in the event. For logon events, this often matches
the target user.

TargetAccount: account being authenticated.

IpAddress: source IP address for remote authentication.

LogonType: numeric logon category, such as `3`, `7`, or `10`.

FailureReason: readable reason for a failed logon.

Status and SubStatus: low-level failure codes that explain why authentication
failed.

## Key KQL Concepts

where: filters rows. Example: `where EventID == 4625`.

project: selects only the columns needed for investigation.

order by: sorts events into a timeline.

summarize count(): counts events, such as failed attempts per source IP.

ago(): creates a relative time window, such as `ago(2h)`.

extract(): can pull the username from account strings such as
`HOST\username`.

tolower(): normalizes account names so matching is easier.

join: combines failed and successful logon results. This is useful, but should
be introduced only after the raw evidence is understood.

## Analyst Memory

- Start with raw `4625` and `4624` events before building a detection.
- Do not rely only on `LogonType == 10`; failed RDP/NLA attempts may appear as
  LogonType `3`.
- A success after failures is more important when it shares the same account,
  host, and source IP.
- Always check what happened after the successful logon.
- Suspicious authentication behavior can still be expected lab activity.

## Interview-Ready Explanation

In this lab, I investigated repeated Windows failed logons followed by a
successful logon in Microsoft Sentinel. I validated raw `4625` and `4624`
events, reviewed the source IP, account, host, logon types, and failure codes,
then created a Sentinel analytics rule that generated an incident. The incident
was closed as expected lab activity after confirming there was no malicious
post-logon behavior.
