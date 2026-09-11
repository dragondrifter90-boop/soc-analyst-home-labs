# LAB-002 Concepts

## What This Lab Taught

This lab taught how to investigate local account creation followed by addition
to the local Administrators group. The main SOC skill is proving which account
was created, who performed the action, and whether the new account received
privileged access.

## Key SOC Concepts

Local account creation: attackers may create local users to maintain access to
a host.

Local administrator membership: adding a user to Administrators gives powerful
control over the machine.

Privilege escalation or persistence: a new admin account can be used to keep
access after the original entry point is removed.

SID correlation: when names are missing or unclear, the Security Identifier can
prove two events refer to the same account.

Benign positive: the behavior was suspicious, but it was expected because it
was performed intentionally in the lab.

## Important Windows Event Details

Event ID 4720: a user account was created.

Event ID 4722: a user account was enabled.

Event ID 4732: a member was added to a security-enabled local group.

Event ID 4733: a member was removed from a security-enabled local group.

Event ID 4726: a user account was deleted.

Builtin\Administrators: the local Administrators group.

MemberName can be `-`: in this lab, event `4732` did not clearly show the
created username in `MemberName`.

TargetSid and MemberSid: comparing `4720.TargetSid` with `4732.MemberSid`
proved that the created user was the same user added to Administrators.

## Important Columns

TimeGenerated: when the event was recorded in Sentinel.

EventID: identifies the account-management event.

Computer: host where the local account or group change happened.

Account: account that performed the action. Example: the user who created the
new account.

TargetAccount: account or group affected by the action. In `4720`, this is the
created user. In `4732`, this may be the group.

TargetUserName: username affected by the event when available.

TargetSid: SID of the affected account or object.

MemberName: name of the member added to or removed from a group when available.

MemberSid: SID of the member added to or removed from a group.

Activity: readable event description.

CommandLine: useful if process creation logging shows how the action was
performed.

## Key KQL Concepts

where EventID in (...): filters for several event IDs at once.

project: keeps the columns needed for evidence review.

order by TimeGenerated asc: builds a timeline.

has: searches for a token in a string.

==: exact comparison, useful for matching a specific event ID or SID.

Manual correlation: for Tier 1 practice, compare values like `TargetSid` and
`MemberSid` directly before using complex joins.

## Analyst Memory

- For `4720`, ask: which account was created, on which host, and by whom?
- For `4732`, ask: which group changed, and which member was added?
- If `MemberName` is missing, check `MemberSid`.
- A new local admin account is important even if no malware is present.
- Cleanup evidence matters: `4733` and `4726` prove the lab users were removed.

## Interview-Ready Explanation

In this lab, I investigated a local user being created and added to the local
Administrators group. I reviewed Windows events `4720`, `4722`, and `4732`,
then proved the created user was the same account added to Administrators by
matching `4720.TargetSid` with `4732.MemberSid`. I documented the incident,
classified it as expected lab activity, and verified cleanup with `4733` and
`4726` events.
