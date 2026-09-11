# LAB-003 Concepts

## What This Lab Taught

This lab taught how to investigate real failed RDP authentication attempts from
unknown external IP addresses. The main SOC skill is separating suspicious
internet activity from legitimate user mistakes, then confirming whether any
authentication succeeded.

## Key SOC Concepts

Internet-facing RDP: exposing Remote Desktop to the internet commonly attracts
password guessing and brute-force attempts.

Password guessing: an attacker tries common usernames and passwords.

Brute force: repeated authentication attempts, often from the same source IP.

True positive suspicious activity: the suspicious behavior was real, even
though no compromise was found.

No compromise found: failed attempts alone do not prove the attacker accessed
the host.

Exposure reduction: limiting RDP access to a known IP, VPN, Bastion, or JIT
access reduces attack surface.

## Important Windows Event Details

Event ID 4625: failed Windows logon.

Event ID 4624: successful Windows logon.

Administrator-style targeting: attempts against `Administrator`, `admin`, and
similar usernames are common in internet-facing RDP activity.

Suspicious IP behavior: many failures in a short time window from an unknown IP
is more suspicious than a few failures from the known user IP.

## Important Columns

TimeGenerated: when each failed or successful logon was recorded.

EventID: distinguishes failures (`4625`) from successes (`4624`).

Computer: host receiving the logon attempt.

Account: account string involved in the logon event.

TargetAccount: account being attempted when available.

IpAddress: source IP address of the authentication attempt.

LogonType: helps identify remote or network-style authentication.

FailureReason: readable reason for failed authentication.

Status and SubStatus: detailed failure codes.

## Key KQL Concepts

summarize count() by IpAddress: counts failed attempts per source IP.

make_list(): collects examples, such as accounts targeted by each IP.

make_set(): collects unique values, such as distinct usernames.

min() and max(): show first seen and last seen times.

where IpAddress != "<LEGITIMATE_IP>": excludes known safe sources during
analysis.

where EventID == 4624: checks if suspicious IPs ever successfully logged in.

## Analyst Memory

- First identify the source IPs with the most failed logons.
- Separate known legitimate IPs from unknown external IPs.
- Review which usernames were targeted.
- Always check for successful `4624` events from suspicious IPs.
- True positive does not always mean compromise. It means the suspicious
  behavior was real.
- Hardening can be the correct response even when the attack failed.

## Interview-Ready Explanation

In this lab, I investigated real failed RDP attempts against my lab VM. I used
KQL to summarize failed `4625` logons by source IP, reviewed targeted
usernames, separated my legitimate IP from suspicious external sources, and
confirmed there were no successful `4624` logons from those suspicious IPs. I
then documented the case as true positive suspicious activity with no evidence
of compromise and restricted RDP access to my known public IP.
