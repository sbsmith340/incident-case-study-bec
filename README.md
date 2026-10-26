# Incident Case Study: Business Email Compromise

> An end-to-end investigation of an adversary-in-the-middle phishing attack that bypassed MFA and led to attempted invoice fraud. It runs from the first alert to scope, root cause, and lessons learned. Every finding is reproducible from raw log data with one command.

![ci](https://github.com/sbsmith340/incident-case-study-bec/actions/workflows/ci.yml/badge.svg)
![data](https://img.shields.io/badge/data-synthetic-blue)
![attack](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566%20%7C%20T1550%20%7C%20T1528%20%7C%20T1657-red)

**[Read the incident report](REPORT.md)** · [Generated findings and timeline](docs/FINDINGS.md)

## Why this exists
A resume can say "led incident response." This shows how: what questions an analyst asks, in what order, how each answer leads to the next pivot, what was ruled out, and what changed afterward.

## The scenario
A look-alike vendor domain sends a "shared payment schedule" lure to 19 employees. One opens it from Junk and signs in on a proxy page that steals her session token, so MFA doesn't help. The attacker then:
- hides payment-related mail with an inbox rule
- grants a malicious OAuth app mailbox access
- reads 46 messages
- sends three requests to change vendor bank details

A second user clicks the same link but is stopped by Safe Links. An unrelated password spray earlier that morning is noise the investigation has to rule out.

## Investigation walkthrough
Each step is a function in [`investigation/investigate.py`](investigation/investigate.py) with a matching KQL query in [`kql/`](kql/). No step is given the answer: attacker IPs, the phishing email, and the scope are all derived from the previous step's output.

| # | Analyst question | Finding |
|---|---|---|
| 1 | Which inbox rule fired, and whose is it? | ana.ruiz, rule "." hiding invoice/payment/bank/wire mail in RSS Feeds |
| 2 | Which of her sign-ins break her baseline? | 3 sign-ins from 2 NL IPs, headless browser, MFA "satisfied by claim in token" (token theft) |
| 3 | Did that infrastructure touch anyone else? | No |
| 4 | How did they get in? | Phishing link clicked 3 minutes before the first malicious sign-in, opened from Junk |
| 5 | How wide was the campaign? | 19 recipients; 1 clicked through, 1 blocked by Safe Links |
| 6 | What persistence was left? | Inbox rule + OAuth grant (Mail.ReadWrite, Mail.Send, offline_access) |
| 7 | What was accessed? | 46 mail items in 11 minutes through the malicious app |
| 8 | Was the mailbox used for fraud? | 3 bank-change emails with an attacker Reply-To: 2 internal finance, 1 vendor |
| 9 | Is the password spray related? | No: all failures, different infrastructure, ended ~4 hours earlier |

## What makes it credible
- **Reproducible.** `python data/generate.py` rebuilds the dataset byte for byte (seeded), and `python investigation/investigate.py` re-derives every finding.
- **The report is tested against the data.** If `REPORT.md` cites an IOC, count, or account the code didn't find, the build fails.
- **Honest about detection.** The report checks each relevant rule from the [KQL detection library](https://github.com/sbsmith340/kql-detection-library) against the data. Two of the four rules would have been late or silent, and that becomes an action item rather than a claim the rules would have caught it.

## Data
About 650 events across five tables, using the column names of the Microsoft Sentinel / Defender tables they imitate:

| File | Mirrors | Rows |
|---|---|---|
| `data/SigninLogs.csv` | Entra ID sign-in logs | 139 |
| `data/EmailEvents.csv` | Defender for Office 365 email events | 422 |
| `data/UrlClickEvents.csv` | Safe Links click events | 27 |
| `data/OfficeActivity.csv` | Exchange audit (inbox rules, MailItemsAccessed) | 57 |
| `data/AuditLogs.csv` | Entra ID audit (OAuth consent) | 4 |

All people, domains, and apps are fictional. IP addresses come from the RFC 5737 documentation ranges.

## How to run it
```bash
git clone https://github.com/sbsmith340/incident-case-study-bec.git
cd incident-case-study-bec
python investigation/investigate.py    # prints the 9-step walkthrough
pip install pytest && pytest -q tests  # 10 tests
```
No dependencies beyond the Python standard library. The KQL in `kql/` is written for Microsoft Sentinel / Azure Data Explorer against the same table schemas. The Python implementation is the executed reference.

## Limitations and what's next
- **One synthetic tenant, clean logs.** Real investigations deal with missing or delayed logs. Some of the events used here (mailbox access auditing, URL click events) depend on licensing and audit settings, so step one in a real case is confirming what was actually being logged.
- **The KQL is written against the real table schemas, but the Python is the executed reference.** Next: run the `kql/` files on the Kusto emulator in CI, the way the [KQL detection library](https://github.com/sbsmith340/kql-detection-library) does.
- **Containment is described, not automated.** A companion playbook (revoke sessions, remove the inbox rule and OAuth grant, block the IOCs) would turn sections 5 and 7 into code.

## Repo layout
```
REPORT.md                     the incident report (start here)
docs/FINDINGS.md              generated walkthrough, timeline, IOCs, scope
investigation/investigate.py  the investigation, step by step
kql/01..09-*.kql              the same steps as KQL
data/generate.py              deterministic synthetic dataset generator
data/*.csv                    the dataset
tests/                        answer checks + report/data consistency
```

---
Synthetic scenario. Built by [Shawn Smith](https://sbsmith340.github.io).
