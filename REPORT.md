# Incident Report: Business Email Compromise via Adversary-in-the-Middle Phishing

| | |
|---|---|
| **Incident ID** | IR-2026-0914-01 (synthetic scenario) |
| **Severity** | SEV-2: one confirmed account compromise, fraud attempted, contained same day |
| **Status** | Closed |
| **Date of incident** | 2026-09-14 (all times UTC) |
| **Detection source** | Analytics rule: inbox rule hiding finance-related mail |
| **Analyst** | Shawn Smith |

> This is a fictional scenario built on a synthetic dataset (`data/`). Every finding below is reproduced by `investigation/investigate.py`; the full generated walkthrough is in [docs/FINDINGS.md](docs/FINDINGS.md).

## 1. Executive summary
An attacker sent a phishing email impersonating a vendor document share to 19 employees. One employee, **ana.ruiz**, opened it from her Junk folder and entered her credentials on a look-alike sign-in page. The page relayed her login in real time (adversary-in-the-middle) and **stole her session token**, which let the attacker sign in **despite MFA**.

Over the next two hours the attacker:
- hid payment-related replies with an inbox rule
- granted a malicious app persistent access to the mailbox
- read 46 mail items
- sent **three payment-redirection emails**: two to the finance team and one to a real vendor, asking that payments go to a new bank account

An analytics rule flagged the inbox rule. **No payment was made.** The account was contained the same day, and no other account was compromised.

## 2. Timeline (UTC, 2026-09-14)
| Time | Event | ATT&CK |
|---|---|---|
| 09:05 | Unrelated password spray from 203.0.113.200 (all 14 attempts failed) | T1110.003 (ruled out, see section 4) |
| 13:02 | Phishing email "Shared with you: Q3 vendor payment schedule" from `docs-share@fabrikam-invoices.com` reaches 19 mailboxes | T1566.002 |
| 13:18 | ana.ruiz opens the message from Junk and clicks the link | T1204.001 |
| 13:21 | First sign-in as ana.ruiz from 198.51.100.23 (NL), headless browser, MFA satisfied by token claim | T1078.004, T1550.004 |
| 13:31 | Inbox rule "." moves mail containing invoice/payment/bank/wire to RSS Feeds, marked read | T1564.008 |
| 13:40 | OAuth consent to "Mail Organizer Pro" (Mail.ReadWrite, Mail.Send, offline_access) | T1528 |
| 13:45 to 13:56 | 46 MailItemsAccessed events through the malicious app | T1114.002 |
| 14:02 | kevin.ng clicks the same link; **Safe Links blocks it** | Prevented |
| 15:04 | Second attacker IP 198.51.100.41 signs in as ana.ruiz | T1078.004 |
| 15:12 to 15:15 | Three emails asking to change remittance bank details, with Reply-To set to an attacker mailbox | T1657 |
| ~16:45 | Alert triaged, incident opened, containment begins | |

## 3. Scope
| Question | Answer |
|---|---|
| Accounts compromised | **1**: ana.ruiz@contoso.com |
| Attacker sign-ins to other accounts | None; both attacker IPs were pivoted across all sign-in logs |
| Campaign reach | 19 recipients: 15 delivered, 4 sent to Junk (including the victim's copy) |
| Other users who interacted | kevin.ng clicked; Safe Links blocked it; no sign-in followed |
| Data accessed | 46 mail items read via the OAuth app over 11 minutes |
| Fraud attempts | 3 emails: marcus.green and nina.rossi (internal finance), billing@northwind-supplies.com (vendor) |
| Financial loss | None. Finance confirmed no bank-detail change was processed. |

## 4. Analysis
**How the attacker got past MFA.** The malicious sign-ins show `AuthenticationDetail = "MFA requirement satisfied by claim in the token"`, with a headless Chrome user agent from an IP the user had never used. The attacker didn't break MFA; they **replayed a session token** captured by the phishing proxy after the user completed MFA herself. The look-alike URL (`fabrikarn-sharepoint.com`, with "rn" posing as "m") is typical of adversary-in-the-middle kits. Resetting the password alone would **not** have evicted the attacker. That takes session revocation plus removing the OAuth grant.

**Why the inbox rule matters.** The rule name is a single period and it routes finance keywords to *RSS Feeds*, a folder users rarely open. It exists to hide vendor and finance replies questioning the bank change, so the fraud stays invisible to the victim.

**The red herring.** A password spray earlier that morning from 203.0.113.200 hit 14 accounts. It was ruled out: every attempt failed, it used different infrastructure and tooling (`python-requests`), and it ended about four hours before the phishing email. It still gets its own low-priority ticket, because sprays often precede targeted campaigns.

## 5. Response actions
**Containment (same day)**
- Revoked all sessions and refresh tokens for ana.ruiz, then reset her password and re-registered MFA
- Removed the inbox rule, and revoked the "Mail Organizer Pro" grant and service principal
- Blocked the sender domain, the phishing URL, both attacker IPs, and the fraudulent Reply-To address
- Called finance and the vendor by phone **using known numbers** (not the ones in the emails) to confirm no change was processed
- Purged the phishing message from all 19 mailboxes

**Eradication and recovery**
- Searched every mailbox for inbox rules and OAuth grants created from the attacker IPs: none besides the victim's
- Confirmed no mail-forwarding, delegate, or MFA-method changes on the account
- Placed the account under 30 days of enhanced monitoring

## 6. Root cause and contributing factors
1. **The user retrieved a message the filter had already flagged.** Junk filtering isn't quarantine; the message and its link stayed usable.
2. **Phishable MFA.** Push and code MFA can be relayed by a proxy. Phishing-resistant methods (FIDO2 or passkeys) can't be.
3. **No token-binding or compliant-device requirement** for Exchange Online, so a stolen token worked from an unmanaged Linux host.
4. **Users could consent to apps requesting mail scopes.**
5. **Detection came late.** The alert was triaged about 3.5 hours after compromise. An OAuth-consent rule would have flagged it within the first hour, but it wasn't deployed (see section 7).

## 7. Lessons learned and actions
| # | Action | Owner | Due |
|---|---|---|---|
| 1 | Quarantine high-confidence phishing instead of sending it to Junk | Email admin | 2 weeks |
| 2 | Require phishing-resistant MFA for finance and executives first, then everyone | Identity team | 60 days |
| 3 | Conditional Access: require compliant devices for Exchange Online; enable token protection where supported | Identity team | 60 days |
| 4 | Restrict user consent to verified publishers with low-risk scopes; turn on the admin consent workflow | Identity team | 2 weeks |
| 5 | Deploy the OAuth-consent detection and run the inbox-rule detection every 15 minutes (see below); add a first-seen-country sign-in rule | Security operations | 2 weeks |
| 6 | Finance procedure: verify any bank-detail change by phone using a number already on file | Finance | Done |
| 7 | Automation: when Safe Links classifies a URL as phishing, retro-hunt every earlier click on that URL and open an incident per user | Security operations | 30 days |

**How each detection would have performed on this data.** All rules come from the [KQL detection library](https://github.com/sbsmith340/kql-detection-library). This was checked against the dataset, not assumed:

| Detection | Would it fire? | Earliest alert |
|---|---|---|
| User consent to OAuth app with high-risk permissions | **Yes**, on the 13:40 consent | Next hourly run, ~14:00 to 14:40. The best early signal in this incident. |
| Inbox rule forwards or hides mail | **Yes**, on the 13:31 rule | This is the rule that fired. Triage at ~16:45 shows the alert sat in the queue too long. |
| Successful sign-ins from two countries within a short window | **Late**. The attacker's first sign-ins had no preceding US sign-in within two hours. | ~16:00, after the victim's legitimate 15:57 US sign-in followed the 15:04 NL sign-in |
| User clicked through a malicious URL | **No** for the victim. Her click at 13:18 happened before the URL was classified; it was only classified as phishing on kevin.ng's blocked click at 14:02. | Never, without action 7 above |

**Takeaway:** single-event rules missed the compromise itself. The fastest high-confidence signal was the OAuth consent. Two gaps remain: first-seen-country or UEBA anomaly detection for the sign-in, and a retroactive hunt when a URL's verdict changes.

## 8. Indicators of compromise
| Type | Value |
|---|---|
| Sender | `docs-share@fabrikam-invoices.com` |
| Sender domain | `fabrikam-invoices.com` |
| Phishing URL | `https://fabrikarn-sharepoint.com/s/q3-payment-schedule` |
| Attacker IP | `198.51.100.23` |
| Attacker IP | `198.51.100.41` |
| User agent | `Mozilla/5.0 (X11; Linux x86_64) ... HeadlessChrome/128.0 ...` |
| OAuth app | `Mail Organizer Pro` |
| Fraud Reply-To | `northwind.billing@outlook-mailbox.example` |
