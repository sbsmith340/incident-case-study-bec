"""
Generate the synthetic incident dataset: a business email compromise (BEC)
hidden inside two days of ordinary Microsoft 365 / Entra ID activity.

Tables mirror the column names of the Microsoft Sentinel / Defender tables they
imitate (a subset of columns). All people, domains and IPs are fictional; IPs
come from the reserved documentation ranges (RFC 5737).

  python data/generate.py          # writes data/*.csv (deterministic, seed 2026)
"""
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent
rng = random.Random(2026)
UTC = timezone.utc
DAY0 = datetime(2026, 9, 14, tzinfo=UTC)

ORG = "contoso.com"
USERS = ["ana.ruiz", "marcus.green", "priya.patel", "jordan.lee", "kevin.ng", "lena.fischer", "omar.haddad",
         "sara.kim", "tom.baker", "nina.rossi", "david.osei", "emma.clark", "li.wei", "raj.mehta", "chloe.martin",
         "sam.ortiz", "grace.hall", "ben.wright", "ivy.nguyen", "max.silva"]
FINANCE = ["marcus.green", "nina.rossi", "david.osei"]
OFFICE_IPS = ["192.0.2.10", "192.0.2.11", "192.0.2.12"]      # corporate egress
HOME_IPS = {u: f"192.0.2.{100 + i}" for i, u in enumerate(USERS)}
APPS = ["Office 365 Exchange Online", "Microsoft Teams", "SharePoint Online", "Microsoft 365 Copilot", "Azure Portal"]
UA_NORMAL = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"

# ---- attacker infrastructure (the "answers" the investigation should find) ----
PHISH_SENDER = "docs-share@fabrikam-invoices.com"
PHISH_DOMAIN = "fabrikam-invoices.com"
PHISH_URL = "https://fabrikarn-sharepoint.com/s/q3-payment-schedule"
ATTACKER_IP = "198.51.100.23"
ATTACKER_IP2 = "198.51.100.41"
ATTACKER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/128.0 Safari/537.36"
MALICIOUS_APP = "Mail Organizer Pro"
VENDOR = "billing@northwind-supplies.com"
ATTACKER_REPLY_TO = "northwind.billing@outlook-mailbox.example"

rows = {k: [] for k in ["SigninLogs", "EmailEvents", "UrlClickEvents", "OfficeActivity", "AuditLogs"]}
msg_id = iter(range(10_000, 99_999))


def t(day, h, m, s=0):
    return (DAY0 + timedelta(days=day, hours=h, minutes=m, seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def signin(ts, user, ip, country, result="0", app=None, ua=UA_NORMAL, mfa="multiFactorAuthentication",
           detail="MFA requirement satisfied by claim in the token"):
    rows["SigninLogs"].append({
        "TimeGenerated": ts, "UserPrincipalName": f"{user}@{ORG}", "IPAddress": ip,
        "Location": country, "AppDisplayName": app or rng.choice(APPS), "ResultType": result,
        "AuthenticationRequirement": mfa, "AuthenticationDetail": detail, "UserAgent": ua})


def email(ts, sender, recipient, subject, direction="Inbound", action="Delivered", threat="", url="", reply_to=""):
    mid = f"msg-{next(msg_id)}"
    rows["EmailEvents"].append({
        "Timestamp": ts, "NetworkMessageId": mid, "SenderFromAddress": sender, "RecipientEmailAddress": recipient,
        "Subject": subject, "EmailDirection": direction, "DeliveryAction": action, "ThreatTypes": threat,
        "Url": url, "ReplyToAddress": reply_to})
    return mid


# ---------------------------------------------------------------- baseline noise
for day in (0, 1):
    for u in USERS:
        for _ in range(rng.randint(2, 4)):
            h, m = rng.randint(12, 22), rng.randint(0, 59)           # 08:00-18:00 US Eastern
            ip, cc = (rng.choice(OFFICE_IPS), "US") if rng.random() < .7 else (HOME_IPS[u], "US")
            signin(t(day, h, m, rng.randint(0, 59)), u, ip, cc)
        if rng.random() < .15:                                        # ordinary typo'd password
            signin(t(day, rng.randint(12, 21), rng.randint(0, 59)), u, rng.choice(OFFICE_IPS), "US",
                   result="50126", mfa="singleFactorAuthentication", detail="Invalid username or password")
    for _ in range(140):
        s, r = rng.sample(USERS, 2)
        email(t(day, rng.randint(12, 22), rng.randint(0, 59)), f"{s}@{ORG}", f"{r}@{ORG}",
              rng.choice(["Re: project status", "Lunch?", "Updated deck", "Timesheet reminder", "Notes from standup"]),
              direction="Intra-org")
    for _ in range(60):
        r = rng.choice(USERS)
        snd = rng.choice(["news@updates.tailspintoys.com", VENDOR, "noreply@proseware.com", "events@litware.com"])
        url = rng.choice(["https://updates.tailspintoys.com/read", "https://portal.northwind-supplies.com/inv", ""])
        mid = email(t(day, rng.randint(12, 22), rng.randint(0, 59)), snd, f"{r}@{ORG}",
                    rng.choice(["Your weekly digest", "Invoice available", "Webinar invite"]), url=url)
        if url and rng.random() < .3:
            rows["UrlClickEvents"].append({"Timestamp": t(day, rng.randint(13, 22), rng.randint(0, 59)),
                                           "AccountUpn": f"{r}@{ORG}", "Url": url, "ActionType": "ClickAllowed",
                                           "IsClickedThrough": "False", "ThreatTypes": "", "NetworkMessageId": mid,
                                           "IPAddress": rng.choice(OFFICE_IPS)})
    for u in rng.sample(USERS, 5):                                     # benign mailbox admin
        rows["OfficeActivity"].append({"TimeGenerated": t(day, rng.randint(13, 21), rng.randint(0, 59)),
                                       "UserId": f"{u}@{ORG}", "Operation": "New-InboxRule", "ClientIP": rng.choice(OFFICE_IPS),
                                       "Parameters": '[{"Name":"Name","Value":"Newsletters"},{"Name":"From","Value":"news@updates.tailspintoys.com"},{"Name":"MoveToFolder","Value":"Newsletters"}]',
                                       "AppId": ""})

# a noisy but unrelated password spray from another range (red herring - all failures)
for i, u in enumerate(rng.sample(USERS, 14)):
    signin(t(0, 9, 5, i * 7), u, "203.0.113.200", "RU", result="50126", app="Office 365 Exchange Online",
           ua="python-requests/2.31", mfa="singleFactorAuthentication", detail="Invalid username or password")

# ---------------------------------------------------------------- the incident
# 1. Phishing campaign (lookalike vendor domain), 13:02 UTC day 0
phish_targets = rng.sample(USERS, 18)
for name in ("ana.ruiz", "kevin.ng"):
    if name not in phish_targets:
        phish_targets.append(name)
phish_ids = {}
for i, u in enumerate(phish_targets):
    action = "Delivered" if i % 6 else "Junked"
    phish_ids[u] = email(t(0, 13, 2, i * 3), PHISH_SENDER, f"{u}@{ORG}", "Shared with you: Q3 vendor payment schedule",
                         action=action, url=PHISH_URL)

# 2. Clicks: ana.ruiz clicks through and is phished; kevin.ng clicks, sees the warning page, stops
rows["UrlClickEvents"].append({"Timestamp": t(0, 13, 18, 4), "AccountUpn": f"ana.ruiz@{ORG}", "Url": PHISH_URL,
                               "ActionType": "ClickAllowed", "IsClickedThrough": "True", "ThreatTypes": "",
                               "NetworkMessageId": phish_ids["ana.ruiz"], "IPAddress": OFFICE_IPS[0]})
rows["UrlClickEvents"].append({"Timestamp": t(0, 14, 2, 40), "AccountUpn": f"kevin.ng@{ORG}", "Url": PHISH_URL,
                               "ActionType": "ClickBlocked", "IsClickedThrough": "False", "ThreatTypes": "Phish",
                               "NetworkMessageId": phish_ids["kevin.ng"], "IPAddress": OFFICE_IPS[1]})

# 3. Adversary-in-the-middle token replay: successful sign-ins from attacker IPs, MFA satisfied by token claim
signin(t(0, 13, 21, 15), "ana.ruiz", ATTACKER_IP, "NL", app="Office 365 Exchange Online", ua=ATTACKER_UA)
signin(t(0, 13, 26, 2), "ana.ruiz", ATTACKER_IP, "NL", app="SharePoint Online", ua=ATTACKER_UA)
signin(t(0, 15, 4, 50), "ana.ruiz", ATTACKER_IP2, "NL", app="Office 365 Exchange Online", ua=ATTACKER_UA)

# 4. Persistence / defense evasion: inbox rule hiding replies about payments
rows["OfficeActivity"].append({
    "TimeGenerated": t(0, 13, 31, 9), "UserId": f"ana.ruiz@{ORG}", "Operation": "New-InboxRule", "ClientIP": ATTACKER_IP,
    "Parameters": '[{"Name":"Name","Value":"."},{"Name":"SubjectOrBodyContainsWords","Value":"invoice;payment;bank;wire"},'
                  '{"Name":"MoveToFolder","Value":"RSS Feeds"},{"Name":"MarkAsRead","Value":"True"}]', "AppId": ""})

# 5. Persistence: OAuth consent to a mail app with offline access
rows["AuditLogs"].append({
    "TimeGenerated": t(0, 13, 40, 33), "OperationName": "Consent to application",
    "InitiatedBy": f"ana.ruiz@{ORG}", "IPAddress": ATTACKER_IP, "TargetApp": MALICIOUS_APP,
    "Permissions": "Mail.ReadWrite Mail.Send offline_access User.Read", "Result": "success"})
for _ in range(3):  # benign consents for contrast
    u = rng.choice(USERS)
    rows["AuditLogs"].append({"TimeGenerated": t(rng.randint(0, 1), rng.randint(13, 21), rng.randint(0, 59)),
                              "OperationName": "Consent to application", "InitiatedBy": f"{u}@{ORG}",
                              "IPAddress": rng.choice(OFFICE_IPS), "TargetApp": rng.choice(["Zoom", "Adobe Acrobat"]),
                              "Permissions": "User.Read openid profile", "Result": "success"})

# 6. Collection: bulk mail access through the malicious app
for i in range(46):
    rows["OfficeActivity"].append({"TimeGenerated": t(0, 13, 45 + i // 4, (i % 4) * 13), "UserId": f"ana.ruiz@{ORG}",
                                   "Operation": "MailItemsAccessed", "ClientIP": ATTACKER_IP, "Parameters": "",
                                   "AppId": MALICIOUS_APP})

# 7. Impact attempt: payment-redirection emails from the compromised mailbox
email(t(0, 15, 12, 30), f"ana.ruiz@{ORG}", f"marcus.green@{ORG}", "RE: Q3 vendor payment schedule - updated bank details",
      direction="Intra-org", reply_to=ATTACKER_REPLY_TO)
email(t(0, 15, 14, 2), f"ana.ruiz@{ORG}", VENDOR, "Change of remittance account", direction="Outbound",
      reply_to=ATTACKER_REPLY_TO)
email(t(0, 15, 15, 47), f"ana.ruiz@{ORG}", f"nina.rossi@{ORG}", "RE: Q3 vendor payment schedule - updated bank details",
      direction="Intra-org", reply_to=ATTACKER_REPLY_TO)

for name, data in rows.items():
    data.sort(key=lambda r: r.get("TimeGenerated") or r.get("Timestamp"))
    with (OUT / f"{name}.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
        w.writeheader()
        w.writerows(data)
    print(f"{name}: {len(data)} rows")
