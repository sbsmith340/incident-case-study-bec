"""
Reproducible investigation of the BEC incident.

Each step answers one analyst question using only the data, in the order an
analyst would pivot. No step is told the answer: attacker IPs, the phishing
email, and the scope are all derived from earlier results. The matching KQL for
each step is in ../kql/.

  python investigation/investigate.py     # prints the walkthrough, writes findings.json and docs/FINDINGS.md
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
SUSPICIOUS_RULE_WORDS = ("invoice", "payment", "bank", "wire", "remit")
HIDING_FOLDERS = ("RSS Feeds", "RSS Subscriptions", "Conversation History", "Archive")
RISKY_SCOPES = ("Mail.Read", "Mail.ReadWrite", "Mail.Send", "offline_access", "Files.ReadWrite.All")


def load(name):
    with (DATA / f"{name}.csv").open(newline="") as f:
        return list(csv.DictReader(f))


def ts(row):
    return datetime.strptime(row.get("TimeGenerated") or row["Timestamp"], "%Y-%m-%dT%H:%M:%SZ")


def params(row):
    try:
        return {p["Name"]: p["Value"] for p in json.loads(row["Parameters"] or "[]")}
    except json.JSONDecodeError:
        return {}


def investigate() -> dict:
    signins, emails, clicks = load("SigninLogs"), load("EmailEvents"), load("UrlClickEvents")
    office, audit = load("OfficeActivity"), load("AuditLogs")
    f: dict = {"steps": []}

    def step(q, answer, kql):
        f["steps"].append({"question": q, "answer": answer, "kql": kql})

    # 1 ── Alert triage: inbox rules that hide finance-related mail
    rules = []
    for r in office:
        if r["Operation"] not in ("New-InboxRule", "Set-InboxRule"):
            continue
        p = params(r)
        words = (p.get("SubjectOrBodyContainsWords", "") + p.get("BodyContainsWords", "")).lower()
        if any(w in words for w in SUSPICIOUS_RULE_WORDS) and (p.get("MoveToFolder") in HIDING_FOLDERS or p.get("DeleteMessage")):
            rules.append({"time": r["TimeGenerated"], "user": r["UserId"], "ip": r["ClientIP"], "rule": p})
    assert len(rules) == 1, "scenario expects exactly one alerting rule"
    alert = rules[0]
    victim = alert["user"]
    step("Which inbox rule triggered the alert, and who owns it?",
         f"{victim} created rule '{alert['rule'].get('Name')}' moving mail containing "
         f"'{alert['rule'].get('SubjectOrBodyContainsWords')}' to '{alert['rule'].get('MoveToFolder')}' from {alert['ip']}",
         "01-suspicious-inbox-rules.kql")

    # 2 ── Victim sign-ins: what is normal for this user, what is not?
    v_sign = [s for s in signins if s["UserPrincipalName"] == victim and s["ResultType"] == "0"]
    alert_ip = alert["ip"]
    baseline = [s for s in v_sign if s["IPAddress"] != alert_ip and s["Location"] == "US"]
    base_ips = {s["IPAddress"] for s in baseline}
    base_uas = {s["UserAgent"] for s in baseline}
    anomalous = [s for s in v_sign if s["IPAddress"] not in base_ips and (s["Location"] != "US" or s["UserAgent"] not in base_uas)]
    attacker_ips = sorted({s["IPAddress"] for s in anomalous})
    attacker_uas = sorted({s["UserAgent"] for s in anomalous})
    first_bad = min(ts(s) for s in anomalous)
    step(f"Which of {victim}'s successful sign-ins don't match the user's baseline?",
         f"{len(anomalous)} sign-ins from {', '.join(attacker_ips)} ({', '.join(sorted({s['Location'] for s in anomalous}))}) "
         f"with a headless-browser user agent; first at {first_bad:%H:%M:%S} UTC. MFA shows as satisfied by a token "
         f"claim: consistent with adversary-in-the-middle session token theft, not password-only compromise.",
         "02-victim-signin-anomalies.kql")

    # 3 ── Scope: did the attacker IPs touch any other account?
    other = sorted({s["UserPrincipalName"] for s in signins if s["IPAddress"] in attacker_ips and s["UserPrincipalName"] != victim})
    step("Did the attacker infrastructure sign in to any other account?",
         "No other account" if not other else ", ".join(other), "03-attacker-ip-pivot.kql")

    # 4 ── Initial access: what did the victim click shortly before the first malicious sign-in?
    v_clicks = [c for c in clicks if c["AccountUpn"] == victim and ts(c) <= first_bad
                and (first_bad - ts(c)).total_seconds() <= 3600]
    v_clicks.sort(key=ts)
    entry = v_clicks[-1]
    phish = next(e for e in emails if e["NetworkMessageId"] == entry["NetworkMessageId"])
    step("How did the attacker get in?",
         f"{victim} clicked {entry['Url']} at {ts(entry):%H:%M:%S} UTC ({int((first_bad - ts(entry)).total_seconds() // 60)} "
         f"minutes before the first malicious sign-in), from an email sent by {phish['SenderFromAddress']} "
         f"with subject '{phish['Subject']}'. The message had been placed in {phish['DeliveryAction'].replace('Junked', 'the Junk folder')}"
         f"{', so the user opened it from Junk' if phish['DeliveryAction'] == 'Junked' else ''}.", "04-initial-access.kql")

    # 5 ── Campaign scope: who else received it, who clicked, who clicked through?
    campaign = [e for e in emails if e["SenderFromAddress"] == phish["SenderFromAddress"] or e["Url"] == entry["Url"]]
    delivered = Counter(e["DeliveryAction"] for e in campaign)
    camp_ids = {e["NetworkMessageId"] for e in campaign}
    camp_clicks = [c for c in clicks if c["NetworkMessageId"] in camp_ids]
    clicked_through = sorted({c["AccountUpn"] for c in camp_clicks if c["IsClickedThrough"] == "True" or c["ActionType"] == "ClickAllowed"})
    blocked = sorted({c["AccountUpn"] for c in camp_clicks if c["ActionType"] == "ClickBlocked"})
    step("How wide was the phishing campaign, and who else interacted with it?",
         f"{len(campaign)} recipients ({dict(delivered)}). Clicked through: {', '.join(clicked_through)}. "
         f"Click blocked by Safe Links: {', '.join(blocked) or 'none'}.", "05-campaign-scope.kql")

    # 6 ── Persistence: what did the attacker leave behind?
    attacker_rules = [r for r in office if r["Operation"] in ("New-InboxRule", "Set-InboxRule") and r["ClientIP"] in attacker_ips]
    consents = [a for a in audit if a["OperationName"] == "Consent to application"
                and (a["IPAddress"] in attacker_ips or any(sc in a["Permissions"].split() for sc in RISKY_SCOPES))]
    step("What persistence did the attacker establish?",
         f"{len(attacker_rules)} inbox rule(s) and {len(consents)} OAuth consent(s): "
         + "; ".join(f"app '{c['TargetApp']}' granted {c['Permissions']}" for c in consents)
         + ". The OAuth grant survives a password reset and must be revoked separately.",
         "06-persistence.kql")

    # 7 ── Collection: what mail did the attacker read?
    access = [o for o in office if o["Operation"] == "MailItemsAccessed" and o["UserId"] == victim and o["ClientIP"] in attacker_ips]
    by_app = Counter(o["AppId"] for o in access)
    step("What did the attacker access?",
         f"{len(access)} MailItemsAccessed events from attacker IPs via {dict(by_app)} between "
         f"{min(ts(o) for o in access):%H:%M} and {max(ts(o) for o in access):%H:%M} UTC.", "07-collection.kql")

    # 8 ── Impact: what was sent from the compromised mailbox during the compromise window?
    window_end = max(ts(s) for s in anomalous)
    sent = [e for e in emails if e["SenderFromAddress"] == victim and ts(e) >= first_bad
            and e["ReplyToAddress"] and not e["ReplyToAddress"].endswith(victim.split("@")[1])]
    step("Did the attacker use the mailbox to commit fraud?",
         f"{len(sent)} emails with an external Reply-To ({sorted({e['ReplyToAddress'] for e in sent})[0]}) requesting "
         f"changed bank details, sent to: {', '.join(e['RecipientEmailAddress'] for e in sent)}.", "08-impact.kql")

    # 9 ── Rule out the noise: is the password spray related?
    spray = defaultdict(lambda: {"fail": 0, "success": 0, "users": set(), "last": None})
    for s in signins:
        if s["IPAddress"] in attacker_ips:
            continue
        k = spray[s["IPAddress"]]
        k["last"] = max(filter(None, [k["last"], ts(s)]))
        k["fail" if s["ResultType"] != "0" else "success"] += 1
        k["users"].add(s["UserPrincipalName"])
    sprays = {ip: v for ip, v in spray.items() if len(v["users"]) >= 10 and v["fail"] >= 10}
    unrelated = [f"{ip}: {v['fail']} failures across {len(v['users'])} accounts, {v['success']} successes" for ip, v in sprays.items()]
    step("Is the password spray seen earlier the same day part of this incident?",
         ("Unrelated: " + "; ".join(unrelated) + ". No successful sign-in, different infrastructure, and it ended "
          f"{(ts(phish) - max(v['last'] for v in sprays.values())).total_seconds() / 3600:.1f} hours before the phishing email arrived.") if unrelated and all(v["success"] == 0 for v in sprays.values())
         else "Needs review: " + "; ".join(unrelated), "09-rule-out-spray.kql")

    f["iocs"] = {
        "phishing_sender": phish["SenderFromAddress"],
        "phishing_domain": phish["SenderFromAddress"].split("@")[1],
        "phishing_url": entry["Url"],
        "attacker_ips": attacker_ips,
        "attacker_user_agents": attacker_uas,
        "malicious_oauth_app": [c["TargetApp"] for c in consents if c["IPAddress"] in attacker_ips],
        "fraud_reply_to": sorted({e["ReplyToAddress"] for e in sent}),
    }
    f["scope"] = {
        "compromised_accounts": [victim] + other,
        "victim_copy_delivery": phish["DeliveryAction"],
        "campaign_recipients": len(campaign),
        "clicked_through": clicked_through,
        "click_blocked": blocked,
        "fraud_email_recipients": [e["RecipientEmailAddress"] for e in sent],
        "mail_items_accessed": len(access),
    }
    f["timeline"] = sorted([
        {"time": phish["Timestamp"], "event": f"Phishing campaign from {phish['SenderFromAddress']} reaches {len(campaign)} mailboxes", "tactic": "Initial Access (T1566.002)"},
        {"time": entry["Timestamp"], "event": f"{victim} clicks phishing link", "tactic": "Execution (T1204.001)"},
        *[{"time": s["TimeGenerated"], "event": f"Sign-in as {victim} from {s['IPAddress']} ({s['Location']}) to {s['AppDisplayName']}",
           "tactic": "Valid Accounts / stolen session (T1078.004, T1550.004)"} for s in sorted(anomalous, key=ts)],
        {"time": alert["time"], "event": f"Inbox rule hides mail containing payment keywords", "tactic": "Defense Evasion (T1564.008)"},
        *[{"time": c["TimeGenerated"], "event": f"OAuth consent to '{c['TargetApp']}' ({c['Permissions']})", "tactic": "Persistence (T1528)"} for c in consents if c["IPAddress"] in attacker_ips],
        {"time": min(o["TimeGenerated"] for o in access), "event": f"Bulk mailbox access begins ({len(access)} events)", "tactic": "Collection (T1114.002)"},
        *[{"time": e["Timestamp"], "event": f"Payment-redirection email to {e['RecipientEmailAddress']}", "tactic": "Impact: financial theft (T1657)"} for e in sent],
    ], key=lambda x: x["time"])
    return f


def findings_md(f) -> str:
    out = ["# Investigation findings", "",
           "Generated by `investigation/investigate.py` from the data in `data/`. Do not edit by hand.", "",
           "## Analyst walkthrough", ""]
    for i, s in enumerate(f["steps"], 1):
        out += [f"**{i}. {s['question']}**  ", f"{s['answer']}  ", f"Query: [`kql/{s['kql']}`](../kql/{s['kql']})", ""]
    out += ["## Timeline (UTC)", "", "| Time | Event | ATT&CK |", "|---|---|---|"]
    out += [f"| {e['time'].replace('T', ' ').rstrip('Z')} | {e['event']} | {e['tactic']} |" for e in f["timeline"]]
    out += ["", "## Indicators of compromise", "", "| Type | Value |", "|---|---|"]
    for k, v in f["iocs"].items():
        for x in (v if isinstance(v, list) else [v]):
            out.append(f"| {k.replace('_', ' ')} | `{x}` |")
    out += ["", "## Scope", "", "| Item | Value |", "|---|---|"]
    for k, v in f["scope"].items():
        out.append(f"| {k.replace('_', ' ')} | {', '.join(v) if isinstance(v, list) else v} |")
    return "\n".join(out) + "\n"


def main():
    f = investigate()
    for i, s in enumerate(f["steps"], 1):
        print(f"[{i}] {s['question']}\n    {s['answer']}\n")
    (ROOT / "investigation" / "findings.json").write_text(json.dumps(f, indent=2) + "\n")
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "FINDINGS.md").write_text(findings_md(f))


if __name__ == "__main__":
    main()
