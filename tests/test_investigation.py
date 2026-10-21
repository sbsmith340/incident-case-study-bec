"""The investigation must reach the right answers from the data alone, and the
hand-written report must agree with what the code found."""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "investigation"))
import investigate  # noqa: E402

F = investigate.investigate()
REPORT = (ROOT / "REPORT.md").read_text()


def test_dataset_is_reproducible(tmp_path):
    before = {p.name: p.read_bytes() for p in (ROOT / "data").glob("*.csv")}
    subprocess.run([sys.executable, str(ROOT / "data" / "generate.py")], check=True, capture_output=True)
    after = {p.name: p.read_bytes() for p in (ROOT / "data").glob("*.csv")}
    assert before == after


def test_identifies_single_compromised_account():
    assert F["scope"]["compromised_accounts"] == ["ana.ruiz@contoso.com"]


def test_derives_attacker_infrastructure():
    assert F["iocs"]["attacker_ips"] == ["198.51.100.23", "198.51.100.41"]
    assert F["iocs"]["phishing_sender"] == "docs-share@fabrikam-invoices.com"
    assert F["iocs"]["malicious_oauth_app"] == ["Mail Organizer Pro"]


def test_distinguishes_blocked_click_from_compromise():
    assert F["scope"]["clicked_through"] == ["ana.ruiz@contoso.com"]
    assert F["scope"]["click_blocked"] == ["kevin.ng@contoso.com"]


def test_finds_all_fraud_emails():
    assert sorted(F["scope"]["fraud_email_recipients"]) == [
        "billing@northwind-supplies.com", "marcus.green@contoso.com", "nina.rossi@contoso.com"]


def test_rules_out_password_spray():
    spray = F["steps"][8]["answer"]
    assert spray.startswith("Unrelated") and "0 successes" in spray


def test_every_step_has_a_kql_file():
    for s in F["steps"]:
        assert (ROOT / "kql" / s["kql"]).exists(), s["kql"]


def test_report_lists_every_ioc_the_code_found():
    for k, v in F["iocs"].items():
        for x in (v if isinstance(v, list) else [v]):
            if k == "attacker_user_agents":
                assert "HeadlessChrome/128.0" in REPORT
            else:
                assert f"`{x}`" in REPORT, f"{k}: {x} missing from REPORT.md"


def test_report_numbers_match_findings():
    assert f"{F['scope']['campaign_recipients']} recipients" in REPORT
    assert f"{F['scope']['mail_items_accessed']} mail items" in REPORT
    assert "**1**: ana.ruiz@contoso.com" in REPORT


def test_generated_findings_are_current():
    assert (ROOT / "docs" / "FINDINGS.md").read_text() == investigate.findings_md(F)
    assert json.loads((ROOT / "investigation" / "findings.json").read_text()) == json.loads(json.dumps(F))
