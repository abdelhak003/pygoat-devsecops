"""Exception / false-positive workflow of the Security Gate — SYNTHETIC findings only.

Every report and registry used here is written to a temporary directory: the real reports,
the real registry (ci/exemptions.toml) and the project history are never touched.
"""
import datetime as dt
import json
import re
import tempfile
import unittest
from pathlib import Path

from ci import security_gate as gate

TODAY = dt.date(2026, 10, 9)
DEMO_RULE = "DEMO-FINGERPRINT-DO-NOT-USE"
DEMO_FILE = "demo/synthetic_example.py"
DEMO_FINGERPRINT = f"{DEMO_RULE}|{DEMO_FILE}:10"


def bandit_issue(line=10, severity="HIGH", rule=DEMO_RULE):
    return {"test_id": rule, "filename": f"./{DEMO_FILE}", "line_number": line, "issue_severity": severity,
            "issue_confidence": "HIGH", "issue_text": "SYNTHETIC finding for the exemption workflow tests",
            "issue_cwe": {"id": 0}}


def exemption(**overrides):
    entry = {"id": "EXC-001", "control": "sast_bandit", "fingerprint": DEMO_FINGERPRINT,
             "reason": "Synthetic false positive used only by the automated tests.",
             "owner": "developer.demo", "approver": "security.demo", "ticket": "#DEMO",
             "created": TODAY - dt.timedelta(days=1), "expires": TODAY + dt.timedelta(days=13)}
    entry.update(overrides)
    return {k: v for k, v in entry.items() if v is not None}


def to_toml(entries):
    lines = []
    for e in entries:
        lines.append("[[exemption]]")
        for key, value in e.items():
            raw = value.isoformat() if isinstance(value, dt.date) else json.dumps(value)
            lines.append(f"{key} = {raw}")
        lines.append("")
    return "\n".join(lines)


class ExemptionWorkflowTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.reports = self.dir / "reports"
        self.reports.mkdir()
        self.registry = self.dir / "exemptions.toml"
        self.write_report([bandit_issue()])

    def write_report(self, issues):
        (self.reports / "bandit.json").write_text(json.dumps({"results": issues}), encoding="utf-8")

    def gate(self, entries=None, raw=None, today=TODAY):
        if raw is not None:
            self.registry.write_text(raw, encoding="utf-8")
        elif entries is not None:
            self.registry.write_text(to_toml(entries), encoding="utf-8")
        elif self.registry.exists():
            self.registry.unlink()
        results, state, blocked = gate.run_gate(["sast_bandit"], self.reports, today, self.registry)
        return results[0], state, blocked

    # ------------------------------------------------------------------ matching

    def test_no_exemption_means_normal_blocking(self):
        result, state, blocked = self.gate()
        self.assertTrue(blocked)
        self.assertEqual(result["counts"], {"block": 1, "warn": 0, "info": 0, "exempted": 0})
        self.assertEqual(result["findings"][0]["fingerprint"], DEMO_FINGERPRINT)
        self.assertEqual(state, {"applied": [], "unused": [], "expired": [], "errors": []})

    def test_exact_active_exemption_covers_one_blocker_and_keeps_it_visible(self):
        result, state, blocked = self.gate([exemption()])
        self.assertFalse(blocked)
        self.assertEqual(result["counts"], {"block": 0, "warn": 0, "info": 0, "exempted": 1})
        finding = result["findings"][0]
        self.assertEqual((finding["level"], finding["exempted_by"]), ("exempted", "EXC-001"))
        self.assertEqual(finding["fingerprint"], DEMO_FINGERPRINT)
        audit = state["applied"][0]
        self.assertEqual({k: audit[k] for k in ("id", "control", "fingerprint", "owner", "approver", "ticket")},
                         {"id": "EXC-001", "control": "sast_bandit", "fingerprint": DEMO_FINGERPRINT,
                          "owner": "developer.demo", "approver": "security.demo", "ticket": "#DEMO"})
        self.assertEqual(audit["expires"], "2026-10-22")

    def test_only_the_matching_finding_is_exempted(self):
        self.write_report([bandit_issue(line=10), bandit_issue(line=42)])
        result, _, blocked = self.gate([exemption()])
        self.assertTrue(blocked)
        self.assertEqual(result["counts"]["block"], 1)
        self.assertEqual(result["counts"]["exempted"], 1)
        levels = {f["fingerprint"]: f["level"] for f in result["findings"]}
        self.assertEqual(levels, {DEMO_FINGERPRINT: "exempted", f"{DEMO_RULE}|{DEMO_FILE}:42": "block"})

    def test_different_fingerprint_is_not_exempted(self):
        _, state, blocked = self.gate([exemption(fingerprint=f"{DEMO_RULE}|{DEMO_FILE}:11")])
        self.assertTrue(blocked)
        self.assertEqual(state["applied"], [])
        self.assertEqual(state["unused"], ["EXC-001"])

    def test_different_control_is_not_exempted(self):
        result, state, blocked = self.gate([exemption(control="secrets")])
        self.assertTrue(blocked)
        self.assertEqual(result["counts"]["block"], 1)
        self.assertEqual(state["unused"], ["EXC-001"])

    def test_exemption_never_touches_non_blocking_findings(self):
        self.write_report([bandit_issue(severity="MEDIUM")])
        result, state, blocked = self.gate([exemption()])
        self.assertFalse(blocked)
        self.assertEqual(result["counts"], {"block": 0, "warn": 1, "info": 0, "exempted": 0})
        self.assertEqual(state["unused"], ["EXC-001"])

    # ------------------------------------------------------------------ expiration

    def test_expired_exemption_does_not_exempt(self):
        expired = exemption(created=TODAY - dt.timedelta(days=30), expires=TODAY - dt.timedelta(days=1))
        result, state, blocked = self.gate([expired])
        self.assertTrue(blocked)
        self.assertEqual(result["counts"]["block"], 1)
        self.assertEqual(result["findings"][0]["exempted_by"], "")
        self.assertEqual([e["id"] for e in state["expired"]], ["EXC-001"])
        self.assertEqual(state["errors"], [], "an expired entry is not a configuration error")

    def test_expired_exemption_does_not_affect_unrelated_findings(self):
        """Finding fixed long ago + old expired entry: the gate must PASS (previously: global BLOCK)."""
        self.write_report([])
        expired = exemption(created=TODAY - dt.timedelta(days=60), expires=TODAY - dt.timedelta(days=5))
        _, state, blocked = self.gate([expired])
        self.assertFalse(blocked)
        self.assertEqual([e["id"] for e in state["expired"]], ["EXC-001"])

    def test_expired_exemption_does_not_disable_other_active_exemptions(self):
        self.write_report([bandit_issue(line=10), bandit_issue(line=42)])
        entries = [exemption(id="EXC-001", created=TODAY - dt.timedelta(days=30),
                             expires=TODAY - dt.timedelta(days=1)),
                   exemption(id="EXC-002", fingerprint=f"{DEMO_RULE}|{DEMO_FILE}:42")]
        result, state, blocked = self.gate(entries)
        self.assertTrue(blocked)
        levels = {f["fingerprint"]: f["level"] for f in result["findings"]}
        self.assertEqual(levels, {DEMO_FINGERPRINT: "block", f"{DEMO_RULE}|{DEMO_FILE}:42": "exempted"})
        self.assertEqual([e["id"] for e in state["applied"]], ["EXC-002"])

    def test_expiry_date_is_inclusive(self):
        _, _, blocked = self.gate([exemption(expires=TODAY)])
        self.assertFalse(blocked)
        _, state, blocked = self.gate([exemption(expires=TODAY)], today=TODAY + dt.timedelta(days=1))
        self.assertTrue(blocked)
        self.assertEqual(len(state["expired"]), 1)

    # ------------------------------------------------------------------ malformed configuration

    def assert_rejected(self, entries=None, raw=None, expected=""):
        result, state, blocked = self.gate(entries, raw)
        self.assertTrue(blocked, expected)
        self.assertTrue(state["errors"], expected)
        self.assertIn(expected, " ".join(state["errors"]))
        self.assertEqual(state["applied"], [], "a malformed entry is never applied")
        self.assertEqual(result["counts"]["block"], 1)

    def test_missing_mandatory_audit_fields_are_rejected(self):
        for name in ("fingerprint", "reason", "owner", "approver", "ticket", "created", "expires", "control"):
            self.assert_rejected([exemption(**{name: None})], expected="champs obligatoires manquants")
        self.assert_rejected([exemption(ticket="")], expected="champs obligatoires manquants")

    def test_wildcards_and_legacy_match_are_rejected(self):
        """An exemption can never mean « ignore everything from this scanner »."""
        for fp in ("*", f"{DEMO_RULE}|*", f"*|{DEMO_FILE}:10", f"{DEMO_RULE}|demo/?.py:10", DEMO_RULE,
                   f"{DEMO_RULE}|", f" {DEMO_FINGERPRINT}"):
            self.assert_rejected([exemption(fingerprint=fp)], expected="fingerprint exact")
        self.assert_rejected([{**exemption(), "match": "*"}], expected="champs inconnus")
        self.assert_rejected([{**exemption(), "path": "*"}], expected="champs inconnus")

    def test_other_malformed_entries_are_rejected(self):
        cases = [
            (exemption(owner="Same.Person", approver="same.person"), "4 yeux"),
            (exemption(control="unknown_control"), "contrôle inconnu"),
            (exemption(id="1"), "EXC-NNN"),
            (exemption(reason="false positive"), "justification trop courte"),
            (exemption(created=TODAY - dt.timedelta(days=1), expires=TODAY + dt.timedelta(days=95)), "durée >"),
            (exemption(expires=TODAY - dt.timedelta(days=3)), "antérieure"),
            (exemption(created=TODAY + dt.timedelta(days=1), expires=TODAY + dt.timedelta(days=5)), "futur"),
            (exemption(created="2026-10-08"), "dates TOML"),
            (exemption(expires=dt.datetime(2026, 10, 20, 12, 0)), "dates TOML"),
            (exemption(ticket=42), "doivent être des textes"),
        ]
        for entry, expected in cases:
            self.assert_rejected([entry], expected=expected)

    def test_duplicate_ids_and_broken_registry_are_rejected(self):
        self.assert_rejected([exemption(), exemption(fingerprint=f"{DEMO_RULE}|{DEMO_FILE}:11")],
                             expected="id déjà utilisé")
        self.assert_rejected(raw="[[exemption]\nid = ", expected="registre illisible")
        self.assert_rejected(raw='exemption = "everything"', expected="registre mal formé")
        self.assert_rejected(raw='[settings]\nignore_all = true', expected="registre mal formé")

    def test_malformed_registry_blocks_even_without_findings(self):
        self.write_report([])
        _, state, blocked = self.gate([exemption(fingerprint="*")])
        self.assertTrue(blocked)
        self.assertTrue(state["errors"])

    # ------------------------------------------------------------------ evidence

    def test_exemption_is_traceable_in_summary_markdown_and_junit(self):
        self.gate([exemption()])
        conf = gate.tomllib.loads(gate.POLICY_FILE.read_text(encoding="utf-8"))
        results, state, blocked = gate.run_gate(None, self.reports, TODAY, self.registry, conf)
        out = self.dir / "out"
        out.mkdir()
        gate.write_outputs(results, state, out, "BLOQUÉ" if blocked else "AUTORISÉ")
        summary = json.loads((out / "security-summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["controls"]["bandit"]["exempted"], 1)
        self.assertEqual(summary["controls"]["bandit"]["blockers"], 0)
        self.assertEqual(summary["exemptions"]["applied"][0]["id"], "EXC-001")
        self.assertEqual(summary["exemptions"]["applied"][0]["approver"], "security.demo")
        self.assertIn("EXC-001", (out / "security-summary.md").read_text(encoding="utf-8"))
        junit = (out / "junit-security.xml").read_text(encoding="utf-8")
        skipped = re.findall(r'<skipped message="([^"]*)"/>', junit)
        self.assertEqual(skipped, ["exempté par EXC-001"])
        self.assertIn(f'name="{DEMO_RULE} — {DEMO_FILE}:10"', junit)

    def test_real_registry_contains_no_exemption(self):
        conf = gate.tomllib.loads(gate.POLICY_FILE.read_text(encoding="utf-8"))
        active, expired, errors = gate.load_exemptions(conf["policy"], conf["controls"], dt.date.today())
        self.assertEqual((active, expired, errors), ([], [], []))
        raw = gate.tomllib.loads(gate.EXEMPTIONS_FILE.read_text(encoding="utf-8"))
        self.assertEqual(raw.get("exemption", []), [])


if __name__ == "__main__":
    unittest.main()
