"""Tests of the observability layer: gate summary, history snapshots, OTLP exporter, dashboard.

Standard library only: discovered by `python manage.py test` and by `python -m unittest`.
No network: the HTTP call to Grafana is replaced by a fake.
"""
import base64
import contextlib
import io
import json
import re
import secrets
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from ci import security_gate as gate
from ci import security_telemetry as telemetry

ROOT = Path(__file__).resolve().parents[2]
HISTORY = ROOT / "monitoring" / "history" / "security-history.json"
DASHBOARD = ROOT / "monitoring" / "grafana" / "pygoat-sentinel-dashboard.json"
CONTROLS = ["secrets", "sast_semgrep", "sast_bandit", "sca", "image", "iac_trivy", "iac_checkov", "dast"]
CI_ENV = {"CI_PROJECT_PATH": "group/pygoat", "CI_COMMIT_SHA": "a" * 40, "CI_COMMIT_SHORT_SHA": "aaaaaaaa",
          "CI_COMMIT_REF_NAME": "master", "CI_PIPELINE_ID": "123", "CI_PIPELINE_URL": "https://gitlab.example/p/123"}


def result(control, status="pass", block=0, warn=0, info=0, exempted=0):
    return {"control": control, "label": control, "status": status,
            "counts": {"block": block, "warn": warn, "info": info, "exempted": exempted}, "findings": []}


def run_quietly(func, *args, **kwargs):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = func(*args, **kwargs)
    return code, out.getvalue()


class GateSummaryTests(unittest.TestCase):

    def test_pass_summary(self):
        results = [result(c, warn=2, info=1) for c in CONTROLS]
        summary = gate.build_summary(results, [], blocked=False, env=CI_ENV)
        self.assertEqual(summary["gate_status"], "PASS")
        self.assertTrue(summary["release_allowed"])
        self.assertEqual(set(summary["controls"]), set(telemetry.CONTROLS))
        self.assertEqual(summary["totals"], {"blockers": 0, "warnings": 16, "info": 8, "exempted": 0})
        self.assertEqual(summary["pipeline_id"], "123")
        self.assertEqual(summary["commit_short_sha"], "aaaaaaaa")
        self.assertTrue(summary["generated_at"].endswith("Z"))

    def test_blocked_summary(self):
        results = [result(c) for c in CONTROLS]
        results[0] = result("secrets", "fail", block=3)
        summary = gate.build_summary(results, [], blocked=True, env=CI_ENV)
        self.assertEqual(summary["gate_status"], "BLOCKED")
        self.assertFalse(summary["release_allowed"])
        self.assertEqual(summary["controls"]["gitleaks"]["status"], "BLOCKED")
        self.assertEqual(summary["controls"]["gitleaks"]["blockers"], 3)

    def test_totals_are_the_sum_of_controls(self):
        results = [result(c, "fail" if i % 2 else "pass", block=i % 2 * i, warn=i, info=2 * i, exempted=i % 3)
                   for i, c in enumerate(CONTROLS)]
        summary = gate.build_summary(results, [], blocked=True, env=CI_ENV)
        for key in ("blockers", "warnings", "info", "exempted"):
            self.assertEqual(summary["totals"][key], sum(c[key] for c in summary["controls"].values()))

    def test_missing_reports_stay_fail_secure(self):
        """No report at all: every control is MISSING, counted as a blocker, the summary is still written."""
        with tempfile.TemporaryDirectory() as reports:
            with mock.patch.object(sys, "argv", ["security_gate.py", "--all", "--reports-dir", reports]):
                code, _ = run_quietly(gate.main)
            summary = json.loads((Path(reports) / "security-summary.json").read_text(encoding="utf-8"))
        self.assertEqual(code, 1)
        self.assertEqual(summary["gate_status"], "BLOCKED")
        self.assertFalse(summary["release_allowed"])
        self.assertEqual(len(summary["controls"]), 8)
        for control in summary["controls"].values():
            self.assertEqual(control["status"], "MISSING")
            self.assertEqual(control["blockers"], 1)
        self.assertEqual(summary["totals"]["blockers"], 8)

    def test_no_sensitive_value_in_summary(self):
        canary = secrets.token_hex(24)
        env = {**CI_ENV, "DJANGO_SECRET_KEY": canary, telemetry.ENV_TOKEN: canary, "CI_JOB_TOKEN": canary}
        summary = gate.build_summary([result(c) for c in CONTROLS], [], blocked=False, env=env)
        self.assertNotIn(canary, json.dumps(summary))


class HistoryTests(unittest.TestCase):

    def setUp(self):
        self.history = json.loads(HISTORY.read_text(encoding="utf-8"))

    def test_history_totals(self):
        snapshots = self.history["snapshots"]
        self.assertEqual([s["total_blockers"] for s in snapshots], [1104, 29, 25, 12, 0])
        for snap in snapshots:
            self.assertEqual(set(snap["blockers"]), set(telemetry.CONTROLS))
            self.assertEqual(sum(snap["blockers"].values()), snap["total_blockers"], snap["phase"])
            self.assertEqual(snap["gate_status"], "PASS" if snap["total_blockers"] == 0 else "BLOCKED")

    def test_history_provenance(self):
        snapshots = self.history["snapshots"]
        self.assertIn("provenance", self.history)
        self.assertEqual([s["committed_at"] for s in snapshots], sorted(s["committed_at"] for s in snapshots))
        for snap in snapshots:
            self.assertRegex(snap["commit"], r"^[0-9a-f]{40}$")
            self.assertTrue(snap["commit"].startswith(snap["commit_short"]))
            self.assertIsNone(snap["pipeline_id"], "historical pipeline IDs are not invented")
        self.assertNotIn("more secure", json.dumps(self.history).lower())


class TelemetryTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        results = [result(c, warn=1) for c in CONTROLS]
        results[-1] = result("dast", "missing", block=1)
        self.summary = gate.build_summary(results, [], blocked=True, env=CI_ENV)
        self.summary_path = self.dir / "security-summary.json"
        self.summary_path.write_text(json.dumps(self.summary), encoding="utf-8")
        self.payload_path = self.dir / "security-telemetry.json"
        self.token = secrets.token_hex(24)
        self.env = {telemetry.ENV_ENDPOINT: "https://otlp-gateway.example.net/otlp",
                    telemetry.ENV_INSTANCE: "123456", telemetry.ENV_TOKEN: self.token}

    def run_exporter(self, env, *extra):
        argv = ["--summary", str(self.summary_path), "--history", str(HISTORY),
                "--payload-out", str(self.payload_path), *extra]
        return run_quietly(telemetry.main, argv, env)

    def metrics(self):
        payload = json.loads(self.payload_path.read_text(encoding="utf-8"))
        return {m["name"]: m for m in payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]}

    @staticmethod
    def value(point):
        return point["asDouble"] if "asDouble" in point else int(point["asInt"])

    def test_dry_run_builds_expected_metrics(self):
        code, out = self.run_exporter(self.env, "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("Dry run", out)
        metrics = self.metrics()
        for name in ("pygoat_security_gate_status", "pygoat_security_release_allowed",
                     "pygoat_security_blockers_total", "pygoat_security_warnings_total", "pygoat_security_info_total",
                     "pygoat_security_blockers", "pygoat_security_warnings", "pygoat_security_info",
                     "pygoat_security_control_status", "pygoat_security_remediation_blockers",
                     "pygoat_security_remediation_control_blockers",
                     "pygoat_security_remediation_blocker_count_reduction_ratio"):
            self.assertIn(name, metrics)
        self.assertEqual(self.value(metrics["pygoat_security_gate_status"]["gauge"]["dataPoints"][0]), 0)
        self.assertEqual(self.value(metrics["pygoat_security_blockers_total"]["gauge"]["dataPoints"][0]), 1)
        self.assertIn("pygoat_security_report_present", metrics)
        self.assertEqual(len(metrics), 16)
        journey = [self.value(p) for p in metrics["pygoat_security_remediation_blockers"]["gauge"]["dataPoints"]]
        self.assertEqual(journey, [1104, 29, 25, 12, 0])
        ratio = metrics["pygoat_security_remediation_blocker_count_reduction_ratio"]["gauge"]["dataPoints"][0]
        self.assertEqual(self.value(ratio), 1.0)

    def per_control(self, metrics, name):
        return {next(a["value"]["stringValue"] for a in p["attributes"] if a["key"] == "control"): self.value(p)
                for p in metrics[name]["gauge"]["dataPoints"]}

    def test_pass_blocked_missing_are_distinguishable(self):
        """PASS = (1, 1); blocked by findings = (0, 1); missing evidence = (0, 0). No other value is emitted."""
        results = [result(c) for c in CONTROLS]
        results[0] = result("secrets", "fail", block=2)    # gitleaks: blocked by findings
        results[-1] = result("dast", "missing", block=1)   # zap: report missing (fail-secure)
        summary = gate.build_summary(results, [], blocked=True, env=CI_ENV)
        metrics = {m["name"]: m for m in telemetry.build_metrics(summary, None, 0)}
        status = self.per_control(metrics, "pygoat_security_control_status")
        present = self.per_control(metrics, "pygoat_security_report_present")
        self.assertEqual((status["semgrep"], present["semgrep"]), (1, 1))
        self.assertEqual((status["gitleaks"], present["gitleaks"]), (0, 1))
        self.assertEqual((status["zap"], present["zap"]), (0, 0))
        self.assertLessEqual(set(status.values()) | set(present.values()), {0, 1})
        self.assertEqual(set(status), set(telemetry.CONTROLS))
        self.assertEqual(set(present), set(telemetry.CONTROLS))

    def test_low_cardinality_labels(self):
        self.run_exporter({}, "--dry-run")
        allowed = {"project", "branch", "control", "phase", "commit", "from_phase", "to_phase",
                   "commit_short_sha", "pipeline_id", "gate_status"}
        for name, metric in self.metrics().items():
            for point in metric["gauge"]["dataPoints"]:
                keys = {a["key"] for a in point["attributes"]}
                self.assertLessEqual(keys, allowed, name)
                if name != "pygoat_security_pipeline_info":
                    self.assertNotIn("pipeline_id", keys, name)

    def test_not_configured_preserves_artifact(self):
        code, out = self.run_exporter({})
        self.assertEqual(code, 0)
        self.assertIn("Grafana telemetry not configured — artifact preserved", out)
        self.assertTrue(self.payload_path.exists())

    def test_partial_configuration_is_an_error(self):
        code, out = self.run_exporter({telemetry.ENV_ENDPOINT: self.env[telemetry.ENV_ENDPOINT]})
        self.assertEqual(code, telemetry.CONFIG_ERROR)
        self.assertIn("GRAFANA_OTLP_TOKEN", out)

    def test_plain_http_endpoint_is_refused(self):
        code, _ = self.run_exporter({**self.env, telemetry.ENV_ENDPOINT: "http://otlp-gateway.example.net/otlp"})
        self.assertEqual(code, telemetry.CONFIG_ERROR)

    def test_missing_summary_is_an_error(self):
        self.summary_path.unlink()
        code, out = self.run_exporter(self.env)
        self.assertEqual(code, telemetry.CONFIG_ERROR)
        self.assertIn("not found", out)

    def test_metrics_url(self):
        self.assertEqual(telemetry.metrics_url("https://h.example.net/otlp"), "https://h.example.net/otlp/v1/metrics")
        self.assertEqual(telemetry.metrics_url("https://h.example.net/otlp/v1/metrics/"),
                         "https://h.example.net/otlp/v1/metrics")

    def test_successful_export_never_prints_the_token(self):
        sent = {}

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(request, timeout):
            sent["url"], sent["headers"], sent["body"] = request.full_url, dict(request.header_items()), request.data
            return FakeResponse()

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            code, out = self.run_exporter(self.env)
        self.assertEqual(code, 0)
        self.assertIn("Security telemetry exported successfully", out)
        self.assertEqual(sent["url"], "https://otlp-gateway.example.net/otlp/v1/metrics")
        credentials = base64.b64encode(f"123456:{self.token}".encode()).decode()
        self.assertEqual(sent["headers"]["Authorization"], f"Basic {credentials}")
        for leaked in (self.token, credentials, "Authorization"):
            self.assertNotIn(leaked, out)
            self.assertNotIn(leaked, self.payload_path.read_text(encoding="utf-8"))
        self.assertNotIn(self.token.encode(), sent["body"])

    def test_grafana_failure_is_tolerated_and_redacted(self):
        def refused(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {},
                                         io.BytesIO(f"invalid token {self.token}".encode()))

        with mock.patch("urllib.request.urlopen", refused):
            code, out = self.run_exporter(self.env)
        self.assertEqual(code, telemetry.EXPORT_FAILURE)
        self.assertIn("HTTP 401", out)
        self.assertNotIn(self.token, out)

    def test_unreachable_grafana_is_tolerated(self):
        def unreachable(request, timeout):
            raise urllib.error.URLError("Name or service not known")

        with mock.patch("urllib.request.urlopen", unreachable):
            code, out = self.run_exporter(self.env)
        self.assertEqual(code, telemetry.EXPORT_FAILURE)
        self.assertIn("unreachable", out)


class DashboardTests(unittest.TestCase):

    def test_dashboard_is_importable_and_has_no_credentials(self):
        text = DASHBOARD.read_text(encoding="utf-8")
        dashboard = json.loads(text)
        self.assertEqual(dashboard["title"], "PyGoat Sentinel — DevSecOps Security Control Center")
        numbered = [p for p in dashboard["panels"] if re.match(r"^\d+ · ", p["title"])]
        self.assertEqual(len(numbered), 10)
        variables = {v["name"]: v for v in dashboard["templating"]["list"]}
        self.assertEqual(variables["datasource"]["type"], "datasource")
        self.assertEqual(variables["datasource"]["query"], "prometheus")
        for p in dashboard["panels"]:
            self.assertEqual(p["datasource"]["uid"], "${datasource}", p["title"])
            for t in p["targets"]:
                self.assertEqual(t["datasource"]["uid"], "${datasource}", p["title"])
        matrix = next(p for p in dashboard["panels"] if p["title"].startswith("9 · "))
        self.assertIn("pygoat_security_report_present", json.dumps(matrix["targets"]))
        organize = next(t for t in matrix["transformations"] if t["id"] == "organize")["options"]
        columns = sorted(organize["indexByName"], key=organize["indexByName"].get)
        self.assertEqual([organize["renameByName"][c] for c in columns],
                         ["Control", "Status", "Evidence", "Blockers", "Warnings", "Info"])
        mappings = {o["matcher"]["options"]: o["properties"][0]["value"][0]["options"]
                    for o in matrix["fieldConfig"]["overrides"] if o["properties"][0]["id"] == "mappings"}
        self.assertEqual(set(mappings["Status"]), {"1", "0"})
        self.assertEqual(mappings["Evidence"]["0"]["text"], "MISSING")
        self.assertNotIn("-1", json.dumps(mappings))
        self.assertEqual(list(variables), ["datasource", "project", "branch"])
        for forbidden in ("glc_", "Authorization", "Bearer", "Basic "):
            self.assertNotIn(forbidden, text)
        self.assertNotIn("more secure", text.lower())

    def panel(self, number):
        dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
        return next(p for p in dashboard["panels"] if p["title"].startswith(f"{number} · "))

    def test_gate_history_is_a_real_time_series(self):
        """Panel 8: range query on the live metric, rendered as a time series (needs a time field)."""
        history = self.panel(8)
        self.assertEqual(history["type"], "timeseries")
        target = history["targets"][0]
        self.assertTrue(target["range"])
        self.assertFalse(target["instant"])
        self.assertEqual(target["format"], "time_series")
        self.assertIn('pygoat_security_gate_status{project="$project", branch="$branch"}', target["expr"])
        defaults = history["fieldConfig"]["defaults"]
        self.assertEqual((defaults["min"], defaults["max"]), (0, 1))
        self.assertIn("1 = PASS, 0 = BLOCKED", history["description"])
        self.assertNotIn("transformations", history)

    def test_pipeline_context_uses_pipeline_info(self):
        """Panel 10: plain last_over_time on pygoat_security_pipeline_info, no timestamp() subquery."""
        context = self.panel(10)
        expr = context["targets"][0]["expr"]
        self.assertIn('pygoat_security_pipeline_info{project="$project", branch="$branch"}', expr)
        self.assertIn("last_over_time(", expr)
        self.assertNotIn("timestamp(", expr)
        self.assertNotIn(":5m]", expr)
        organize = next(t for t in context["transformations"] if t["id"] == "organize")["options"]
        columns = sorted(organize["indexByName"], key=organize["indexByName"].get)
        self.assertEqual([organize["renameByName"][c] for c in columns], ["Gate", "Commit", "Pipeline", "Project"])
        self.assertTrue(organize["excludeByName"]["Value"])
        link = context["fieldConfig"]["overrides"][0]["properties"][0]["value"][0]["url"]
        self.assertEqual(link, "https://gitlab.com/${project:raw}/-/pipelines/${__value.raw}")


class BeforeAfterTests(unittest.TestCase):
    """BEFORE vs AFTER section: validated historical data only, numbers recomputed from the history file."""

    BEFORE, AFTER = "1-initial-baseline", "5-final-secure-baseline"

    def setUp(self):
        self.dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
        self.history = json.loads(HISTORY.read_text(encoding="utf-8"))
        self.snap = {s["phase"]: s for s in self.history["snapshots"]}
        self.section = [p for p in self.dashboard["panels"] if 11 <= p["id"] <= 18]

    def panel(self, prefix):
        return next(p for p in self.dashboard["panels"] if p["title"].startswith(prefix))

    def test_section_added_and_existing_panels_kept(self):
        numbered = sorted(int(p["title"].split(" · ")[0]) for p in self.dashboard["panels"]
                          if re.match(r"^\d+ · ", p["title"]))
        self.assertEqual(numbered, list(range(1, 11)))
        self.assertEqual(self.dashboard["title"], "PyGoat Sentinel — DevSecOps Security Control Center")
        for prefix in ("BEFORE — Initial baseline", "TRANSFORMATION", "AFTER — Current secure baseline",
                       "BEFORE — Initial blockers by control", "Blocker-count reduction — NOT a security score",
                       "AFTER — Blockers by control", "Security improvement summary"):
            self.panel(prefix)
        header = next(p for p in self.section if p["type"] == "text")["options"]["content"]
        self.assertIn("BEFORE vs AFTER — SECURITY POSTURE", header)
        self.assertIn("NOT a security score", header)

    def test_section_uses_only_validated_historical_metrics(self):
        for p in self.section:
            for t in p["targets"]:
                metrics = set(re.findall(r"pygoat_security_\w+", t["expr"]))
                self.assertTrue(metrics, p["title"])
                for m in metrics:
                    self.assertTrue(m.startswith("pygoat_security_remediation_"), (p["title"], m))
                for phase in re.findall(r'phase=~?"([^"]+)"', t["expr"]):
                    self.assertLessEqual(set(phase.split("|")), {self.BEFORE, self.AFTER}, p["title"])
                self.assertEqual(t["datasource"]["uid"], "${datasource}")
        text = json.dumps(self.section)
        self.assertNotIn("100% secure", text)
        self.assertNotIn("vulnerabilities fixed", text.lower())

    def category_total(self, phase, expr):
        """Recomputes a summary cell from the history file, using the control filter of its PromQL."""
        blockers = self.snap[phase]["blockers"]
        match = re.search(r'control=~"([^"]+)"', expr)
        controls = match.group(1).split("|") if match else list(blockers)
        return sum(blockers[c] for c in controls)

    def test_summary_numbers_match_the_validated_history(self):
        summary = self.panel("Security improvement summary")
        names = next(t for t in summary["transformations"] if t["id"] == "organize")["options"]["renameByName"]
        queries = {names[f"Value #{t['refId']}"]: t["expr"] for t in summary["targets"]}
        expected = {"Secret blockers": (13, 0), "SAST blockers": (12, 0),
                    "Dependency/Image blockers": (1077, 0), "IaC blockers": (2, 0)}
        for name, values in expected.items():
            self.assertEqual((self.category_total(self.BEFORE, queries[name]),
                              self.category_total(self.AFTER, queries[name])), values, name)
        self.assertEqual((self.snap[self.BEFORE]["total_blockers"], self.snap[self.AFTER]["total_blockers"]),
                         (1104, 0))
        with_blockers = [sum(v > 0 for v in self.snap[p]["blockers"].values()) for p in (self.BEFORE, self.AFTER)]
        self.assertEqual(with_blockers, [7, 0])
        self.assertEqual(len(self.history["controls"]), 8)
        self.assertEqual((self.snap[self.BEFORE]["gate_status"], self.snap[self.AFTER]["gate_status"]),
                         ("BLOCKED", "PASS"))
        self.assertIn("> bool 0", queries["Controls with blockers"])
        self.assertIn("== bool 0", queries["Security Gate"])
        self.assertIn("== bool 0", queries["Release"])
        # categories + DAST (0) account for every blocking finding of the baseline
        self.assertEqual(sum(v[0] for v in expected.values()) + self.snap[self.BEFORE]["blockers"]["zap"], 1104)

    def test_before_is_red_after_is_green(self):
        before = self.panel("BEFORE — Initial blockers by control")
        after = self.panel("AFTER — Blockers by control")
        self.assertEqual(before["fieldConfig"]["defaults"]["color"]["fixedColor"], "red")
        self.assertEqual(after["fieldConfig"]["defaults"]["color"]["fixedColor"], "green")
        self.assertIn(f'phase="{self.BEFORE}"', before["targets"][0]["expr"])
        self.assertIn(f'phase="{self.AFTER}"', after["targets"][0]["expr"])
        sort = next(t for t in before["transformations"] if t["id"] == "sortBy")["options"]["sort"][0]
        self.assertTrue(sort["desc"])


if __name__ == "__main__":
    unittest.main()
