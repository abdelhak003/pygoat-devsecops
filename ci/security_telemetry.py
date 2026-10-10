#!/usr/bin/env python3
"""Exports the Security Gate result to Grafana Cloud as OTLP/HTTP JSON metrics.

    SCANNERS DETECT  →  SECURITY GATE DECIDES  →  GRAFANA VISUALISES

This script only READS reports/security-summary.json (written by ci/security_gate.py --all)
and monitoring/history/security-history.json. It has no influence on the gate decision.

Configuration (GitLab CI/CD variables):
    GRAFANA_OTLP_ENDPOINT     OTLP base URL, e.g. https://otlp-gateway-prod-<region>.grafana.net/otlp
    GRAFANA_OTLP_INSTANCE_ID  Grafana Cloud OTLP instance ID (numeric)
    GRAFANA_OTLP_TOKEN        Grafana Cloud access policy token (SECRET: never printed)

Exit codes:
    0  exported, not configured (artifact preserved) or --dry-run
    2  configuration / input error   (job fails: must be fixed)
    3  Grafana unreachable or refused the data (tolerated by the CI job: allow_failure)

Python standard library only.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG_ERROR = 2
EXPORT_FAILURE = 3
ENV_ENDPOINT, ENV_INSTANCE, ENV_TOKEN = "GRAFANA_OTLP_ENDPOINT", "GRAFANA_OTLP_INSTANCE_ID", "GRAFANA_OTLP_TOKEN"
CONTROLS = ("gitleaks", "semgrep", "bandit", "trivy_fs", "trivy_image", "trivy_config", "checkov", "zap")
SCOPE = {"name": "pygoat.security", "version": "1.0"}
CONTROL_STATUSES = ("PASS", "BLOCKED", "MISSING")


class TelemetryConfigError(ValueError):
    """Invalid input or configuration: fails the job visibly."""


# --------------------------------------------------------------------------- inputs

def load_json(path: Path, label: str) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise TelemetryConfigError(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        raise TelemetryConfigError(f"{label} is not valid JSON: {exc}")


def validate_summary(summary: dict) -> dict:
    required = ("schema_version", "project", "branch", "gate_status", "release_allowed", "controls", "totals")
    missing = [k for k in required if k not in summary]
    if missing:
        raise TelemetryConfigError(f"security-summary.json: missing fields {missing}")
    if summary["gate_status"] not in ("PASS", "BLOCKED"):
        raise TelemetryConfigError("security-summary.json: gate_status must be PASS or BLOCKED")
    if summary["release_allowed"] is not (summary["gate_status"] == "PASS"):
        raise TelemetryConfigError("security-summary.json: release_allowed contradicts gate_status")
    for name, control in summary["controls"].items():
        if control.get("status") not in CONTROL_STATUSES:
            raise TelemetryConfigError(f"security-summary.json: controls.{name}.status must be PASS, BLOCKED or MISSING")
        for key in ("blockers", "warnings", "info", "exempted"):
            if not isinstance(control.get(key), int) or control[key] < 0:
                raise TelemetryConfigError(f"security-summary.json: controls.{name}.{key} must be an integer >= 0")
    return summary


def validate_history(history: dict) -> dict:
    snapshots = history.get("snapshots")
    if not snapshots:
        raise TelemetryConfigError("security-history.json: no snapshots")
    for snap in snapshots:
        if sum(snap["blockers"].values()) != snap["total_blockers"]:
            raise TelemetryConfigError(f"security-history.json: {snap['phase']} total does not match its controls")
    return history


# --------------------------------------------------------------------------- metrics

def _attrs(**labels) -> list:
    return [{"key": k, "value": {"stringValue": str(v)}} for k, v in labels.items()]


def _gauge(name: str, description: str, points: list, now_ns: int) -> dict:
    data_points = []
    for value, labels in points:
        point = {"timeUnixNano": str(now_ns), "attributes": _attrs(**labels)}
        if isinstance(value, float):
            point["asDouble"] = value
        else:
            point["asInt"] = str(int(value))
        data_points.append(point)
    return {"name": name, "description": description, "gauge": {"dataPoints": data_points}}


def build_metrics(summary: dict, history: dict | None, now_ns: int) -> list:
    """Live metrics (current pipeline) + historical comparison metrics (validated snapshots)."""
    base = {"project": summary["project"], "branch": summary["branch"]}
    passed = summary["gate_status"] == "PASS"
    totals = summary["totals"]
    controls = summary["controls"]

    def per_control(key):
        return [(controls[c][key], {**base, "control": c}) for c in CONTROLS if c in controls]

    metrics = [
        _gauge("pygoat_security_gate_status", "Security Gate decision: 1 = PASS, 0 = BLOCKED",
               [(1 if passed else 0, base)], now_ns),
        _gauge("pygoat_security_release_allowed", "Release allowed by the Security Gate: 1 = yes, 0 = no",
               [(1 if summary["release_allowed"] else 0, base)], now_ns),
        _gauge("pygoat_security_blockers_total", "Blocking findings, all controls", [(totals["blockers"], base)], now_ns),
        _gauge("pygoat_security_warnings_total", "Warning findings, all controls", [(totals["warnings"], base)], now_ns),
        _gauge("pygoat_security_info_total", "Informational findings, all controls", [(totals["info"], base)], now_ns),
        _gauge("pygoat_security_exempted_total", "Findings covered by a valid exemption", [(totals["exempted"], base)], now_ns),
        _gauge("pygoat_security_blockers", "Blocking findings per control", per_control("blockers"), now_ns),
        _gauge("pygoat_security_warnings", "Warning findings per control", per_control("warnings"), now_ns),
        _gauge("pygoat_security_info", "Informational findings per control", per_control("info"), now_ns),
        _gauge("pygoat_security_control_status", "Control status: 1 = PASS, 0 = BLOCKED or report MISSING",
               [(1 if controls[c]["status"] == "PASS" else 0, {**base, "control": c}) for c in CONTROLS if c in controls],
               now_ns),
        # Fail-secure evidence: separates "blocked by findings" from "no report, the scan did not run".
        _gauge("pygoat_security_report_present", "Scanner report present: 1 = report OK, 0 = report MISSING",
               [(0 if controls[c]["status"] == "MISSING" else 1, {**base, "control": c})
                for c in CONTROLS if c in controls], now_ns),
        # Pipeline context: the only metric carrying per-pipeline values (one series per run, value 1).
        _gauge("pygoat_security_pipeline_info", "Context of the latest exported pipeline (value is always 1)",
               [(1, {**base, "commit_short_sha": summary.get("commit_short_sha", ""),
                     "pipeline_id": summary.get("pipeline_id", ""), "gate_status": summary["gate_status"]})], now_ns),
    ]

    if history:
        snapshots = history["snapshots"]
        first, last = snapshots[0], snapshots[-1]
        project = {"project": summary["project"]}
        metrics += [
            _gauge("pygoat_security_remediation_blockers",
                   "HISTORICAL validated snapshot: blocking findings at each remediation phase",
                   [(s["total_blockers"], {**project, "phase": s["phase"], "commit": s["commit_short"]})
                    for s in snapshots], now_ns),
            _gauge("pygoat_security_remediation_control_blockers",
                   "HISTORICAL validated snapshot: blocking findings per control at each remediation phase",
                   [(s["blockers"][c], {**project, "phase": s["phase"], "control": c})
                    for s in snapshots for c in CONTROLS], now_ns),
            _gauge("pygoat_security_remediation_blocker_count_reduction_ratio",
                   "HISTORICAL: (first - last) / first blocking findings. Blocker-count reduction, NOT a security score",
                   [((first["total_blockers"] - last["total_blockers"]) / first["total_blockers"]
                     if first["total_blockers"] else 0.0,
                     {**project, "from_phase": first["phase"], "to_phase": last["phase"]})], now_ns),
            _gauge("pygoat_security_remediation_blockers_removed",
                   "HISTORICAL: number of blocking findings removed between the first and last snapshot",
                   [(first["total_blockers"] - last["total_blockers"],
                     {**project, "from_phase": first["phase"], "to_phase": last["phase"]})], now_ns),
        ]
    return metrics


def build_payload(summary: dict, history: dict | None, now_ns: int | None = None) -> dict:
    now_ns = now_ns if now_ns is not None else time.time_ns()
    resource = _attrs(**{
        "service.name": "pygoat-security-gate",
        "service.namespace": "devsecops",
        "service.instance.id": "gitlab-ci",    # constant on purpose: no new series per pipeline
        "vcs.commit.sha": summary.get("commit_sha", ""),
        "cicd.pipeline.id": summary.get("pipeline_id", ""),
    })
    return {"resourceMetrics": [{"resource": {"attributes": resource},
                                 "scopeMetrics": [{"scope": SCOPE, "metrics": build_metrics(summary, history, now_ns)}]}]}


# --------------------------------------------------------------------------- export

def metrics_url(endpoint: str) -> str:
    """OTLP base endpoint → .../v1/metrics. HTTPS only, no credentials or query in the URL."""
    parts = urllib.parse.urlsplit((endpoint or "").strip())
    if parts.scheme != "https" or not parts.hostname:
        raise TelemetryConfigError(f"{ENV_ENDPOINT} must be an https:// URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise TelemetryConfigError(f"{ENV_ENDPOINT} must not contain credentials, a query or a fragment")
    path = parts.path.rstrip("/")
    if not path.endswith("/v1/metrics"):
        path += "/v1/metrics"
    return urllib.parse.urlunsplit(("https", parts.netloc, path, "", ""))


def redact(text: str, secrets: list) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def send(url: str, payload: bytes, instance_id: str, token: str, timeout: float = 15.0) -> int:
    credentials = base64.b64encode(f"{instance_id}:{token}".encode()).decode()
    request = urllib.request.Request(url, data=payload, method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Basic {credentials}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # URL validated by metrics_url()
        return response.status


def read_config(env) -> tuple | None:
    values = {name: (env.get(name) or "").strip() for name in (ENV_ENDPOINT, ENV_INSTANCE, ENV_TOKEN)}
    present = [name for name, value in values.items() if value]
    if not present:
        return None
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise TelemetryConfigError(f"Grafana telemetry partially configured, missing variables: {', '.join(missing)}")
    if not values[ENV_INSTANCE].isdigit():
        raise TelemetryConfigError(f"{ENV_INSTANCE} must be the numeric Grafana Cloud instance ID")
    return metrics_url(values[ENV_ENDPOINT]), values[ENV_INSTANCE], values[ENV_TOKEN]


def main(argv=None, env=None) -> int:
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--summary", default="reports/security-summary.json")
    ap.add_argument("--history", default="monitoring/history/security-history.json")
    ap.add_argument("--payload-out", default="reports/security-telemetry.json",
                    help="copy of the OTLP payload (no secret) kept as a CI artifact")
    ap.add_argument("--dry-run", action="store_true", help="build and save the payload, send nothing")
    args = ap.parse_args(argv)
    secrets = [env.get(ENV_TOKEN, "")]

    try:
        summary = validate_summary(load_json(Path(args.summary), "security-summary.json"))
        history_path = Path(args.history)
        history = validate_history(load_json(history_path, "security-history.json")) if history_path.exists() else None
        payload = build_payload(summary, history)
        body = json.dumps(payload).encode("utf-8")
        Path(args.payload_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.payload_out).write_bytes(body)
        metric_names = [m["name"] for m in payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]]
        points = sum(len(m["gauge"]["dataPoints"]) for m in payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"])
        print(f"Security Gate: {summary['gate_status']} | blockers={summary['totals']['blockers']} "
              f"warnings={summary['totals']['warnings']} info={summary['totals']['info']}")
        print(f"OTLP payload: {len(metric_names)} metrics, {points} data points, {len(body)} bytes "
              f"(history: {'yes' if history else 'no'}) → {args.payload_out}")
        if args.dry_run:
            print("Dry run: nothing sent.")
            return 0
        config = read_config(env)
    except TelemetryConfigError as exc:
        print(f"TELEMETRY CONFIGURATION ERROR: {redact(str(exc), secrets)}")
        return CONFIG_ERROR

    if config is None:
        print("Grafana telemetry not configured — artifact preserved")
        return 0
    url, instance_id, token = config
    host = urllib.parse.urlsplit(url).hostname
    try:
        status = send(url, body, instance_id, token)
    except urllib.error.HTTPError as exc:
        detail = exc.read(300).decode("utf-8", "replace") if exc.fp else ""
        exc.close()
        print(f"TELEMETRY EXPORT FAILED: Grafana ({host}) answered HTTP {exc.code} {exc.reason}: "
              f"{redact(detail, secrets)}")
        if exc.code in (401, 403):
            print("  → check GRAFANA_OTLP_INSTANCE_ID / GRAFANA_OTLP_TOKEN (scope metrics:write)")
        return EXPORT_FAILURE
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        print(f"TELEMETRY EXPORT FAILED: Grafana ({host}) unreachable: {redact(str(reason), secrets)}")
        return EXPORT_FAILURE
    print(f"Security telemetry exported successfully (HTTP {status}, {host})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
