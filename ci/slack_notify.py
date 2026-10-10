#!/usr/bin/env python3
"""Sends the Security Gate decision and production promotions to Slack (Incoming Webhook).

    SCANNERS DETECT → SECURITY GATE DECIDES → GRAFANA VISUALISES → SLACK NOTIFIES

The message is built ONLY from reports/security-summary.json (written by ci/security_gate.py --all)
and non-secret GitLab CI metadata. Slack has no influence on the gate decision or on deploy:production.

    python3 ci/slack_notify.py --event gate         # PASS or BLOCKED, after the security_gate job
    python3 ci/slack_notify.py --event production   # after a successful manual deploy:production

Configuration: SLACK_WEBHOOK_URL (GitLab CI/CD variable, masked + protected). SECRET: never printed.

Exit codes:
    0  sent, or SLACK_WEBHOOK_URL not set (nothing to do), or --dry-run
    2  invalid input / configuration (summary missing or malformed, webhook not https://hooks.slack.com)
    3  Slack unreachable or refused the message (tolerated by the CI job: allow_failure)

Python standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG_ERROR = 2
DELIVERY_FAILURE = 3
ENV_WEBHOOK = "SLACK_WEBHOOK_URL"
SLACK_HOST = "hooks.slack.com"


class NotifyConfigError(ValueError):
    """Invalid input or configuration: fails the job visibly."""


# --------------------------------------------------------------------------- inputs

def load_summary(path: Path) -> dict:
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise NotifyConfigError(f"security summary not found: {path}")
    except json.JSONDecodeError as exc:
        raise NotifyConfigError(f"security summary is not valid JSON: {exc}")
    if not isinstance(summary, dict):
        raise NotifyConfigError("security summary must be a JSON object")
    missing = [k for k in ("gate_status", "release_allowed", "totals", "branch", "commit_short_sha", "pipeline_url")
               if k not in summary]
    if missing:
        raise NotifyConfigError(f"security summary: missing fields {missing}")
    if summary["gate_status"] not in ("PASS", "BLOCKED"):
        raise NotifyConfigError("security summary: gate_status must be PASS or BLOCKED")
    if summary["release_allowed"] is not (summary["gate_status"] == "PASS"):
        raise NotifyConfigError("security summary: release_allowed contradicts gate_status")
    for key in ("blockers", "warnings", "info"):
        value = summary["totals"].get(key) if isinstance(summary["totals"], dict) else None
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise NotifyConfigError(f"security summary: totals.{key} must be an integer >= 0")
    return summary


def webhook_url(env) -> str | None:
    """None when not configured; otherwise a validated https://hooks.slack.com/services/... URL."""
    url = (env.get(ENV_WEBHOOK) or "").strip()
    if not url:
        return None
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise NotifyConfigError(f"{ENV_WEBHOOK} must be an https:// URL")
    if parts.hostname != SLACK_HOST or parts.port not in (None, 443):
        raise NotifyConfigError(f"{ENV_WEBHOOK} must point to https://{SLACK_HOST}/ (Slack Incoming Webhook)")
    if parts.username or parts.password or parts.query or parts.fragment or not parts.path.startswith("/services/"):
        raise NotifyConfigError(f"{ENV_WEBHOOK} must be a Slack Incoming Webhook URL (https://{SLACK_HOST}/services/...)")
    return url


# --------------------------------------------------------------------------- messages

def esc(value) -> str:
    """Slack mrkdwn escaping: user-controlled values (branch names...) cannot inject links or mentions."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def link(url: str, label: str) -> str:
    if not url.startswith("https://"):
        return esc(label)
    return f"<{url.replace('|', '%7C').replace('>', '%3E')}|{esc(label)}>"


def _message(title: str, fields: list, body: str, pipeline: str) -> dict:
    return {
        "text": f"{title} — {body}",   # fallback: notifications, screen readers, clients without blocks
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title, "emoji": True}},
            {"type": "section", "fields": [{"type": "mrkdwn", "text": f"*{k}:*\n{v}"} for k, v in fields]},
            {"type": "section", "text": {"type": "mrkdwn", "text": body}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Pipeline: {pipeline}"}]},
        ],
    }


def _context(summary: dict) -> tuple:
    pipeline_id = summary.get("pipeline_id") or ""
    pipeline = link(summary["pipeline_url"], f"#{pipeline_id}" if pipeline_id else summary["pipeline_url"] or "n/a")
    return f"`{esc(summary['branch'])}`", f"`{esc(summary['commit_short_sha'])}`", pipeline


def gate_message(summary: dict) -> dict:
    branch, commit, pipeline = _context(summary)
    totals = summary["totals"]
    passed = summary["gate_status"] == "PASS"
    fields = [("Security Gate", "PASS" if passed else "BLOCKED"), ("Blocking findings", totals["blockers"]),
              ("Warnings", totals["warnings"]), ("Info", totals["info"]), ("Branch", branch), ("Commit", commit)]
    if passed:
        return _message("🟢 RELEASE AUTHORIZED", fields,
                        "Production promotion is now allowed but still requires manual approval "
                        "(job `deploy:production`).", pipeline)
    return _message("🔴 RELEASE BLOCKED", fields,
                    f"Production promotion is refused by security policy: {totals['blockers']} blocking finding(s). "
                    "See the reports and the Tests tab of the pipeline.", pipeline)


def production_message(summary: dict, env) -> dict:
    if summary["gate_status"] != "PASS":
        # deploy:production needs a successful security_gate: this would be an inconsistent pipeline.
        raise NotifyConfigError("production notification requested but the Security Gate summary is not PASS")
    branch, commit, pipeline = _context(summary)
    fields = [("Security Gate", "PASS"), ("Promotion", "completed"), ("Branch", branch), ("Commit", commit)]
    image, registry = env.get("IMAGE", "").strip(), env.get("CI_REGISTRY_IMAGE", "").strip()
    if image:
        fields.append(("Validated image", f"`{esc(image)}`"))
    if registry:
        fields.append(("Production tag", f"`{esc(registry)}:production`"))
    return _message("🚀 PRODUCTION PROMOTED", fields,
                    "Production release/promotion completed: the image validated by the Security Gate "
                    "was promoted to the `production` tag after manual approval.", pipeline)


# --------------------------------------------------------------------------- delivery

def redact(text: str, secrets: list) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def post(url: str, body: bytes, timeout: float = 15.0) -> tuple:
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json; charset=utf-8"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # URL validated by webhook_url()
        return response.status, response.read(200).decode("utf-8", "replace")


def main(argv=None, env=None) -> int:
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--event", choices=("gate", "production"), required=True)
    ap.add_argument("--summary", default="reports/security-summary.json")
    ap.add_argument("--dry-run", action="store_true", help="print the message, send nothing")
    args = ap.parse_args(argv)
    raw = (env.get(ENV_WEBHOOK) or "").strip()
    secrets = [raw, urllib.parse.urlsplit(raw).path if raw else ""]

    try:
        summary = load_summary(Path(args.summary))
        message = gate_message(summary) if args.event == "gate" else production_message(summary, env)
        print(f"Slack {args.event} notification: {message['blocks'][0]['text']['text']} "
              f"(gate {summary['gate_status']}, blockers={summary['totals']['blockers']})")
        if args.dry_run:
            print(json.dumps(message, indent=2, ensure_ascii=False))
            print("Dry run: nothing sent.")
            return 0
        url = webhook_url(env)
    except NotifyConfigError as exc:
        print(f"SLACK NOTIFICATION CONFIGURATION ERROR: {redact(str(exc), secrets)}")
        return CONFIG_ERROR

    if url is None:
        print(f"Slack notifications not configured ({ENV_WEBHOOK} not set) — nothing sent")
        return 0
    try:
        status, answer = post(url, json.dumps(message, ensure_ascii=False).encode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read(200).decode("utf-8", "replace") if exc.fp else ""
        exc.close()
        print(f"SLACK NOTIFICATION FAILED: Slack answered HTTP {exc.code}: {redact(detail, secrets)}")
        if exc.code in (403, 404, 410):
            print(f"  → the webhook was revoked or its channel archived: create a new one and update {ENV_WEBHOOK}")
        return DELIVERY_FAILURE
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        print(f"SLACK NOTIFICATION FAILED: Slack unreachable: {redact(str(reason), secrets)}")
        return DELIVERY_FAILURE
    print(f"Slack notification sent (HTTP {status}, {redact(answer, secrets)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
