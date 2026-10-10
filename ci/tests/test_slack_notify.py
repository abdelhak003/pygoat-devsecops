"""Tests of the Slack notifications (ci/slack_notify.py). No network: urlopen is replaced by a fake."""
import contextlib
import io
import json
import secrets
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from ci import security_gate as gate
from ci import slack_notify as slack

CONTROLS = ["secrets", "sast_semgrep", "sast_bandit", "sca", "image", "iac_trivy", "iac_checkov", "dast"]
CI_ENV = {"CI_PROJECT_PATH": "group/pygoat", "CI_COMMIT_SHA": "b" * 40, "CI_COMMIT_SHORT_SHA": "bbbbbbbb",
          "CI_COMMIT_REF_NAME": "master", "CI_PIPELINE_ID": "4242",
          "CI_PIPELINE_URL": "https://gitlab.com/group/pygoat/-/pipelines/4242"}


def result(control, status="pass", block=0, warn=0, info=0):
    return {"control": control, "label": control, "status": status,
            "counts": {"block": block, "warn": warn, "info": info, "exempted": 0}, "findings": []}


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return b"ok"


class SlackNotifyTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.summary_path = Path(tmp.name) / "security-summary.json"
        # Built at run time: no webhook-shaped literal in the source (and a fresh value per test).
        self.webhook = f"https://{slack.SLACK_HOST}/services/T{secrets.token_hex(5)}/B{secrets.token_hex(5)}/" \
                       f"{secrets.token_hex(12)}"
        self.canary = secrets.token_hex(20)
        self.env = {slack.ENV_WEBHOOK: self.webhook, "DJANGO_SECRET_KEY": self.canary,
                    "GRAFANA_OTLP_TOKEN": self.canary, "CI_JOB_TOKEN": self.canary,
                    "IMAGE": "registry.gitlab.com/group/pygoat:bbbbbbbb",
                    "CI_REGISTRY_IMAGE": "registry.gitlab.com/group/pygoat"}
        self.sent = []

    def write_summary(self, passed=True):
        results = [result(c, warn=2, info=1) for c in CONTROLS]
        if not passed:
            results[0] = result("secrets", "fail", block=3, warn=2, info=1)
            results[-1] = result("dast", "missing", block=1)
        summary = gate.build_summary(results, [], blocked=not passed, env=CI_ENV)
        self.summary_path.write_text(json.dumps(summary), encoding="utf-8")
        return summary

    def fake_urlopen(self, request, timeout):
        self.sent.append({"url": request.full_url, "body": json.loads(request.data.decode("utf-8")),
                          "headers": dict(request.header_items())})
        return FakeResponse()

    def run_notify(self, event, env, urlopen=None):
        out = io.StringIO()
        with mock.patch("urllib.request.urlopen", urlopen or self.fake_urlopen), contextlib.redirect_stdout(out):
            code = slack.main(["--event", event, "--summary", str(self.summary_path)], env)
        return code, out.getvalue()

    def assert_no_secret(self, out):
        path = self.webhook.split(slack.SLACK_HOST, 1)[1]
        for secret in (self.webhook, path, self.canary):
            self.assertNotIn(secret, out)
        for message in self.sent:
            self.assertNotIn(self.canary, json.dumps(message["body"]))
            self.assertNotIn(path, json.dumps(message["body"]))

    @staticmethod
    def text_of(message):
        return json.dumps(message, ensure_ascii=False)

    # ------------------------------------------------------------------ messages

    def test_pass_message(self):
        self.write_summary(passed=True)
        code, out = self.run_notify("gate", self.env)
        self.assertEqual(code, 0)
        self.assertIn("Slack notification sent", out)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["url"], self.webhook)
        body = self.sent[0]["body"]
        self.assertEqual(body["blocks"][0]["text"]["text"], "🟢 RELEASE AUTHORIZED")
        self.assertIn("RELEASE AUTHORIZED", body["text"])
        text = self.text_of(body)
        for expected in ("*Security Gate:*\\nPASS", "*Blocking findings:*\\n0", "*Warnings:*\\n16",
                         "*Info:*\\n8", "`master`", "`bbbbbbbb`",
                         "<https://gitlab.com/group/pygoat/-/pipelines/4242|#4242>",
                         "still requires manual approval"):
            self.assertIn(expected, text)
        self.assert_no_secret(out)

    def test_blocked_message(self):
        self.write_summary(passed=False)
        code, out = self.run_notify("gate", self.env)
        self.assertEqual(code, 0)
        body = self.sent[0]["body"]
        self.assertEqual(body["blocks"][0]["text"]["text"], "🔴 RELEASE BLOCKED")
        text = self.text_of(body)
        for expected in ("*Security Gate:*\\nBLOCKED", "*Blocking findings:*\\n4",
                         "refused by security policy", "#4242"):
            self.assertIn(expected, text)
        self.assertNotIn("AUTHORIZED", text)
        self.assert_no_secret(out)

    def test_production_promoted_message(self):
        self.write_summary(passed=True)
        code, out = self.run_notify("production", self.env)
        self.assertEqual(code, 0)
        body = self.sent[0]["body"]
        self.assertEqual(body["blocks"][0]["text"]["text"], "🚀 PRODUCTION PROMOTED")
        text = self.text_of(body)
        for expected in ("*Security Gate:*\\nPASS", "release/promotion completed",
                         "`registry.gitlab.com/group/pygoat:bbbbbbbb`", "`registry.gitlab.com/group/pygoat:production`",
                         "`master`", "`bbbbbbbb`", "#4242"):
            self.assertIn(expected, text)
        self.assertNotIn("running", text.lower())
        self.assert_no_secret(out)

    def test_production_refused_when_gate_blocked(self):
        self.write_summary(passed=False)
        code, out = self.run_notify("production", self.env)
        self.assertEqual(code, slack.CONFIG_ERROR)
        self.assertEqual(self.sent, [])

    def test_user_controlled_values_are_escaped(self):
        summary = self.write_summary(passed=True)
        summary["branch"] = "feat/<!channel>&x"
        message = slack.gate_message(summary)
        text = self.text_of(message)
        self.assertNotIn("<!channel>", text)
        self.assertIn("&lt;!channel&gt;&amp;x", text)

    # ------------------------------------------------------------------ configuration

    def test_missing_webhook_sends_nothing(self):
        self.write_summary(passed=True)
        env = {k: v for k, v in self.env.items() if k != slack.ENV_WEBHOOK}
        code, out = self.run_notify("gate", env)
        self.assertEqual(code, 0)
        self.assertIn("not configured", out)
        self.assertEqual(self.sent, [])

    def test_invalid_webhooks_are_refused(self):
        self.write_summary(passed=True)
        token = secrets.token_hex(12)
        for bad in (f"http://{slack.SLACK_HOST}/services/T1/B2/{token}",       # not HTTPS
                    f"https://evil.example.com/services/T1/B2/{token}",         # not Slack
                    f"https://{slack.SLACK_HOST}.evil.example/services/{token}",  # look-alike host
                    f"https://{slack.SLACK_HOST}/api/{token}",                   # not a webhook path
                    f"https://user:{token}@{slack.SLACK_HOST}/services/{token}"):
            code, out = self.run_notify("gate", {**self.env, slack.ENV_WEBHOOK: bad})
            self.assertEqual(code, slack.CONFIG_ERROR, bad)
            self.assertIn("CONFIGURATION ERROR", out)
            self.assertNotIn(token, out)
        self.assertEqual(self.sent, [])

    def test_malformed_summaries_are_errors(self):
        cases = ["not json", json.dumps([1, 2]), json.dumps({"gate_status": "PASS"}),
                 json.dumps({"gate_status": "MAYBE", "release_allowed": True, "totals": {}, "branch": "",
                             "commit_short_sha": "", "pipeline_url": ""})]
        valid = self.write_summary(passed=True)
        cases.append(json.dumps({**valid, "release_allowed": False}))                      # contradiction
        cases.append(json.dumps({**valid, "totals": {**valid["totals"], "blockers": -1}}))  # impossible count
        for content in cases:
            self.summary_path.write_text(content, encoding="utf-8")
            code, out = self.run_notify("gate", self.env)
            self.assertEqual(code, slack.CONFIG_ERROR, content[:60])
        self.summary_path.unlink()
        code, out = self.run_notify("gate", self.env)
        self.assertEqual(code, slack.CONFIG_ERROR)
        self.assertIn("not found", out)
        self.assertEqual(self.sent, [])

    # ------------------------------------------------------------------ delivery failures

    def test_slack_http_error_is_a_tolerated_failure_and_redacted(self):
        self.write_summary(passed=True)

        def refused(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {},
                                         io.BytesIO(f"no_service {request.full_url}".encode()))

        code, out = self.run_notify("gate", self.env, refused)
        self.assertEqual(code, slack.DELIVERY_FAILURE)
        self.assertIn("HTTP 404", out)
        self.assert_no_secret(out)

    def test_slack_unreachable_is_a_tolerated_failure(self):
        self.write_summary(passed=False)

        def unreachable(request, timeout):
            raise urllib.error.URLError("Temporary failure in name resolution")

        code, out = self.run_notify("gate", self.env, unreachable)
        self.assertEqual(code, slack.DELIVERY_FAILURE)
        self.assertIn("unreachable", out)
        self.assert_no_secret(out)

    def test_failure_never_changes_the_reported_decision(self):
        """A delivery failure is reported as such; the BLOCKED decision is never rewritten as PASS (or vice versa)."""
        self.write_summary(passed=False)
        code, out = self.run_notify("gate", self.env,
                                    lambda r, timeout: (_ for _ in ()).throw(urllib.error.URLError("down")))
        self.assertEqual(code, slack.DELIVERY_FAILURE)
        self.assertIn("RELEASE BLOCKED", out)
        self.assertNotIn("AUTHORIZED", out)


if __name__ == "__main__":
    unittest.main()
