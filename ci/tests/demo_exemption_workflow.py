"""Teacher-facing demonstration of the exception workflow — SYNTHETIC data in a temporary folder.

    python -m ci.tests.demo_exemption_workflow

    1. synthetic blocker, no exemption            → Gate BLOCKED
    2. same blocker + valid temporary exemption   → finding EXEMPTED (still visible), Gate PASS
    3. same blocker + EXPIRED exemption           → blocker active again, Gate BLOCKED

Nothing is written to reports/, ci/exemptions.toml or monitoring/: everything lives in a temporary
directory deleted at the end. The real security policy is used unchanged.
"""
import datetime as dt
import json
import tempfile
from pathlib import Path

from ci import security_gate as gate
from ci.tests.test_exemptions import DEMO_FINGERPRINT, bandit_issue, exemption, to_toml


def scenario(title: str, reports: Path, registry: Path, entries, today: dt.date) -> bool:
    if entries is None:
        registry.unlink(missing_ok=True)
    else:
        registry.write_text(to_toml(entries), encoding="utf-8")
    results, state, blocked = gate.run_gate(["sast_bandit"], reports, today, registry)
    result = results[0]
    print(f"\n{'─' * 92}\n{title}\n{'─' * 92}")
    for f in result["findings"]:
        tag = {"block": "BLOCKING", "exempted": f"EXEMPTED by {f['exempted_by']}"}.get(f["level"], f["level"])
        print(f"  finding  {f['fingerprint']:<55} → {tag}")
    c = result["counts"]
    print(f"  counts   blockers={c['block']}  exempted={c['exempted']}  warnings={c['warn']}")
    for e in state["applied"]:
        print(f"  audit    {e['id']}: owner={e['owner']} approver={e['approver']} ticket={e['ticket']} "
              f"expires={e['expires']}")
    for e in state["expired"]:
        print(f"  expired  {e['id']} (expired {e['expires']}): no longer applied")
    print(f"  GATE     {'❌ BLOCKED' if blocked else '✅ PASS'}")
    return blocked


def main() -> int:
    today = dt.date.today()
    with tempfile.TemporaryDirectory() as tmp:
        reports, registry = Path(tmp) / "reports", Path(tmp) / "exemptions.toml"
        reports.mkdir()
        (reports / "bandit.json").write_text(json.dumps({"results": [bandit_issue()]}), encoding="utf-8")
        print(f"Synthetic finding: Bandit HIGH/HIGH, fingerprint {DEMO_FINGERPRINT} (policy: blocking)")
        valid = exemption(created=today - dt.timedelta(days=1), expires=today + dt.timedelta(days=13))
        expired = exemption(created=today - dt.timedelta(days=30), expires=today - dt.timedelta(days=1))
        outcomes = [
            scenario("1. No exemption", reports, registry, None, today),
            scenario("2. Valid temporary exemption EXC-001 (exact fingerprint, owner ≠ approver, 14 days)",
                     reports, registry, [valid], today),
            scenario("3. Same exemption, EXPIRED yesterday", reports, registry, [expired], today),
        ]
    expected = [True, False, True]
    print(f"\n{'═' * 92}\nExpected BLOCKED / PASS / BLOCKED → "
          f"{'OK' if outcomes == expected else 'UNEXPECTED: ' + str(outcomes)}")
    return 0 if outcomes == expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
