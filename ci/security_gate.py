#!/usr/bin/env python3
"""Quality gate de sécurité « policy as code ».

Lit les rapports JSON des scanners, leur applique la politique (ci/security-policy.toml)
et le registre d'exemptions (ci/exemptions.toml), puis décide : BLOQUANT ou non.

    python3 ci/security_gate.py --control sca     # un seul contrôle (dans le job de scan)
    python3 ci/security_gate.py --all             # tous les contrôles (job security_gate)

En mode --all, produit aussi :
    reports/security-summary.json   synthèse machine (tableau de bord, historique)
    reports/security-summary.md     synthèse lisible
    reports/junit-security.xml      affiché par GitLab dans l'onglet « Tests » du pipeline

Bibliothèque standard uniquement (Python >= 3.11) : tourne dans toutes les images d'outils.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
POLICY_FILE = ROOT / "ci" / "security-policy.toml"
EXEMPTIONS_FILE = ROOT / "ci" / "exemptions.toml"
# Une exemption = l'acceptation temporaire et tracée d'UN finding précis (docs/devsecops/06-exemptions.md)
EXEMPTION_FIELDS = ("id", "control", "fingerprint", "reason", "owner", "approver", "ticket", "created", "expires")
EXEMPTION_ID = re.compile(r"^EXC-\d{3,}$")
WILDCARDS = re.compile(r"[*?\[\]]")
MIN_REASON_LENGTH = 20
CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass
class Finding:
    rule: str            # CVE, id de règle, id de check…
    location: str        # fichier:ligne, ou paquet@version
    severity: str
    title: str
    level: str = "info"  # block | warn | info (politique) ; exempted (bloquant couvert par une exemption active)
    exempted_by: str = ""
    extra: dict = field(default_factory=dict)
    fingerprint: str = ""  # identifiant stable et exact : "<règle>|<emplacement>"

    def __post_init__(self):
        self.fingerprint = self.fingerprint or f"{self.rule}|{self.location}"


# --------------------------------------------------------------------------- parsers
# Un parser par format de rapport : JSON brut → liste de Finding normalisés.

def parse_gitleaks(data):
    return [Finding(f["RuleID"], f"{f['File']}:{f['StartLine']}", "HIGH",
                    f.get("Description", "Secret détecté")) for f in data or []]


def parse_semgrep(data):
    out = []
    for r in data.get("results", []):
        cwe = r["extra"].get("metadata", {}).get("cwe") or []
        out.append(Finding(r["check_id"].split(".")[-1], f"{r['path']}:{r['start']['line']}",
                           r["extra"]["severity"], r["extra"]["message"].strip().split("\n")[0][:160],
                           extra={"cwe": cwe[0] if cwe else ""}))
    return out


def _clean_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./")


def parse_bandit(data):
    return [Finding(r["test_id"], f"{_clean_path(r['filename'])}:{r['line_number']}",
                    r["issue_severity"], r["issue_text"],
                    extra={"confidence": r["issue_confidence"],
                           "cwe": f"CWE-{r.get('issue_cwe', {}).get('id', '')}"})
            for r in data.get("results", [])]


def _max_cvss(vuln):
    scores = [s.get("V3Score") for s in (vuln.get("CVSS") or {}).values() if s.get("V3Score")]
    return max(scores) if scores else None


def parse_trivy_vuln(data):
    out = []
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            out.append(Finding(v["VulnerabilityID"], f"{v['PkgName']}@{v.get('InstalledVersion', '?')}",
                               v.get("Severity", "UNKNOWN"), v.get("Title", "")[:160],
                               extra={"cvss": _max_cvss(v), "fixed": v.get("FixedVersion", ""),
                                      "target": res.get("Target", "")}))
    return out


def parse_trivy_misconfig(data):
    return [Finding(m["ID"], res.get("Target", ""), m.get("Severity", "UNKNOWN"), m.get("Title", ""))
            for res in data.get("Results", [])
            for m in res.get("Misconfigurations") or [] if m.get("Status", "FAIL") == "FAIL"]


def parse_checkov(data):
    blocks = data if isinstance(data, list) else [data]
    return [Finding(c["check_id"], f"{c.get('file_path', '').lstrip('/')}", c.get("severity") or "UNKNOWN",
                    c.get("check_name", ""))
            for b in blocks for c in b.get("results", {}).get("failed_checks", [])]


def parse_zap(data):
    risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    return [Finding(f"zap-{a['pluginid']}", s.get("@name", ""), risk.get(str(a["riskcode"]), "INFO"),
                    a.get("name", a.get("alert", "")), extra={"risk": int(a["riskcode"])})
            for s in data.get("site", []) for a in s.get("alerts", [])]


PARSERS = {"gitleaks": parse_gitleaks, "semgrep": parse_semgrep, "bandit": parse_bandit,
           "trivy-vuln": parse_trivy_vuln, "trivy-misconfig": parse_trivy_misconfig,
           "checkov": parse_checkov, "zap": parse_zap}


# --------------------------------------------------------------------------- politique

def classify(f: Finding, c: dict) -> str:
    """Applique les seuils d'un contrôle à un finding → block | warn | info."""
    sev = f.severity.upper()
    if c.get("block_all"):
        return "block"
    if c["tool"] == "trivy-vuln":
        cvss = f.extra.get("cvss")
        serious = cvss >= c["block_cvss"] if cvss is not None else sev in c["block_severity"]
        if serious and (f.extra.get("fixed") or not c.get("require_fix")):
            return "block"
        return "warn" if serious or sev in c.get("warn_severity", []) else "info"
    if c["tool"] == "checkov":
        return "block" if f.rule in c["block_checks"] else ("warn" if c.get("warn_all_other") else "info")
    if c["tool"] == "zap":
        risk = f.extra["risk"]
        return "block" if risk >= c["block_risk"] else ("warn" if risk >= c["warn_risk"] else "info")
    if sev in c.get("block_severity", []):
        conf = f.extra.get("confidence")
        if conf is None or CONFIDENCE_RANK[conf] >= CONFIDENCE_RANK[c.get("min_confidence", "LOW")]:
            return "block"
        return "warn"
    return "warn" if sev in c.get("warn_severity", []) else "info"


def _exemption_errors(e: dict, controls: dict, policy: dict, today: dt.date) -> list[str]:
    """Problèmes de STRUCTURE d'une entrée (l'expiration n'en fait pas partie)."""
    problems = []
    unknown = sorted(set(e) - set(EXEMPTION_FIELDS))
    if unknown:  # ex. anciens champs match/path à jokers, ou faute de frappe : refusés
        problems.append(f"champs inconnus {unknown}")
    missing = [k for k in EXEMPTION_FIELDS if e.get(k) in (None, "")]
    if missing:
        problems.append(f"champs obligatoires manquants {missing}")
    text_fields = [k for k in EXEMPTION_FIELDS if k not in ("created", "expires")]
    if any(k in e and not isinstance(e[k], str) for k in text_fields):
        problems.append("id, control, fingerprint, reason, owner, approver et ticket doivent être des textes")
    if problems:
        return problems
    if not EXEMPTION_ID.match(e["id"]):
        problems.append("id au format EXC-NNN attendu")
    if e["control"] not in controls:
        problems.append(f"contrôle inconnu « {e['control']} » (voir security-policy.toml)")
    fp = e["fingerprint"]
    if fp != fp.strip() or WILDCARDS.search(fp) or fp.count("|") != 1 or "" in fp.split("|"):
        problems.append("fingerprint exact attendu « <règle>|<emplacement> », sans joker (* ? [ ])")
    if len(e["reason"].strip()) < MIN_REASON_LENGTH:
        problems.append(f"justification trop courte (minimum {MIN_REASON_LENGTH} caractères)")
    if e["owner"].strip().casefold() == e["approver"].strip().casefold():
        problems.append("owner et approver doivent être deux personnes différentes (principe des 4 yeux)")
    created, expires = e["created"], e["expires"]
    is_date = [isinstance(d, dt.date) and not isinstance(d, dt.datetime) for d in (created, expires)]
    if not all(is_date):  # une date-heure (sous-classe de date) ou un texte entre guillemets est refusé
        problems.append("created et expires doivent être des dates TOML (AAAA-MM-JJ, sans guillemets)")
    elif expires < created:
        problems.append("expires est antérieure à created")
    elif created > today:
        problems.append("created est dans le futur")
    elif (expires - created).days > policy["max_exemption_days"]:
        problems.append(f"durée > {policy['max_exemption_days']} jours (non autorisé)")
    return problems


def load_exemptions(policy: dict, controls: dict, today: dt.date, path: Path = EXEMPTIONS_FILE):
    """Valide le registre. Retourne (actives, expirées, erreurs).

    - entrée mal formée  → erreur : la gate BLOQUE et AUCUNE exemption du registre n'est appliquée
                           (fail-secure, jamais ignorée en silence) ;
    - entrée expirée     → n'est plus appliquée : son finding redevient bloquant s'il existe encore,
                           sans bloquer le reste (simple avertissement dans la synthèse) ;
    - entrée active      → peut couvrir le(s) finding(s) BLOQUANT(S) ayant exactement son fingerprint.
    """
    if not path.exists():
        return [], [], []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return [], [], [f"registre illisible ({path.name}) : {exc}"]
    unexpected = sorted(set(data) - {"exemption"})
    entries = data.get("exemption", [])
    if unexpected or not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        return [], [], [f"registre mal formé ({path.name}) : seules des tables [[exemption]] sont autorisées"]

    active, expired, errors, seen = [], [], [], set()
    for index, e in enumerate(entries, 1):
        eid = e.get("id") if isinstance(e.get("id"), str) and e.get("id") else f"<entrée n°{index} sans id>"
        problems = _exemption_errors(e, controls, policy, today)
        if eid in seen:
            problems.append("id déjà utilisé")
        seen.add(eid)
        if problems:
            errors.append(f"{eid} : " + " ; ".join(problems))
        elif e["expires"] < today:
            expired.append(e)
        else:
            active.append(e)
    if errors:  # registre non fiable : AUCUNE exemption appliquée, tous les bloquants restent visibles
        return [], [], errors
    return active, expired, errors


def apply_exemptions(control: str, findings: list[Finding], exemptions: list[dict]) -> list[str]:
    """Correspondance EXACTE (contrôle + fingerprint), uniquement sur les findings BLOQUANTS.

    Le finding reste dans les rapports, au niveau « exempted », avec l'id de l'exemption.
    Retourne les ids des exemptions effectivement utilisées.
    """
    by_fingerprint = {e["fingerprint"]: e for e in exemptions if e["control"] == control}
    used = []
    for f in findings:
        e = by_fingerprint.get(f.fingerprint)
        if e and f.level == "block":
            f.level, f.exempted_by = "exempted", e["id"]
            if e["id"] not in used:
                used.append(e["id"])
    return used


def evaluate(name: str, c: dict, policy: dict, exemptions: list[dict], reports_dir: Path) -> dict:
    report = reports_dir / Path(c["report"]).name
    if not report.exists():
        status = "missing"
        return {"control": name, "label": c["label"], "status": status, "findings": [], "exemptions_used": [],
                "counts": {"block": 1 if policy["fail_on_missing_report"] else 0, "warn": 0, "info": 0,
                           "exempted": 0},
                "message": f"rapport absent ({report}) : le contrôle n'a pas tourné"}
    findings = PARSERS[c["tool"]](json.loads(report.read_text(encoding="utf-8") or "null"))
    for f in findings:
        f.level = classify(f, c)
    used = apply_exemptions(name, findings, exemptions)
    counts = {lvl: sum(f.level == lvl for f in findings) for lvl in ("block", "warn", "info", "exempted")}
    return {"control": name, "label": c["label"], "status": "fail" if counts["block"] else "pass",
            "counts": counts, "findings": [asdict(f) for f in findings], "exemptions_used": used}


# --------------------------------------------------------------------------- sorties

def print_result(r: dict):
    icon = {"pass": "✅", "fail": "❌", "missing": "⛔"}[r["status"]]
    c = r["counts"]
    print(f"\n{icon} {r['label']:<32} bloquants={c['block']:<4} avertissements={c['warn']:<4} "
          f"info={c['info']:<4} exemptés={c['exempted']}")
    if r["status"] == "missing":
        print(f"   {r['message']}")
    for f in [f for f in r["findings"] if f["level"] == "block"][:25]:
        cvss = f["extra"].get("cvss")
        fix = f["extra"].get("fixed")
        details = (f" CVSS {cvss}" if cvss else "") + (f" → corrigé en {fix}" if fix else "")
        print(f"   ■ [{f['severity']}] {f['rule']}  {f['location']}{details}\n     {f['title']}"
              f"\n     fingerprint : {f['fingerprint']}")
    hidden = c["block"] - 25
    if hidden > 0:
        print(f"   … et {hidden} autres (voir le rapport JSON complet)")
    for f in [f for f in r["findings"] if f["level"] == "exempted"]:
        print(f"   ◌ EXEMPTÉ par {f['exempted_by']} — [{f['severity']}] {f['fingerprint']}\n     {f['title']}")


def exemption_audit(e: dict) -> dict:
    """Trace d'audit d'une exemption (aucune donnée sensible : identifiants, personnes, dates, ticket)."""
    return {"id": e["id"], "control": e["control"], "fingerprint": e["fingerprint"], "reason": e["reason"],
            "owner": e["owner"], "approver": e["approver"], "ticket": e["ticket"],
            "created": e["created"].isoformat(), "expires": e["expires"].isoformat()}


def run_gate(names: list[str] | None, reports_dir: Path, today: dt.date,
             exemptions_path: Path = EXEMPTIONS_FILE, conf: dict | None = None):
    """Évalue les contrôles. Retourne (résultats, état des exemptions, bloqué ?)."""
    conf = conf or tomllib.loads(POLICY_FILE.read_text(encoding="utf-8"))
    policy, controls = conf["policy"], conf["controls"]
    active, expired, errors = load_exemptions(policy, controls, today, exemptions_path)
    results = [evaluate(n, controls[n], policy, active, reports_dir) for n in (names or list(controls))]
    used = {i for r in results for i in r["exemptions_used"]}
    state = {"applied": [exemption_audit(e) for e in active if e["id"] in used],
             "unused": [e["id"] for e in active if e["id"] not in used],
             "expired": [exemption_audit(e) for e in expired],
             "errors": errors}
    # Seuls les findings bloquants restants et un registre MAL FORMÉ bloquent. Une exemption expirée
    # ne bloque pas par elle-même : elle n'est simplement plus appliquée.
    blocked = any(r["counts"]["block"] for r in results) or bool(errors)
    return results, state, blocked


# Stable, scanner-oriented names used by the summary and the observability layer
# (the policy file keeps its own control names; their semantics are unchanged).
SUMMARY_CONTROL_NAMES = {"secrets": "gitleaks", "sast_semgrep": "semgrep", "sast_bandit": "bandit",
                         "sca": "trivy_fs", "image": "trivy_image", "iac_trivy": "trivy_config",
                         "iac_checkov": "checkov", "dast": "zap"}
SUMMARY_SCHEMA_VERSION = "1.1"   # 1.1 : ajout additif du bloc « exemptions » (trace d'audit)


def build_summary(results: list[dict], errors: list[str], blocked: bool, env=None,
                  exemptions: dict | None = None) -> dict:
    """Machine-readable result of the gate, written on EVERY --all run (PASS or BLOCKED).

    Only counts, statuses, pipeline identifiers and the exemption audit trail: no finding
    details, no secret value. A missing report keeps its fail-secure count (1 blocker) and
    the status MISSING.
    """
    env = os.environ if env is None else env
    exemptions = exemptions or {"applied": [], "unused": [], "expired": []}
    status_names = {"pass": "PASS", "fail": "BLOCKED", "missing": "MISSING"}
    controls = {}
    for r in results:
        c = r["counts"]
        controls[SUMMARY_CONTROL_NAMES.get(r["control"], r["control"])] = {
            "label": r["label"], "policy_control": r["control"], "status": status_names[r["status"]],
            "blockers": c["block"], "warnings": c["warn"], "info": c["info"], "exempted": c["exempted"],
        }
    totals = {key: sum(ctrl[key] for ctrl in controls.values())
              for key in ("blockers", "warnings", "info", "exempted")}
    commit_sha = env.get("CI_COMMIT_SHA", "")
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "project": env.get("CI_PROJECT_PATH", "pygoat"),
        "commit_sha": commit_sha,
        "commit_short_sha": env.get("CI_COMMIT_SHORT_SHA", commit_sha[:8]),
        "branch": env.get("CI_COMMIT_REF_NAME", ""),
        "pipeline_id": env.get("CI_PIPELINE_ID", ""),
        "pipeline_url": env.get("CI_PIPELINE_URL", ""),
        "gate_status": "BLOCKED" if blocked else "PASS",
        "release_allowed": not blocked,
        "exemption_errors": errors,
        "exemptions": {"applied": exemptions["applied"], "expired": exemptions["expired"],
                       "unused": exemptions["unused"]},
        "controls": controls,
        "totals": totals,
    }


def write_outputs(results: list[dict], state: dict, reports_dir: Path, decision: str):
    errors = state["errors"]
    summary = build_summary(results, errors, blocked=(decision != "AUTORISÉ"), exemptions=state)
    (reports_dir / "security-summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False),
                                                       encoding="utf-8")
    lines = [f"# Synthèse sécurité — décision : **{decision}**", "",
             "| Contrôle | Statut | Bloquants | Avertissements | Exemptés |", "|---|---|---|---|---|"]
    for r in results:
        c = r["counts"]
        lines.append(f"| {r['label']} | {r['status']} | {c['block']} | {c['warn']} | {c['exempted']} |")
    lines += ["", *[f"- ⚠️ Exemption invalide : {e}" for e in errors]]
    lines += [f"- ◌ Exemption appliquée {e['id']} ({e['control']}, `{e['fingerprint']}`) — owner {e['owner']}, "
              f"approver {e['approver']}, ticket {e['ticket']}, expire le {e['expires']}" for e in state["applied"]]
    lines += [f"- ⏰ Exemption expirée {e['id']} (le {e['expires']}) : plus appliquée, le finding bloque à nouveau "
              f"s'il existe encore" for e in state["expired"]]
    lines += [f"- ℹ️ Exemption active sans finding correspondant {i} : à retirer du registre" for i in state["unused"]]
    (reports_dir / "security-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # JUnit : un « test suite » par contrôle, un « test » en échec par finding bloquant,
    # un « test » ignoré (skipped) par finding exempté — l'exemption reste visible dans GitLab.
    xml = ['<?xml version="1.0" encoding="UTF-8"?>', "<testsuites>"]
    for r in results:
        blocking = [f for f in r["findings"] if f["level"] == "block"]
        exempted = [f for f in r["findings"] if f["level"] == "exempted"]
        xml.append(f'<testsuite name="{escape(r["label"])}" tests="{max(1, len(blocking) + len(exempted))}" '
                   f'failures="{len(blocking) or int(r["status"] == "missing")}" skipped="{len(exempted)}">')
        for f in exempted:
            name = escape(f"{f['rule']} — {f['location']}", {'"': "&quot;"})
            xml.append(f'<testcase classname="{r["control"]}" name="{name}">'
                       f'<skipped message="{escape("exempté par " + f["exempted_by"], {chr(34): "&quot;"})}"/>'
                       "</testcase>")
        if r["status"] == "missing":
            xml.append(f'<testcase classname="{r["control"]}" name="rapport présent">'
                       f'<failure message="{escape(r["message"])}"/></testcase>')
        elif not blocking and not exempted:
            xml.append(f'<testcase classname="{r["control"]}" name="aucun finding bloquant"/>')
        for f in blocking:
            name = escape(f"{f['rule']} — {f['location']}", {'"': "&quot;"})
            xml.append(f'<testcase classname="{r["control"]}" name="{name}">'
                       f'<failure message="{escape(f["severity"], {chr(34): "&quot;"})}">'
                       f'{escape(f["title"])}</failure></testcase>')
        xml.append("</testsuite>")
    if errors:
        xml.append('<testsuite name="Registre d\'exemptions" tests="1" failures="1">'
                   '<testcase classname="exemptions" name="registre valide">'
                   f'<failure message="exemption invalide">{escape(chr(10).join(errors))}</failure>'
                   "</testcase></testsuite>")
    xml.append("</testsuites>")
    (reports_dir / "junit-security.xml").write_text("\n".join(xml), encoding="utf-8")


# --------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--control", help="nom d'un contrôle de security-policy.toml")
    group.add_argument("--all", action="store_true", help="évaluer tous les contrôles")
    ap.add_argument("--reports-dir", default="reports")
    args = ap.parse_args()

    conf = tomllib.loads(POLICY_FILE.read_text(encoding="utf-8"))
    controls = conf["controls"]
    if args.control and args.control not in controls:
        print(f"Contrôle inconnu : {args.control}. Disponibles : {', '.join(controls)}")
        return 2

    reports_dir = Path(args.reports_dir)
    results, state, blocked = run_gate(None if args.all else [args.control], reports_dir, dt.date.today(),
                                       conf=conf)

    print("=" * 100 + "\n POLITIQUE DE SÉCURITÉ — ci/security-policy.toml\n" + "=" * 100)
    for r in results:
        print_result(r)
    for e in state["errors"]:
        print(f"\n⛔ Registre d'exemptions : {e}")
    for e in state["expired"]:
        print(f"\n⏰ Exemption {e['id']} expirée le {e['expires']} (ticket {e['ticket']}) : plus appliquée — "
              f"le finding {e['fingerprint']} bloque à nouveau s'il existe encore. À supprimer ou re-justifier.")
    if args.all:
        for i in state["unused"]:
            print(f"\nℹ️ Exemption {i} active mais sans finding bloquant correspondant : à retirer du registre.")

    decision = "BLOQUÉ" if blocked else "AUTORISÉ"
    if args.all:
        reports_dir.mkdir(parents=True, exist_ok=True)
        write_outputs(results, state, reports_dir, decision)
    print("\n" + "=" * 100)
    print(f" DÉCISION : {'❌ ' if blocked else '✅ '}{decision}"
          + (" — corriger les findings bloquants ou demander une exemption (docs/devsecops/06-exemptions.md)"
             if blocked else ""))
    print("=" * 100)
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
