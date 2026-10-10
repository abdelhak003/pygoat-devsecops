#!/usr/bin/env python3
"""Vérifications d'EXÉCUTION des scanners — distinguer une panne d'outil d'un résultat de sécurité.

Convention de codes de retour utilisée dans tout le pipeline :
    0  → l'étape s'est exécutée correctement
    1  → SECURITY FINDINGS : réservé à la politique (ci/security_gate.py)
    3  → SCAN EXECUTION FAILURE : l'outil n'a pas pu faire son travail
         (application injoignable, crash, rapport absent / invalide / incomplet)

Un scan qui n'a pas tourné n'est JAMAIS considéré comme « propre » (fail secure).

    python3 ci/scan_checks.py wait-http http://cible:8000 --timeout 180
    python3 ci/scan_checks.py semgrep reports/semgrep.json
    python3 ci/scan_checks.py zap reports/zap.json

Bibliothèque standard uniquement (Python >= 3.8) : tourne dans les images des outils.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

EXECUTION_FAILURE = 3


def fail(message: str) -> int:
    print(f"❌ SCAN EXECUTION FAILURE : {message}")
    print("   → panne de l'outil ou de la configuration CI, PAS un résultat de sécurité.")
    return EXECUTION_FAILURE


def load_json_report(path: str):
    """Retourne (données, None) ou (None, message d'erreur)."""
    report = Path(path)
    if not report.is_file():
        return None, f"rapport absent : {path}"
    if report.stat().st_size == 0:
        return None, f"rapport vide : {path}"
    try:
        return json.loads(report.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as exc:
        return None, f"rapport JSON invalide : {path} ({exc})"


# --------------------------------------------------------------------------- wait-http

def wait_http(url: str, timeout: int, interval: int) -> int:
    """Prouve que l'application répond en HTTP 2xx/3xx avant de l'attaquer (DAST).

    Une réponse 4xx/5xx ne compte PAS : scanner une page d'erreur (ex. Django
    DisallowedHost → 400) donnerait un faux « aucun problème ».
    """
    deadline = time.monotonic() + timeout
    attempt, last = 0, "aucune tentative"
    while True:
        attempt += 1
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:  # suit les redirections
                print(f"✅ Application joignable : {url} → HTTP {resp.status} "
                      f"(URL finale {resp.geturl()}, tentative {attempt})")
                return 0
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError) as exc:
            last = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
        remaining = deadline - time.monotonic()
        print(f"… tentative {attempt} : pas prête ({last}), nouvel essai dans {interval}s")
        if remaining <= 0:
            return fail(f"application injoignable sur {url} après {timeout}s "
                        f"({attempt} tentatives, dernière erreur : {last})")
        time.sleep(min(interval, max(remaining, 0)))


# --------------------------------------------------------------------------- semgrep

def check_semgrep(path: str) -> int:
    data, error = load_json_report(path)
    if error:
        return fail(error)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list) \
            or not isinstance(data.get("errors"), list):
        return fail("structure inattendue : clés « results » et « errors » attendues")

    scanned = data.get("paths", {}).get("scanned", [])
    fatal = [e for e in data["errors"] if e.get("level") == "error"]
    warnings = [e for e in data["errors"] if e.get("level") != "error"]

    for e in fatal[:10]:
        print(f"   [error] {e.get('type')} : {str(e.get('message', ''))[:200]}")
    if fatal:
        return fail(f"Semgrep a signalé {len(fatal)} erreur(s) de niveau « error » "
                    "(règles / configuration) : scan non fiable")
    if not scanned:
        return fail("Semgrep n'a analysé AUCUN fichier (paths.scanned vide)")

    print(f"✅ Rapport Semgrep valide : {len(scanned)} fichiers analysés, "
          f"{len(data['results'])} findings, {len(warnings)} avertissement(s) d'analyse")
    if warnings:
        print("   ⚠️ Certains fichiers n'ont pas pu être entièrement analysés (avertissements) :")
        for e in warnings[:5]:
            print(f"      - {e.get('type')} : {str(e.get('message', ''))[:160]}")
    return 0


# --------------------------------------------------------------------------- zap

def check_zap(path: str) -> int:
    data, error = load_json_report(path)
    if error:
        return fail(error)
    sites = data.get("site") if isinstance(data, dict) else None
    if not isinstance(sites, list) or not sites:
        return fail("aucun site dans le rapport ZAP : la cible n'a pas été analysée")
    if any(not isinstance(s.get("alerts"), list) for s in sites):
        return fail("structure inattendue : chaque site doit contenir une liste « alerts »")

    names = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}
    by_risk = Counter(names.get(str(a.get("riskcode")), "?") for s in sites for a in s["alerts"])
    print(f"✅ Rapport ZAP valide : site(s) analysé(s) = {', '.join(s.get('@name', '?') for s in sites)}")
    print("   Alertes par niveau de risque : "
          + ", ".join(f"{k}={by_risk.get(k, 0)}" for k in ("High", "Medium", "Low", "Informational")))
    print("   (la décision bloquante est prise ensuite par ci/security_gate.py --control dast)")
    return 0


# --------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    w = sub.add_parser("wait-http", help="attendre que l'application réponde en HTTP 2xx/3xx")
    w.add_argument("url")
    w.add_argument("--timeout", type=int, default=180)
    w.add_argument("--interval", type=int, default=5)
    sub.add_parser("semgrep", help="valider reports/semgrep.json").add_argument("report")
    sub.add_parser("zap", help="valider reports/zap.json").add_argument("report")
    args = ap.parse_args()

    if args.command == "wait-http":
        return wait_http(args.url, args.timeout, args.interval)
    if args.command == "semgrep":
        return check_semgrep(args.report)
    return check_zap(args.report)


if __name__ == "__main__":
    sys.exit(main())
