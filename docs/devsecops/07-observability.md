# 07 — Observabilité sécurité : PyGoat Sentinel (Grafana Cloud)

> **SCANNERS DETECT → SECURITY GATE DECIDES → GRAFANA VISUALISES**
>
> Les scanners détectent, la Security Gate décide, Grafana affiche. Grafana ne décide **jamais** si une
> version peut partir en production.

Exigences couvertes : R6.1 (rapports conservés), R6.2 (tableau de bord), R6.4 (historique), R5.4 (secrets
du pipeline).

---

## 1. Pourquoi Grafana ne décide pas

| Rôle | Composant | Ce qu'il fait |
|---|---|---|
| Détecter | Gitleaks, Semgrep, Bandit, Trivy (fs / image / config), Checkov, OWASP ZAP | produisent des rapports JSON complets |
| Décider | `ci/security_gate.py` + `ci/security-policy.toml` + `ci/exemptions.toml` | applique la politique versionnée, écrit la décision, code de sortie 1 si BLOQUÉ |
| Visualiser | `ci/security_telemetry.py` → Grafana Cloud → tableau de bord *PyGoat Sentinel* | affiche la décision déjà prise |

Raisons de cette séparation :

1. **Une seule source de vérité.** La décision est prise par du code et une politique versionnés dans git,
   relus en merge request. Un seuil ou une alerte Grafana modifiable en un clic dans une interface web ne
   serait ni versionné ni relu.
2. **Indépendance vis-à-vis d'un service externe.** Si Grafana Cloud est indisponible, mal configuré ou
   supprimé, la gate décide exactement de la même façon. `deploy:production` dépend uniquement du job
   `security_gate` (`needs: [security_gate]`), jamais du job d'observabilité.
3. **Fail-secure préservé.** Un rapport absent reste compté comme 1 bloquant (statut `MISSING`) par la gate.
   Le tableau de bord ne fait qu'afficher ce statut.

## 2. Architecture des métriques

```
 scanners ──► reports/*.json ──► security_gate.py --all ──► reports/security-summary.json  (artefact, toujours)
                                       │ décision (exit 0/1)            │
                                       ▼                                ▼
                               deploy:production            security_observability:grafana
                               (needs: security_gate)        ci/security_telemetry.py
                                                                        │ OTLP/HTTP JSON (HTTPS, Basic auth)
                                                                        ▼
                     monitoring/history/security-history.json ──► Grafana Cloud (Mimir / Prometheus)
                                                                        │ PromQL
                                                                        ▼
                                                     PyGoat Sentinel — DevSecOps Security Control Center
```

### 2.1 `reports/security-summary.json` (écrit par la gate)

Écrit à **chaque** exécution `security_gate.py --all`, que la décision soit PASS ou BLOCKED. Il ne contient
que des compteurs, des statuts et des identifiants de pipeline : aucun détail de finding, aucune valeur
secrète.

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-10-09T02:10:00Z",
  "project": "abdelhak_hafedh_devsecops/pygoat_devsecops",
  "commit_sha": "<40 caractères>", "commit_short_sha": "<8 caractères>",
  "branch": "master", "pipeline_id": "<CI_PIPELINE_ID>", "pipeline_url": "<CI_PIPELINE_URL>",
  "gate_status": "PASS | BLOCKED", "release_allowed": true,
  "exemption_errors": [],
  "controls": {
    "gitleaks": {"label": "...", "policy_control": "secrets", "status": "PASS | BLOCKED | MISSING",
                 "blockers": 0, "warnings": 0, "info": 0, "exempted": 0},
    "semgrep": {}, "bandit": {}, "trivy_fs": {}, "trivy_image": {}, "trivy_config": {}, "checkov": {}, "zap": {}
  },
  "totals": {"blockers": 0, "warnings": 0, "info": 0, "exempted": 0}
}
```

Correspondance avec les noms de contrôles de la politique (inchangés) : `secrets`→`gitleaks`,
`sast_semgrep`→`semgrep`, `sast_bandit`→`bandit`, `sca`→`trivy_fs`, `image`→`trivy_image`,
`iac_trivy`→`trivy_config`, `iac_checkov`→`checkov`, `dast`→`zap`.

### 2.2 Métriques envoyées (jauges OTLP, 16 métriques, < 100 points par pipeline)

**Live — résultat du pipeline courant** (labels : `project`, `branch`, et `control` si indiqué)

| Métrique | Valeur |
|---|---|
| `pygoat_security_gate_status` | 1 = PASS, 0 = BLOCKED |
| `pygoat_security_release_allowed` | 1 = autorisé, 0 = bloqué |
| `pygoat_security_blockers_total` / `_warnings_total` / `_info_total` / `_exempted_total` | totaux |
| `pygoat_security_blockers{control}` / `pygoat_security_warnings{control}` / `pygoat_security_info{control}` | par contrôle |
| `pygoat_security_control_status{control}` | 1 = PASS, 0 = BLOCKED ou rapport MISSING |
| `pygoat_security_report_present{control}` | 1 = rapport du scanner présent, 0 = rapport MISSING |
| `pygoat_security_pipeline_info{commit_short_sha, pipeline_id, gate_status}` | toujours 1 : contexte du pipeline |

**Historique — snapshots validés** (`monitoring/history/security-history.json`, label `project`)

| Métrique | Valeur |
|---|---|
| `pygoat_security_remediation_blockers{phase, commit}` | bloquants à chaque phase : 1104 → 29 → 25 → 12 → 0 |
| `pygoat_security_remediation_control_blockers{phase, control}` | bloquants par contrôle et par phase |
| `pygoat_security_remediation_blocker_count_reduction_ratio{from_phase, to_phase}` | (premier − dernier) / premier |
| `pygoat_security_remediation_blockers_removed{from_phase, to_phase}` | nombre de bloquants supprimés |

**Distinguer un blocage d'une preuve manquante (fail-secure)** : deux métriques simples plutôt qu'une
métrique surchargée.

| Situation | `control_status` | `report_present` | Affichage (matrice) |
|---|---|---|---|
| Contrôle réussi | 1 | 1 | PASS · REPORT OK |
| Bloqué par des findings | 0 | 1 | BLOCKED · REPORT OK |
| Preuve de sécurité manquante (le scan n'a pas produit de rapport) | 0 | 0 | BLOCKED · **MISSING** (rouge foncé) |

Dans les deux derniers cas, la gate compte le contrôle comme bloquant : un rapport absent n'est jamais
interprété comme « aucune vulnérabilité ».

Attributs de ressource OTLP : `service.name=pygoat-security-gate`, `service.namespace=devsecops`,
`service.instance.id=gitlab-ci` (constant), `vcs.commit.sha`, `cicd.pipeline.id`. Grafana Cloud les range
dans la série `target_info` : le SHA complet et l'ID de pipeline ne sont donc pas recopiés sur chaque série.

**Cardinalité maîtrisée** : aucun identifiant de vulnérabilité, de règle ou de fichier n'est envoyé.
Seule `pygoat_security_pipeline_info` crée une série par pipeline (une seule, valeur 1), pour le panneau
de contexte.

## 3. Données live et données historiques

| | Live | Historique |
|---|---|---|
| Source | `reports/security-summary.json` du pipeline | `monitoring/history/security-history.json` (versionné) |
| Producteur | `security_gate.py --all` à chaque pipeline | snapshots validés manuellement pendant le projet |
| Préfixe | `pygoat_security_*` | `pygoat_security_remediation_*` |

Le fichier historique documente sa **provenance** : comptages de bloquants décidés par la gate avec la
politique inchangée, horodatages = date de commit git (UTC), `pipeline_id: null` car les identifiants des
anciens pipelines ne sont pas prouvables (ils ne sont pas inventés). Les 5 commits ont été vérifiés dans
l'historique git :

| Phase | Commit | Date (UTC) | Gate | Bloquants |
|---|---|---|---|---|
| 1-initial-baseline | `7ccd7b4` | 2026-10-08 19:24 | BLOCKED | 1104 |
| 2-phase-a | `31a9ed6` | 2026-10-08 22:31 | BLOCKED | 29 |
| 3-phase-a1 | `a7edd17` | 2026-10-08 23:00 | BLOCKED | 25 |
| 4-phase-b1 | `bdaedc0` | 2026-10-09 00:50 | BLOCKED | 12 |
| 5-final-secure-baseline | `5a3b908` | 2026-10-09 02:57 | PASS | 0 |

Les points historiques sont envoyés avec l'horodatage **courant** (Grafana Cloud refuse les échantillons
trop anciens) ; la chronologie réelle est portée par le label `phase` et par le fichier JSON.

**Réduction du nombre de bloquants : (1104 − 0) / 1104 = 100 %.** Cela signifie que tous les findings
dépassant les seuils de la politique ont été traités. Ce n'est **pas** un pourcentage de sécurité de
l'application : les avertissements restent visibles (panneau 5) et certaines vulnérabilités pédagogiques
sont volontaires (PyGoat est une application d'entraînement).

## 4. Le tableau de bord (`monitoring/grafana/pygoat-sentinel-dashboard.json`)

Titre : **PyGoat Sentinel — DevSecOps Security Control Center**. Variables : `datasource` (choix de la
source Prometheus, aucun UID codé en dur), `project`, `branch`. Un bandeau rappelle que le tableau de bord
ne décide pas.

| # | Panneau | Requête (simplifiée) |
|---|---|---|
| 1 | Security Gate — PASS / BLOCKED | `last_over_time(pygoat_security_gate_status[$__range])` |
| 2 | Blocking findings | `pygoat_security_blockers_total` |
| 3 | Release — AUTHORIZED / BLOCKED | `pygoat_security_release_allowed` |
| 4 | Blockers by control | `max by (control) (pygoat_security_blockers)` |
| 5 | Warnings by control | `max by (control) (pygoat_security_warnings)` |
| 6 | Remediation journey 1104 → 29 → 25 → 12 → 0 (historique) | `pygoat_security_remediation_blockers` |
| 7 | Blocker-count reduction — *not a security score* | `pygoat_security_remediation_blocker_count_reduction_ratio` |
| 8 | Security Gate history (1 = PASS, 0 = BLOCKED) | `max(pygoat_security_gate_status{project="$project", branch="$branch"})` — requête *range*, panneau Time series en escalier, axe 0–1 |
| 9 | Control status matrix | Control · Status (PASS/BLOCKED) · Evidence (REPORT OK/MISSING) · Blockers · Warnings · Info |
| 10 | Pipeline & commit context | `max by (project, commit_short_sha, pipeline_id, gate_status) (last_over_time(pygoat_security_pipeline_info{project="$project", branch="$branch"}[$__range]))` — colonnes Gate · Commit · Pipeline · Project, triées par ID de pipeline décroissant, ID cliquable vers GitLab |

Les métriques n'arrivent qu'une fois par pipeline : les panneaux « valeur actuelle » utilisent
`last_over_time(...[$__range])` pour afficher la dernière valeur connue sur la période choisie (sinon
Prometheus considère la série périmée après 5 minutes). Le panneau 8, lui, est une vraie série temporelle :
un point par pipeline exporté, reliés en escalier, pour montrer une séquence PASS → BLOCKED → PASS lors
d'une démonstration. Avec un seul pipeline exporté, il n'affiche qu'un point : c'est normal.

Corrections après import réel dans Grafana Cloud (phase C1.1) : le panneau 8 (*state timeline*) affichait
« Data does not have a time field » → remplacé par un panneau *Time series* sur une requête *range*. Le
panneau 10 (sous-requête `timestamp()`) affichait « No data » → requête simplifiée `last_over_time` sur
`pygoat_security_pipeline_info`, sans colonne « Exported at ».

Grandes valeurs et couleurs franches : lisible au vidéoprojecteur.

### 4.1 Section « BEFORE vs AFTER — SECURITY POSTURE »

Placée sous le parcours de remédiation (panneaux 6-7), elle résume la transformation en quelques secondes.
Elle n'utilise **que les snapshots historiques validés** : `1-initial-baseline` (`7ccd7b4`, AVANT) et
`5-final-secure-baseline` (`5a3b908`, APRÈS), via les métriques déjà envoyées
`pygoat_security_remediation_blockers` et `pygoat_security_remediation_control_blockers` (plus
`_blockers_removed` et `_blocker_count_reduction_ratio`). Aucune nouvelle métrique, aucun changement de
télémétrie, aucun nombre d'avertissements ou d'info historique (non validés, donc non affichés).

| Colonne | Panneaux | Couleur |
|---|---|---|
| AVANT | 1104 BLOCKING FINDINGS · Gate BLOCKED · Release BLOCKED ; graphique des bloquants initiaux par contrôle (trié) | rouge |
| TRANSFORMATION | 1104 → 0 ; « 1104 blocking findings removed » ; « 100 % reduction in blocker count — NOT a security score » | bleu / neutre |
| APRÈS | 0 BLOCKING FINDINGS · Gate PASS · Release AUTHORIZED ; les 8 contrôles à 0 | vert |

Requêtes (avec `$project`) :

```promql
# total d'une phase (AVANT : 1104, APRÈS : 0)
max(last_over_time(pygoat_security_remediation_blockers{project="$project", phase="1-initial-baseline"}[$__range]))
# gate / release dérivés du nombre de bloquants validé : 1 = PASS / AUTHORIZED, 0 = BLOCKED
max(last_over_time(pygoat_security_remediation_blockers{project="$project", phase="1-initial-baseline"}[$__range])) == bool 0
# bloquants par contrôle
max by (control) (last_over_time(pygoat_security_remediation_control_blockers{project="$project", phase="1-initial-baseline"}[$__range]))
```

Le statut de la gate et de la release n'est pas une métrique historique séparée : il est déduit du nombre
de bloquants validé (0 bloquant ⇔ PASS ⇔ release autorisée), exactement comme le fichier historique
l'enregistre (`gate_status`), ce que les tests vérifient.

**Tableau « Security improvement summary »** : une ligne par snapshot (AVANT / APRÈS), une colonne par
indicateur. Grafana applique les formats et les correspondances de valeurs (PASS / BLOCKED / AUTHORIZED,
« / 8 ») **par colonne** : cette orientation garde chaque cellule calculée à partir des données, sans texte
codé en dur.

| Indicateur | AVANT | APRÈS | Calcul |
|---|---|---|---|
| Blocking findings | 1104 | 0 | total de la phase |
| Controls with blockers | 7 / 8 | 0 / 8 | contrôles dont le nombre de bloquants > 0 |
| Security Gate | BLOCKED | PASS | bloquants == 0 |
| Release | BLOCKED | AUTHORIZED | bloquants == 0 |
| Secret blockers | 13 | 0 | Gitleaks |
| SAST blockers | 12 | 0 | Semgrep 8 + Bandit 4 |
| Dependency/Image blockers | 1077 | 0 | Trivy FS 83 + Trivy Image 994 |
| IaC blockers | 2 | 0 | Trivy Config 1 + Checkov 1 |

13 + 12 + 1077 + 2 + ZAP 0 = 1104 : chaque bloquant initial est compté. La colonne IaC a été ajoutée pour
que le total se vérifie. Vocabulaire : « blocking findings » et non « vulnérabilités corrigées », car un
bloquant peut être un secret exposé ou une mauvaise configuration (Dockerfile), pas seulement une CVE.

## 5. Gestion des secrets

- `GRAFANA_OTLP_TOKEN` est une variable CI/CD **masquée** (*Masked and hidden* si disponible) et
  **protégée**. Elle n'apparaît dans aucun fichier du dépôt.
- Le script construit l'en-tête `Authorization: Basic base64(instanceID:token)` **en mémoire** ; il n'affiche
  jamais le jeton, l'en-tête, ni aucune autre variable CI. Les messages d'erreur sont filtrés (le jeton est
  remplacé par `[REDACTED]` s'il apparaissait dans une réponse).
- Le payload sauvegardé en artefact (`reports/security-telemetry.json`) ne contient que des métriques.
- Endpoint **HTTPS obligatoire**, sans identifiants ni paramètres dans l'URL (sinon erreur de configuration).
- Jeton à privilèges minimaux : portée `metrics:write` uniquement suffit.
- Les tests (`ci/tests/test_security_observability.py`) vérifient avec un jeton aléatoire qu'il n'apparaît
  ni dans la sortie, ni dans le payload, ni dans la synthèse.

## 6. Comportement du job CI `security_observability:grafana`

```yaml
security_observability:grafana:
  stage: security_observability      # après security_gate, avant deploy
  when: always                       # exporte aussi les pipelines BLOQUÉS
  needs: [{job: security_gate, artifacts: true}]
  allow_failure: {exit_codes: [3]}
```

| Situation | Sortie du script | Code | Job | Effet sur la gate / le déploiement |
|---|---|---|---|---|
| Export réussi | `Security telemetry exported successfully` | 0 | vert | aucun |
| Aucune variable `GRAFANA_OTLP_*` | `Grafana telemetry not configured — artifact preserved` | 0 | vert | aucun |
| Grafana injoignable, HTTP 4xx/5xx | `TELEMETRY EXPORT FAILED: ...` | 3 | orange (échec toléré) | aucun |
| Variables incomplètes, URL non HTTPS, synthèse absente ou invalide | `TELEMETRY CONFIGURATION ERROR: ...` | 2 | rouge | aucun : `deploy:production` ne dépend que de `security_gate` |

Pourquoi `allow_failure` seulement pour le code 3 : une panne de Grafana Cloud est extérieure au projet et
ne doit pas rendre le pipeline rouge. Une **erreur de configuration** est en revanche une erreur du projet :
elle doit rester visible (job rouge) pour être corrigée, au lieu d'être silencieusement ignorée.

## 7. Configuration de Grafana Cloud (aucun jeton réel dans ce document)

1. Créer un compte gratuit sur grafana.com ; une *stack* est créée (ex. `<stack>.grafana.net`).
2. Dans Grafana : **Connections → Add new connection → OpenTelemetry (OTLP)** (ou, depuis le portail
   grafana.com : *My Account → stack → OpenTelemetry → Configure*).
3. Relever :
   - **OTLP endpoint** : `https://otlp-gateway-prod-<région>.grafana.net/otlp`
   - **Instance ID** : identifiant numérique de la stack.
4. **Generate / Create token** : nom `pygoat-gitlab-ci`, portée `metrics:write`, expiration définie. Copier
   le jeton **une seule fois**, directement dans GitLab (étape suivante), sans l'enregistrer ailleurs.
5. GitLab : **Settings → CI/CD → Variables → Add variable** :

| Clé | Valeur | Visibilité | Protégée | Remarque |
|---|---|---|---|---|
| `GRAFANA_OTLP_ENDPOINT` | `https://otlp-gateway-prod-<région>.grafana.net/otlp` | Visible | Oui | pas de secret |
| `GRAFANA_OTLP_INSTANCE_ID` | identifiant numérique | Visible (ou masquée) | Oui | |
| `GRAFANA_OTLP_TOKEN` | jeton | **Masked and hidden** (ou *Masked*) | Oui | secret |

   Les **trois** variables doivent avoir la **même** option *Protect variable* : sinon, sur une branche non
   protégée, seules certaines seraient présentes et le job signalerait une configuration incomplète (code 2).
   Avec les trois protégées, les branches non protégées affichent simplement « not configured ».

## 8. Import du tableau de bord

1. Grafana : **Dashboards → New → Import**.
2. **Upload dashboard JSON file** → `monitoring/grafana/pygoat-sentinel-dashboard.json` → **Import**.
3. En haut du tableau de bord : choisir la source **Prometheus data source** (Grafana Cloud :
   `grafanacloud-<stack>-prom`), puis `Project` et `Branch` (`master`).
4. **Save dashboard** pour mémoriser ces choix.

## 9. Vérification

1. Local, sans identifiants :
   ```bash
   python3 ci/security_gate.py --all                 # écrit reports/security-summary.json
   python3 ci/security_telemetry.py --dry-run        # construit et sauvegarde le payload, n'envoie rien
   python -m unittest ci.tests.test_security_observability -v
   ```
2. Pipeline GitLab : le job `security_observability:grafana` affiche
   `Security telemetry exported successfully (HTTP 200, otlp-gateway-...)`.
3. Grafana : **Explore** → source Prometheus → `pygoat_security_gate_status` → une série
   `{project="...", branch="master"}` de valeur 1 (PASS) ou 0 (BLOCKED).
4. Le tableau de bord doit afficher la même décision que le job `security_gate` du même pipeline.

## 10. Dépannage

| Symptôme | Cause probable | Correction |
|---|---|---|
| `HTTP 401` / `403` | Instance ID erroné, jeton expiré ou sans `metrics:write` | régénérer le jeton, vérifier l'Instance ID |
| `HTTP 404` | endpoint sans `/otlp` | utiliser l'URL exacte de la page OpenTelemetry |
| `unreachable` | panne réseau / Grafana Cloud | job orange toléré, relancer plus tard ; la gate n'est pas affectée |
| `partially configured` | variables protégées + branche non protégée, ou variable oubliée | aligner l'option *Protect* des 3 variables |
| `security-summary.json not found` | le job `security_gate` n'a pas produit d'artefact | lire le log de `security_gate` |
| Tableau de bord « NO DATA » | période trop courte, mauvaise branche / source | élargir la période (ex. 30 jours), choisir `master` |
| Métrique introuvable dans Explore | nom transformé par l'ingestion | chercher `pygoat_security` dans le *Metrics browser* |
| Panneaux historiques vides | aucun pipeline exporté sur la période | relancer un pipeline : l'historique est renvoyé à chaque export |
