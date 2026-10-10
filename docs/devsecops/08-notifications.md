# 08 — Notifications Slack : alertes sécurité et mise en production

> **SCANNERS DETECT → SECURITY GATE DECIDES → GRAFANA VISUALISES → SLACK NOTIFIES**
>
> Slack informe l'équipe. Slack ne décide **jamais** si une version peut partir en production.

Exigences couvertes : R6.3 (notification des résultats), R5.4 (secret du pipeline).

---

## 1. Rôle de Slack

Le pipeline prévient l'équipe au moment où une décision est prise, sans qu'elle ait à surveiller GitLab :

| Événement | Message | Quand |
|---|---|---|
| Security Gate PASS | 🟢 **RELEASE AUTHORIZED** | à la fin de `security_gate`, à chaque pipeline |
| Security Gate BLOCKED | 🔴 **RELEASE BLOCKED** | à la fin de `security_gate`, à chaque pipeline |
| Mise en production | 🚀 **PRODUCTION PROMOTED** | après un `deploy:production` manuel réussi |

Script : `ci/slack_notify.py` (bibliothèque standard Python uniquement), deux modes :

```bash
python3 ci/slack_notify.py --event gate         # PASS ou BLOCKED
python3 ci/slack_notify.py --event production   # promotion en production
python3 ci/slack_notify.py --event gate --dry-run   # affiche le message, n'envoie rien
```

## 2. Pourquoi Slack ne décide pas

1. **La décision existe avant le message.** `ci/security_gate.py` applique la politique versionnée
   (`ci/security-policy.toml`, `ci/exemptions.toml`) et écrit `reports/security-summary.json`. Le script
   Slack **lit** ce fichier : `gate_status`, `release_allowed`, `totals.blockers / warnings / info`,
   `branch`, `commit_short_sha`, `pipeline_url`. Il ne recalcule rien et n'invente aucune valeur.
2. **Aucune dépendance inverse.** `deploy:production` dépend uniquement de `security_gate`
   (`needs: [security_gate]`). Les jobs Slack ne figurent dans les `needs` d'aucun job de livraison.
3. **Une panne de Slack ne change pas la décision.** Si Slack est injoignable, le job de notification
   est en échec (orange) mais la gate reste PASS ou BLOCKED, et le message n'est jamais réinterprété.
4. **Cohérence vérifiée.** Un `summary` où `release_allowed` contredit `gate_status` est refusé (erreur
   visible). Une notification « production » avec une gate non PASS est refusée.

## 3. Les trois alertes

Les blocs ci-dessous sont des **exemples de mise en forme** : les nombres réels viennent de la synthèse
de chaque pipeline.

Format : Slack *Block Kit* (titre, champs, explication, lien vers le pipeline) + un champ `text` de
secours (notifications mobiles, lecteurs d'écran). Les valeurs venant de GitLab (nom de branche…) sont
échappées : une branche nommée `<!channel>` ne peut pas déclencher de mention ni de faux lien.

### 3.1 🟢 RELEASE AUTHORIZED (gate PASS)

```
🟢 RELEASE AUTHORIZED
Security Gate: PASS          Blocking findings: 0
Warnings: 20                 Info: 32
Branch: master               Commit: 5a3b9080
Production promotion is now allowed but still requires manual approval (job deploy:production).
Pipeline: #123456789 (lien cliquable)
```

### 3.2 🔴 RELEASE BLOCKED (gate BLOCKED)

```
🔴 RELEASE BLOCKED
Security Gate: BLOCKED       Blocking findings: 4
Warnings: 14                 Info: 7
Branch: feature/x            Commit: 1a2b3c4d
Production promotion is refused by security policy: 4 blocking finding(s).
See the reports and the Tests tab of the pipeline.
Pipeline: #123456790 (lien cliquable)
```

Un rapport de scanner absent compte comme bloquant (fail-secure) : il apparaît donc dans « Blocking
findings » et le message est BLOCKED.

### 3.3 🚀 PRODUCTION PROMOTED

```
🚀 PRODUCTION PROMOTED
Security Gate: PASS          Promotion: completed
Branch: master               Commit: 5a3b9080
Validated image: registry.gitlab.com/<groupe>/<projet>:5a3b9080
Production tag: registry.gitlab.com/<groupe>/<projet>:production
Production release/promotion completed: the image validated by the Security Gate was promoted
to the production tag after manual approval.
```

Vocabulaire exact : `deploy:production` **promeut** l'image validée (re-tag `production` dans le
registre GitLab). Le message parle donc de *production release/promotion*, pas d'un serveur en
fonctionnement.

## 4. Jobs GitLab CI

```yaml
.slack:
  stage: notify
  image: python:3.12-alpine
  allow_failure:
    exit_codes: [3]

notify:slack-gate:            # PASS et BLOCKED
  extends: .slack
  when: always
  needs: [{job: security_gate, artifacts: true}]
  script: [python3 ci/slack_notify.py --event gate]

notify:slack-production:      # après deploy:production manuel réussi
  extends: .slack
  needs: [{job: deploy:production, artifacts: false}, {job: security_gate, artifacts: true}]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      when: on_success
  script: [python3 ci/slack_notify.py --event production]
```

**Pourquoi l'alerte BLOCKED part quand même** : quand des findings bloquants existent,
`security_gate` sort en code 1 (job en échec). `when: always` fait démarrer `notify:slack-gate` quel que
soit ce résultat, et `needs` + `artifacts: true` lui donne `reports/security-summary.json` (artefact
conservé `when: always`). Grâce à `needs`, il n'attend pas le job manuel `deploy:production`.

**Pourquoi l'alerte production ne part qu'après une promotion réussie** : `on_success` + `needs:
deploy:production` → le job démarre uniquement quand le job manuel a été lancé ET a réussi. Si la gate
est BLOCKED, `deploy:production` est ignoré, donc l'alerte production aussi. Les `rules` sont celles de
`deploy:production` : sur une autre branche, aucun des deux jobs n'existe.

| Situation | Code | Job | Effet sur la gate / la livraison |
|---|---|---|---|
| Message envoyé | 0 | vert | aucun |
| `SLACK_WEBHOOK_URL` absente | 0 | vert (« not configured — nothing sent ») | aucun |
| Slack injoignable, HTTP 4xx/5xx | 3 | **orange** (échec toléré, visible) | aucun |
| Synthèse absente / invalide, URL non `https://hooks.slack.com/services/…` | 2 | **rouge** | aucun : à corriger |

`allow_failure` seulement pour le code 3 : une panne de Slack est externe et ne doit pas rendre un
pipeline PASS rouge, mais elle reste visible (job orange). Une erreur de configuration est une erreur du
projet : elle doit être corrigée, donc le job est rouge.

Ancien job remplacé : `notify:slack` (curl, `when: on_failure`) n'alertait jamais en cas de PASS,
attendait le job manuel de production sur la branche par défaut, et construisait le JSON par
concaténation shell (un titre de commit avec des guillemets cassait le message).

## 5. Gestion du secret

- L'URL d'un *Incoming Webhook* **est** le secret : quiconque la connaît peut écrire dans le canal.
- Elle est stockée uniquement dans GitLab : **Settings → CI/CD → Variables** → `SLACK_WEBHOOK_URL`,
  *Masked and hidden* (ou *Masked*) et *Protected*. Jamais dans le dépôt, jamais dans un artefact.
- Le script ne l'affiche jamais : ni l'URL, ni son chemin (`/services/…`), y compris dans les erreurs
  (remplacés par `[REDACTED]`).
- Validation stricte : `https` obligatoire, hôte exactement `hooks.slack.com`, chemin `/services/…`,
  pas d'identifiants ni de paramètres dans l'URL. Une URL mal recopiée ou pointant ailleurs est refusée
  avant tout envoi (évite d'exfiltrer le message vers un autre serveur).
- Le message ne contient que des compteurs, statuts, branche, commit, lien de pipeline et nom d'image :
  aucun secret Django, Grafana ou GitLab (vérifié par les tests avec des valeurs témoins aléatoires).
- *Protected* : seuls les pipelines des branches protégées (`master`) envoient des messages. Les branches
  non protégées affichent « not configured » — choix volontaire pour qu'une branche quelconque ne puisse
  pas utiliser le webhook.

### Créer le webhook (aucune URL réelle dans ce document)

1. Slack → **Paramètres et administration → Gérer les apps** → *Create New App* → *From scratch*
   (ex. `PyGoat Sentinel`, dans l'espace de travail du projet).
2. **Incoming Webhooks** → *Activate* → **Add New Webhook to Workspace** → choisir le canal
   (ex. `#pygoat-security`) → *Allow*.
3. Copier l'URL `https://hooks.slack.com/services/<…>` **directement** dans la variable GitLab
   `SLACK_WEBHOOK_URL` (*Masked*, *Protected*). Ne pas la coller ailleurs.
4. Relancer un pipeline sur `master`.

En cas de fuite : Slack → l'app → *Incoming Webhooks* → **Revoke** le webhook, en créer un nouveau,
mettre à jour la variable GitLab.

## 6. Dépannage

| Symptôme | Cause probable | Correction |
|---|---|---|
| « Slack notifications not configured » | variable absente, ou protégée et branche non protégée | créer la variable / lancer sur `master` |
| `CONFIGURATION ERROR: … must point to https://hooks.slack.com/` | URL mal recopiée (espace, autre service) | recopier l'URL complète du webhook |
| `HTTP 403` / `404` / `410` | webhook révoqué, app supprimée, canal archivé | créer un nouveau webhook, mettre à jour la variable |
| `HTTP 400 invalid_payload` | message refusé par Slack | lire le message d'erreur du job ; vérifier avec `--dry-run` |
| `Slack unreachable` | panne réseau / Slack | job orange toléré ; la gate n'est pas affectée ; relancer le job |
| `security summary not found` | `security_gate` n'a pas produit d'artefact | lire le log de `security_gate` |
| Pas d'alerte production | `deploy:production` non lancé ou en échec | lancer le job manuel ; vérifier son log |
| Alerte BLOCKED attendue mais absente | job `notify:slack-gate` absent du pipeline | vérifier `.gitlab-ci.yml` (`when: always`) |

Test local sans Slack :

```bash
python3 ci/security_gate.py --all
python3 ci/slack_notify.py --event gate --dry-run
python -m unittest ci.tests.test_slack_notify -v
```

## 7. Captures d'écran à réaliser pour le rapport

1. GitLab → Settings → CI/CD → Variables : `SLACK_WEBHOOK_URL` *Masked* + *Protected* (valeur cachée).
2. Pipeline PASS : graphe montrant `security_gate` → `notify:slack-gate` (vert) et `deploy:production`
   en attente manuelle.
3. Slack : message 🟢 **RELEASE AUTHORIZED** avec le lien du pipeline.
4. Pipeline BLOCKED (pipeline de démonstration, scénario à préparer lors de la phase de démo) :
   `security_gate` rouge, `notify:slack-gate` exécuté quand même.
5. Slack : message 🔴 **RELEASE BLOCKED** avec le nombre de bloquants.
6. Job manuel `deploy:production` lancé → `notify:slack-production` vert.
7. Slack : message 🚀 **PRODUCTION PROMOTED** (image validée et tag `production`).
8. Log d'un job de notification : aucune URL de webhook visible.
