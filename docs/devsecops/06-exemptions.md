# 06 — Exceptions de sécurité et faux positifs : procédure contrôlée et auditable

> Une exemption est l'acceptation **temporaire**, **tracée** et **approuvée** d'**un** finding bloquant
> précis. Ce n'est jamais « ignorer un scanner ».

Exigences couvertes : R7.3 (procédure d'exception), R5.3 (bloquant / non bloquant), R5.2 (quality gate).
Fichiers : `ci/exemptions.toml` (registre), `ci/security_gate.py` (application automatique),
`ci/tests/test_exemptions.py` (tests), `ci/tests/demo_exemption_workflow.py` (démonstration).

---

## 1. Qu'est-ce qu'un faux positif ?

Un scanner signale un problème qui, **dans ce contexte précis**, n'en est pas un. Exemples typiques :

- Bandit signale `subprocess` avec `shell=True`, mais la commande est une constante sans aucune entrée
  utilisateur ;
- Trivy signale une CVE dans une fonction d'une bibliothèque que l'application n'appelle jamais ;
- Gitleaks détecte une « clé » qui est en réalité une valeur d'exemple documentée.

Il existe un second cas, différent : le **risque accepté**. La vulnérabilité est réelle, mais aucun
correctif n'existe encore et le risque est jugé tolérable pendant une durée limitée. Les deux cas suivent
la même procédure ; la justification (`reason`) doit dire lequel des deux s'applique et pourquoi.

## 2. Pourquoi désactiver un scanner (ou baisser un seuil) est une erreur

| Mauvaise réponse | Conséquence |
|---|---|
| Retirer le job du pipeline | plus aucune détection, y compris des **vrais** problèmes futurs |
| Baisser un seuil dans `security-policy.toml` | toutes les vulnérabilités de ce niveau passent, pour tout le projet |
| `# nosec`, `# nosemgrep` dans le code | décision invisible, non datée, non approuvée, sans expiration |
| Règle à joker (« tout Bandit dans ce dossier ») | les findings **à venir** au même endroit sont masqués sans revue |

Une exemption, au contraire, ne couvre qu'**un** finding identifié, pour une **durée limitée**, avec un
**responsable**, un **approbateur** et une **référence de suivi**, et reste **visible** dans tous les
rapports.

## 3. Cycle de vie d'une exception

```
 1. Détection      la gate bloque et affiche le fingerprint du finding
 2. Analyse        l'owner prouve le faux positif / évalue le risque → ticket
 3. Demande        merge request ajoutant UNE entrée [[exemption]] dans ci/exemptions.toml
 4. Approbation    l'approver (≠ owner) relit la preuve et approuve la merge request
 5. Application    la gate couvre ce finding exact : visible « EXEMPTED », plus bloquant
 6. Suivi          le ticket reste ouvert ; la synthèse liste l'exemption à chaque pipeline
 7. Fin            correctif livré → entrée supprimée   |   date dépassée → expirée, le finding rebloque
```

## 4. Correspondance exacte : le fingerprint

Chaque finding reçoit un identifiant stable, le **fingerprint** :

```
<règle>|<emplacement>
B602|introduction/views.py:120              (SAST : règle | fichier:ligne)
CVE-2024-12345|somepackage@1.2.3            (SCA / image : CVE | paquet@version)
CKV_DOCKER_3|Dockerfile                      (IaC : check | fichier)
```

La gate l'affiche sous chaque finding bloquant (`fingerprint : …`), et il figure dans le rapport JSON.
Une exemption s'applique uniquement si **le contrôle ET le fingerprint sont identiques**, caractère pour
caractère :

- **aucun joker** (`*`, `?`, `[ ]`) : une entrée qui en contient est refusée ;
- une autre ligne, un autre fichier, une autre version de paquet ou un autre contrôle → **pas d'exemption** ;
- si le code bouge (le finding change de ligne), le fingerprint change : l'exemption ne s'applique plus et
  le finding rebloque. C'est volontaire : un code modifié doit être ré-analysé.
- seuls les findings **bloquants** sont concernés ; une exemption ne modifie jamais un avertissement.

## 5. Champs d'audit obligatoires

| Champ | Contenu | Contrôle automatique |
|---|---|---|
| `id` | `EXC-001`, `EXC-002`… | format `EXC-NNN`, unique |
| `control` | contrôle de `security-policy.toml` (`secrets`, `sast_bandit`, `sca`…) | doit exister |
| `fingerprint` | `<règle>\|<emplacement>` copié depuis la sortie de la gate | exact, sans joker |
| `reason` | faux positif ou risque accepté, et la preuve | ≥ 20 caractères |
| `owner` | responsable du risque et du suivi | obligatoire |
| `approver` | personne qui accepte le risque | obligatoire, **différente** de l'owner |
| `ticket` | référence de suivi (issue GitLab…) | obligatoire |
| `created` | date d'acceptation (`AAAA-MM-JJ`, sans guillemets) | date TOML, pas dans le futur |
| `expires` | date limite, **incluse** | ≥ created, durée ≤ 90 jours |

Tout autre champ est refusé : les anciens champs `match` / `path`, qui acceptaient des jokers, ne
peuvent plus être utilisés, et une faute de frappe dans un nom de champ ne passe pas inaperçue.

### Owner ou approver ?

- **Owner** : la personne qui demande l'exception et s'engage à la suivre (analyse, correctif, suppression
  de l'entrée). En général le développeur ou l'équipe propriétaire du code.
- **Approver** : la personne qui **accepte le risque** au nom du projet (responsable sécurité, tech lead).
  Elle relit la preuve et approuve la merge request.

Une même personne ne peut pas tenir les deux rôles (principe des **4 yeux**) : la gate refuse une entrée
où `owner` et `approver` sont identiques.

### Expiration et ticket

Une exception sans fin devient une dette invisible. La durée maximale est de **90 jours**
(`max_exemption_days` dans `security-policy.toml`). Le **ticket** relie l'exception à son suivi : analyse,
décision, correctif prévu. À l'échéance, il faut soit livrer le correctif (et supprimer l'entrée), soit
refaire une nouvelle demande justifiée.

## 6. Comment la Security Gate traite chaque cas

| Situation | Effet sur le finding | Effet sur la gate |
|---|---|---|
| Pas d'exemption | bloquant | BLOCKED |
| Exemption **active**, correspondance exacte | niveau **EXEMPTED**, id d'exemption attaché, toujours visible | ne compte plus comme bloquant |
| Exemption active, autre fingerprint / autre contrôle | inchangé (bloquant) | BLOCKED ; exemption signalée « sans finding correspondant » |
| Exemption **expirée** | plus appliquée : redevient bloquant s'il existe encore | BLOCKED seulement si le finding existe encore |
| Exemption expirée dont le finding a disparu | — | **aucun effet** (simple avertissement « expirée » à nettoyer) |
| Registre **mal formé** (champ manquant, joker, owner = approver, durée > 90 j, TOML invalide…) | **aucune** exemption du registre n'est appliquée | **BLOCKED** (fail-secure) avec un message explicite |

Où l'exemption reste visible :

- **log du job** : `◌ EXEMPTÉ par EXC-001 — [HIGH] <fingerprint>` ;
- **`reports/security-summary.json`** : `controls.<scanner>.exempted` (compteur) et
  `exemptions.applied` (id, contrôle, fingerprint, raison, owner, approver, ticket, dates) ;
  `exemptions.expired` et `exemptions.unused` pour le nettoyage ;
- **`reports/security-summary.md`** : une ligne par exemption appliquée, expirée ou inutilisée ;
- **onglet *Tests* de GitLab** (JUnit) : le finding exempté apparaît en *skipped* avec l'id d'exemption.

Comptage : un finding exempté est compté dans `exempted`, ni dans `blockers` ni dans `warnings` ;
`blockers + warnings + info + exempted` = nombre total de findings.

### Correction apportée (phase C4)

Avant cette phase :

1. une exemption **expirée** bloquait **toute** la gate, même si le finding concerné avait été corrigé
   depuis longtemps — une vieille entrée inoffensive empêchait des livraisons sans rapport ;
2. les champs `match` / `path` acceptaient des jokers : `match = "*"` sans `path` revenait à ignorer
   **tous** les findings d'un scanner ;
3. un registre TOML invalide ou une date entre guillemets provoquait un plantage Python au lieu d'un refus
   explicite ;
4. le finding exempté était compté à la fois en avertissement et en exempté.

Désormais : l'expiration ne fait que retirer l'exemption ; la correspondance est exacte ; toute erreur de
registre produit un refus clair ; les compteurs ne se recouvrent plus.

## 7. Exemple SÛR (fictif)

Le fingerprint ci-dessous ne correspond à **aucun** finding réel. Il sert uniquement aux tests et à la
démonstration.

```toml
[[exemption]]
id          = "EXC-001"
control     = "sast_bandit"
fingerprint = "DEMO-FINGERPRINT-DO-NOT-USE|demo/synthetic_example.py:10"
reason      = "Faux positif démontré : la valeur ne provient jamais d'une entrée utilisateur (analyse dans le ticket)."
owner       = "developer.demo"
approver    = "security.demo"
ticket      = "#DEMO"
created     = 2026-10-09
expires     = 2026-10-23
```

## 8. Démonstration (données synthétiques uniquement)

```bash
python -m ci.tests.demo_exemption_workflow
```

Le script crée un rapport Bandit **synthétique** dans un dossier temporaire, avec la politique réelle
inchangée, puis :

1. sans exemption → `DEMO-FINGERPRINT-DO-NOT-USE|…` **BLOCKING** → gate **❌ BLOCKED** ;
2. avec `EXC-001` valide (14 jours, owner ≠ approver) → **EXEMPTED by EXC-001**, trace d'audit affichée →
   gate **✅ PASS** ;
3. avec la même exemption **expirée** hier → le finding redevient **BLOCKING** → gate **❌ BLOCKED**.

Rien n'est écrit dans `reports/`, `ci/exemptions.toml` ou `monitoring/`. Les tests automatisés
(`python -m unittest ci.tests.test_exemptions -v`) couvrent en plus : autre fingerprint, autre contrôle,
expiration incluse, expirée sans effet sur le reste, jokers et anciens champs refusés, champs manquants,
owner = approver, durée excessive, dates invalides, id en double, TOML invalide, traces dans la synthèse,
le Markdown et le JUnit, et l'absence d'exemption dans le registre réel.

## 9. Révoquer une exemption

- **Correctif livré** ou **risque plus acceptable** : supprimer l'entrée `[[exemption]]` par merge request
  (référence au ticket dans le message de commit). Au pipeline suivant, le finding (s'il existe encore)
  bloque à nouveau.
- **Urgence** : la suppression de l'entrée suffit, elle prend effet au prochain pipeline ; aucune autre
  configuration n'est à modifier.
- **Exemption expirée** : elle ne protège déjà plus rien ; la supprimer du registre pour le garder propre
  (la synthèse la signale tant qu'elle est présente).
- L'historique git conserve la trace complète : qui a ajouté, approuvé et retiré l'exception, et quand.

## 10. Pourquoi la baseline de production n'a aucune exemption active

La baseline `5a3b908` passe la Security Gate avec **0 finding bloquant** et **0 exemption** : chaque
bloquant initial (1104) a été **corrigé** (mise à jour d'image et de dépendances, suppression des secrets,
correction du code), pas masqué. `ci/exemptions.toml` ne contient qu'un exemple en commentaire ; un test
automatisé vérifie que le registre réel est vide. La procédure existe et est testée, mais elle n'a pas été
nécessaire : c'est l'objectif — l'exception doit rester rare, temporaire et visible.
