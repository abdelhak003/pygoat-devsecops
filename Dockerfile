# =============================================================================
#  Image PyGoat — construction en 2 étapes (multi-stage)
# -----------------------------------------------------------------------------
#  Base : python:3.11-slim-bookworm
#    - Python 3.11 STABLE (l'ancienne base était une bêta, 3.11.0b1)
#    - Debian 12 « bookworm », maintenue avec correctifs de sécurité
#      (l'ancienne base était Debian 10 « buster », en fin de vie : plus aucun correctif)
#    - variante « slim » : le strict minimum de paquets → surface d'attaque réduite
#
#  Étape 1 (builder) : contient les outils de compilation (gcc, en-têtes),
#                      nécessaires pour compiler psycopg2. Elle est JETÉE à la fin.
#  Étape 2 (finale)  : seulement l'exécution. Aucun compilateur en production.
# =============================================================================

# ---------- Étape 1 : compilation des dépendances Python ----------------------
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# build-essential + libpq-dev : compiler psycopg2 (dépendance de django-heroku, distribuée en sources)
RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Toutes les dépendances sont préparées sous forme de « wheels » (paquets déjà construits)
RUN pip wheel --wheel-dir /wheels -r requirements.txt


# ---------- Étape 2 : image d'exécution ----------------------------------------
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Paquets système d'EXÉCUTION uniquement :
#   libpq5   : bibliothèque PostgreSQL utilisée par psycopg2 (sans les en-têtes de compilation)
#   dnsutils : nslookup / dig, appelés par le lab d'injection de commande (introduction/views.py)
RUN apt-get update \
    && apt-get install --no-install-recommends -y libpq5 dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur dédié, sans privilèges, sans shell de connexion (moindre privilège)
RUN groupadd --system --gid 10001 pygoat \
    && useradd --system --uid 10001 --gid pygoat --home-dir /app --no-create-home \
       --shell /usr/sbin/nologin pygoat

# Installation hors-ligne depuis les wheels de l'étape 1 (aucun téléchargement ici).
# Puis les outils de gestion de paquets sont RETIRÉS de l'image finale : ni PyGoat, ni
# Django, ni Gunicorn n'en ont besoin à l'exécution. pip embarque ses propres copies
# de bibliothèques (urllib3, msgpack…) qui apparaissent comme vulnérables dans le scan
# d'image ; sans pip, plus de copies cachées. pip se désinstalle en DERNIER.
COPY requirements.txt /tmp/requirements.txt
COPY --from=builder /wheels /tmp/wheels
RUN pip install --no-index --find-links=/tmp/wheels -r /tmp/requirements.txt \
    && pip uninstall -y setuptools wheel \
    && pip uninstall -y pip \
    && rm -rf /tmp/wheels /tmp/requirements.txt

WORKDIR /app

# Le CODE appartient à root : l'application peut le lire et l'exécuter, mais pas le modifier.
COPY . /app/

# Le runner GitLab clone le code avec umask 0000 (fichiers potentiellement modifiables par
# tous) et COPY conserve ces droits → on retire l'écriture « groupe » et « autres » partout.
# Puis écriture autorisée UNIQUEMENT là où l'application en a besoin :
#   /app (le dossier lui-même) : base SQLite db.sqlite3 + son journal, test.log, staticfiles/
# Aucun fichier de code (.py) ni template n'est modifiable : les labs « playground » analysent
# le code de l'apprenant comme une DONNÉE (introduction/playground_review.py) au lieu de
# l'écrire dans des modules importés, et le lab SSTI stocke les billets en base.
RUN chmod -R go-w /app \
    && chown pygoat:pygoat /app

# À partir d'ici, tout s'exécute avec l'utilisateur non-root (CIS Docker 4.1)
USER pygoat

# La base est créée PAR l'utilisateur applicatif → il en est propriétaire.
# migrate charge les settings, qui exigent DJANGO_SECRET_KEY : une clé JETABLE est générée
# pour cette seule commande (variable limitée au RUN, jamais écrite dans l'image).
# La vraie clé est fournie au démarrage du conteneur (docker run -e / variable CI).
RUN DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(50))')" \
    python manage.py migrate --noinput

EXPOSE 8000

# Vérification de santé : l'application répond-elle en HTTP ? (sans curl, absent de l'image slim)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=4)" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "6", "pygoat.wsgi"]
