# VulnBank — TP2 DevSecOps : sécurité dans un pipeline CI/CD

Suite du [TP1](https://github.com/HanineKhemir/devsecops-tp1-sast-sca) (SAST + SCA
lancés **à la main**). Ici, les mêmes scans deviennent un **garde-fou automatique** :
un pipeline GitHub Actions qui **bloque toute fusion** contenant une vulnérabilité
critique ou haute.

> **Avertissement** : l'application contient volontairement des failles (support
> pédagogique). Elle ne doit jamais être déployée ailleurs qu'en local ou dans
> l'environnement éphémère du pipeline.

## Le pipeline

Fichier : [`.github/workflows/ci-security.yml`](.github/workflows/ci-security.yml)

```
                        push / pull request sur main
                                     │
        ┌────────────┬───────────────┼───────────────┬────────────┐
        ▼            ▼               ▼               ▼            │
  ┌───────────┐ ┌─────────┐   ┌─────────────┐  ┌──────────┐      │
  │1. BUILD   │ │ 2. SAST │   │   3. SCA    │  │ 4. DAST  │      │ en
  │  & TESTS  │ │ Bandit  │   │  pip-audit  │  │ OWASP    │      │ parallèle
  │  pytest   │ │ (code)  │   │   (CVE)     │  │   ZAP    │      │
  └───────────┘ └─────────┘   └─────────────┘  └──────────┘      │
        │            │               │               │            │
        └────────────┴───────────────┼───────────────┴────────────┘
                                     ▼
                        ┌─────────────────────────┐
                        │  VERDICT DE SÉCURITÉ    │
                        │  4 vertes → fusion OK   │
                        │  1 rouge  → fusion KO   │
                        └─────────────────────────┘
```

| # | Porte | Outil | Ce qu'elle vérifie | Règle de blocage |
|---|---|---|---|---|
| 1 | Build & tests | `pytest` | compilation + 14 tests de **non-régression de sécurité** | un test rouge = pipeline rouge |
| 2 | **SAST** | Bandit | failles dans **notre code** (analyse statique) | ≥ 1 constat de sévérité **HIGH** |
| 3 | **SCA** | pip-audit / OSV | **CVE connues** de nos dépendances | ≥ 1 CVE connue (politique stricte) |
| 4 | **DAST** | OWASP ZAP | failles de l'application **qui tourne** (scan actif) | ≥ 1 alerte de risque **High** |

Les quatre jobs sont **indépendants et parallèles** : une PR vulnérable montre
d'un seul coup *tous* ses problèmes (si les scanners dépendaient des tests, des
tests rouges les empêcheraient de s'exécuter).

### Les règles de blocage sont du code, pas une option de scanner

Chaque porte est un petit script Python sans dépendance : il lit le rapport JSON
du scanner et renvoie `exit 1` si la règle est violée.

| Script | Porte | Règle |
|---|---|---|
| [`scripts/gate_bandit.py`](scripts/gate_bandit.py) | SAST | bloque sur `issue_severity == HIGH` |
| [`scripts/gate_sca.py`](scripts/gate_sca.py) | SCA | bloque sur toute CVE/GHSA connue |
| [`scripts/gate_zap.py`](scripts/gate_zap.py) | DAST | bloque sur `riskcode == 3` (High) |

Pourquoi ne pas utiliser le code de sortie des scanners ? Parce qu'ils échouent
sur **toute** anomalie, même informative : le pipeline serait rouge en permanence
et l'équipe finirait par l'ignorer. Ici la règle est **écrite, lisible et
identique en local et en CI**, et chaque script accepte des **exceptions
documentées** (dictionnaire `EXCEPTIONS`, justification + date) pour traiter un
faux positif sans désactiver la porte.

Un rapport **manquant** est aussi traité comme un échec : un scanner cassé ne doit
jamais être confondu avec un scanner qui n'a rien trouvé.

### L'environnement éphémère (porte DAST)

Le job `dast` déploie l'application le temps du scan, puis la détruit :

1. `docker build` de l'image, puis réseau Docker privé `zapnet` ;
2. conteneur `vulnbank` démarré dessus — **non exposé** au réseau du runner ;
3. attente de la sonde `HEALTHCHECK` du [`Dockerfile`](Dockerfile) — on ne scanne
   jamais une application pas encore démarrée (sinon : rapport vide, porte verte
   à tort) ;
4. ZAP en **scan actif** (`zap-full-scan.py`) : il envoie de vraies attaques et
   observe les réponses. Le scan *baseline* (passif) ne produit presque jamais
   d'alerte High — il ne verrait ni injection SQL ni XSS réfléchi ;
5. destruction du conteneur et du réseau (`if: always()`).

## Rejouer le pipeline en local

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Porte 1 — tests unitaires
pytest tests/ -v

# Porte 2 — SAST
bandit -r vulnbank -f json -o reports/bandit.json --exit-zero
PYTHONPATH=scripts python scripts/gate_bandit.py reports/bandit.json

# Porte 3 — SCA
pip-audit -r requirements.txt -f json -o reports/pip-audit.json || true
PYTHONPATH=scripts python scripts/gate_sca.py reports/pip-audit.json

# Porte 4 — DAST (environnement éphémère : application + ZAP)
docker compose -f docker-compose.ci.yml up --build --abort-on-container-exit
PYTHONPATH=scripts python scripts/gate_zap.py reports/zap.json
docker compose -f docker-compose.ci.yml down -v
```

## Lancer l'application seule

```bash
docker build -t vulnbank:local .
docker run --rm -e HOST=0.0.0.0 -e SECRET_KEY=dev-local -p 5000:5000 vulnbank:local
# http://localhost:5000
```

Comptes de test : `alice/password`, `bob/123456`, `admin/admin`.

## Structure

| Chemin | Rôle |
|---|---|
| `.github/workflows/ci-security.yml` | le pipeline (5 jobs) |
| `scripts/gate_*.py` | les règles de blocage |
| `tests/test_app.py` | tests de non-régression de sécurité |
| `docker-compose.ci.yml` | environnement éphémère, rejouable en local |
| `.zap/rules.tsv` | réglage du bruit ZAP |
| `vulnbank/` | l'application Flask (reprise du TP1, corrigée) |
| `RAPPORT.md` | compte rendu du TP |

## Démonstration (partie « Validation » de l'énoncé)

Deux pull requests prouvent que le garde-fou fonctionne :

| PR | Contenu | Résultat attendu |
|---|---|---|
| **PR #1** | route `/search` non sécurisée + `os.system` + dépendance vulnérable | 4 portes ❌ — **fusion bloquée** |
| **PR #2** | la même fonctionnalité, corrigée | 4 portes ✅ — **fusion autorisée** |

Détail des failles, des alertes obtenues et des corrections : [`RAPPORT.md`](RAPPORT.md).
