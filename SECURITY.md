# Securite — resultats des scans

Ce depot est le support du TP1 DevSecOps (SAST + SCA). Il contient, dans son
historique Git, une application volontairement vulnerable puis sa remediation.

## Historique

| Tag / commit | Etat |
|---|---|
| `baseline` | application vulnerable, avant tout scan |
| `fix(sast)` | correctifs d'analyse statique |
| `fix(sca)`  | mise a jour des dependances vulnerables |

## SAST (Bandit + SonarQube)

| Vulnerabilite | Regle | Correctif |
|---|---|---|
| Injection SQL | Bandit B608 | requetes parametrees (`?` placeholders) |
| Injection de commande | Bandit B605 | suppression de `os.system`, dump via l'API SQLite |
| XSS | — | `render_template` (auto-echappement Jinja2) au lieu de `render_template_string` |
| Hachage MD5 | Bandit B324 / Sonar hotspot | `werkzeug.security` (pbkdf2) |
| TLS desactive | Bandit B501 / Sonar S4830 | verification du certificat reactivee |
| `yaml.load` | Bandit B506 | `yaml.safe_load` |
| Secret en dur | Bandit B105 | lu depuis une variable d'environnement |
| `debug=True` / bind 0.0.0.0 | Bandit B201 / B104 | controles par variables d'environnement |

Resultat : **Bandit 9 -> 0**, **SonarQube Security D -> A**.

## SCA (OSV / pip-audit / OWASP Dependency-Check)

7 paquets vulnerables, ~55 CVE a l'etat initial. Mise a jour vers des versions
corrigees (Flask 3.1, Werkzeug 3.1, Jinja2 3.1.6, urllib3 2.8, requests 2.32.5,
etc.) et passage de l'image de base Python 3.9 -> 3.11.

Resultat : **0 paquet vulnerable**.

CVE phare : **Jinja2 2.10 / CVE-2019-10906** — evasion du bac a sable de
templates via `str.format_map`, pouvant mener a l'execution de code. Corrigee
en 2.10.1.
