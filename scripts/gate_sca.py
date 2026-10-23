#!/usr/bin/env python3
"""
PORTE SCA — vulnerabilites connues des dependances (rapport pip-audit / OSV).

REGLE DE BLOCAGE
    Toute dependance portant une vulnerabilite connue (CVE / GHSA) arrete le
    pipeline — politique STRICTE.

Pourquoi une politique stricte et non un filtre "HIGH/CRITICAL seulement" ?
La sortie JSON de pip-audit ne contient PAS de score CVSS : elle donne
l'identifiant de la faille (GHSA/PYSEC), ses alias (CVE) et la version
corrigee, mais pas la severite. On ne peut donc pas filtrer par severite de
facon fiable sans interroger une autre base. Deux consequences :

  1. on bloque sur toute CVE connue (surensemble de "critique ou haute" :
     la regle de l'enonce est donc bien respectee) ;
  2. le mecanisme d'EXCEPTIONS ci-dessous permet de debloquer un cas precis,
     avec justification ecrite, quand la faille ne nous concerne pas.

C'est tenable ici parce que les versions sont epinglees et deja corrigees au
TP1 : la porte est verte en regime normal.

Usage : python scripts/gate_sca.py reports/pip-audit.json
"""

import sys

from gate_common import lire_rapport, titre, verdict

# ---------------------------------------------------------------------------
# EXCEPTIONS DOCUMENTEES
#
# Format :  "IDENTIFIANT" : "justification — qui, quand"
# Exemple : "GHSA-xxxx-yyyy-zzzz": "faille dans un module non utilise
#            (export CSV) ; correctif prevu — equipe GL4, 23/10/2026"
#
# Equivalent de l'option  pip-audit --ignore-vuln <ID>  mais versionne dans le
# depot : l'exception est relue en revue de code, pas cachee dans une commande.
# Vide aujourd'hui : aucune CVE connue sur nos dependances.
# ---------------------------------------------------------------------------
EXCEPTIONS = {}


def extraire_dependances(rapport):
    """Renvoie la liste des dependances, quel que soit le format de pip-audit.

    Selon la version, pip-audit produit soit {"dependencies": [...]} soit
    directement une liste. On accepte les deux.
    """
    if isinstance(rapport, dict):
        return rapport.get("dependencies", [])
    if isinstance(rapport, list):
        return rapport
    return []


def main(chemin_rapport):
    titre("PORTE SCA — pip-audit / OSV (securite des dependances)")
    rapport = lire_rapport(chemin_rapport)
    dependances = extraire_dependances(rapport)

    bloquants = []
    ignores = []

    for dependance in dependances:
        for faille in dependance.get("vulns", []) or []:
            entree = (dependance, faille)
            identifiants = {faille.get("id")} | set(faille.get("aliases", []) or [])
            if identifiants & set(EXCEPTIONS):
                ignores.append(entree)
            else:
                bloquants.append(entree)

    print(f"Dependances analysees : {len(dependances)}")
    print(f"Dependances vulnerables : "
          f"{len({d['name'] for d, _ in bloquants + ignores})}")
    print(f"Vulnerabilites trouvees : {len(bloquants) + len(ignores)}")
    print()

    for dependance, faille in bloquants:
        alias = ", ".join(faille.get("aliases", []) or []) or "aucun"
        corrections = ", ".join(faille.get("fix_versions", []) or []) or "aucune"
        print(f"[BLOQUANT] {dependance['name']} {dependance['version']}")
        print(f"  Identifiant      : {faille.get('id')}")
        print(f"  Alias (CVE)      : {alias}")
        print(f"  Versions corrigees : {corrections}")
        description = (faille.get("description") or "").strip().replace("\n", " ")
        if description:
            print(f"  Description      : {description[:160]}")
        print()

    for dependance, faille in ignores:
        identifiant = faille.get("id")
        justification = EXCEPTIONS.get(identifiant) or next(
            (EXCEPTIONS[a] for a in faille.get("aliases", []) if a in EXCEPTIONS),
            "",
        )
        print(
            f"[EXCEPTION ACCEPTEE] {dependance['name']} {dependance['version']} "
            f"({identifiant}) — {justification}"
        )

    # Resume affiche sur la page du run GitHub Actions
    lignes = [
        "## Porte SCA — pip-audit / OSV",
        "",
        f"Dependances analysees : **{len(dependances)}** — "
        f"vulnerabilites bloquantes : **{len(bloquants)}**",
        "",
    ]
    if bloquants:
        lignes += [
            "| Paquet | Version | Faille | CVE | Corrige en |",
            "|---|---|---|---|---|",
        ]
        for dependance, faille in bloquants:
            lignes.append(
                f"| `{dependance['name']}` | {dependance['version']} | "
                f"{faille.get('id')} | "
                f"{', '.join(faille.get('aliases', []) or []) or '—'} | "
                f"{', '.join(faille.get('fix_versions', []) or []) or '—'} |"
            )
        lignes.append("")
        lignes.append(
            "Corriger : relever la version dans `requirements.txt` "
            "jusqu'a une version corrigee."
        )
        lignes.append("")
    else:
        lignes.append("Aucune CVE connue sur les dependances. Porte verte.")
        lignes.append("")

    return verdict("SCA", len(bloquants), lignes)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
