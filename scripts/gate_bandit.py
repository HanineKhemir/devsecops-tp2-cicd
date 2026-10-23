#!/usr/bin/env python3
"""
PORTE SAST — analyse statique du code (rapport Bandit).

REGLE DE BLOCAGE
    Toute vulnerabilite de severite HIGH arrete le pipeline.
    Les severites MEDIUM et LOW sont affichees comme avertissements.

Pourquoi HIGH seulement ? Bandit classe en MEDIUM/LOW beaucoup de constats de
style ou de contexte (ex. "assert utilise", "binding sur 0.0.0.0"). Bloquer sur
tout rendrait le pipeline inutilisable. L'enonce demande de bloquer les
vulnerabilites critiques ou hautes : chez Bandit, cela correspond a HIGH
(B602/B605 injection de commande, B501 TLS non verifie, B201 debug actif...).

Usage : python scripts/gate_bandit.py reports/bandit.json
"""

import sys

from gate_common import lire_rapport, titre, verdict

# Severites qui arretent le pipeline
SEVERITES_BLOQUANTES = {"HIGH"}

# ---------------------------------------------------------------------------
# EXCEPTIONS DOCUMENTEES (faux positifs acceptes par l'equipe)
#
# Format :  "B###" : "justification — qui, quand"
# Une exception doit toujours etre justifiee et datee : c'est une dette de
# securite assumee, pas un oubli. Vide aujourd'hui : aucun faux positif HIGH.
# ---------------------------------------------------------------------------
EXCEPTIONS = {}


def main(chemin_rapport):
    titre("PORTE SAST — Bandit (analyse statique du code)")
    rapport = lire_rapport(chemin_rapport)
    resultats = rapport.get("results", [])

    # Comptage par severite, pour le resume
    comptes = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    bloquants = []
    ignores = []

    for resultat in resultats:
        severite = resultat.get("issue_severity", "UNDEFINED").upper()
        comptes[severite] = comptes.get(severite, 0) + 1
        if severite not in SEVERITES_BLOQUANTES:
            continue
        if resultat.get("test_id") in EXCEPTIONS:
            ignores.append(resultat)
        else:
            bloquants.append(resultat)

    nombre_de_lignes = rapport.get("metrics", {}).get("_totals", {}).get("loc", "?")
    print(f"Lignes de code analysees : {nombre_de_lignes}")
    print(
        "Constats : "
        f"{comptes.get('HIGH', 0)} HIGH, "
        f"{comptes.get('MEDIUM', 0)} MEDIUM, "
        f"{comptes.get('LOW', 0)} LOW"
    )
    print()

    # Detail des constats bloquants
    for resultat in bloquants:
        print(f"[BLOQUANT] {resultat['test_id']} — {resultat.get('test_name', '')}")
        print(f"  Fichier    : {resultat['filename']}:{resultat['line_number']}")
        print(f"  Probleme   : {resultat['issue_text']}")
        print(f"  Confiance  : {resultat.get('issue_confidence', '?')}")
        cwe = resultat.get("issue_cwe") or {}
        if cwe.get("id"):
            print(f"  CWE        : CWE-{cwe['id']} ({cwe.get('link', '')})")
        extrait = (resultat.get("code") or "").strip().splitlines()
        if extrait:
            print(f"  Code       : {extrait[0].strip()}")
        print()

    for resultat in ignores:
        print(
            f"[EXCEPTION ACCEPTEE] {resultat['test_id']} "
            f"({resultat['filename']}:{resultat['line_number']}) — "
            f"{EXCEPTIONS[resultat['test_id']]}"
        )

    # Avertissements non bloquants : visibles, mais ne cassent pas le build
    for resultat in resultats:
        if resultat.get("issue_severity", "").upper() == "MEDIUM":
            print(
                f"[AVERTISSEMENT] {resultat['test_id']} "
                f"({resultat['filename']}:{resultat['line_number']}) — "
                f"{resultat['issue_text']}"
            )

    # Resume affiche sur la page du run GitHub Actions
    lignes = [
        "## Porte SAST — Bandit",
        "",
        "| Severite | Constats | Bloquant |",
        "|---|---|---|",
        f"| HIGH | {comptes.get('HIGH', 0)} | oui |",
        f"| MEDIUM | {comptes.get('MEDIUM', 0)} | non |",
        f"| LOW | {comptes.get('LOW', 0)} | non |",
        "",
    ]
    if bloquants:
        lignes.append("**Vulnerabilites bloquantes :**")
        lignes.append("")
        for resultat in bloquants:
            lignes.append(
                f"- `{resultat['test_id']}` {resultat['issue_text']} "
                f"— `{resultat['filename']}:{resultat['line_number']}`"
            )
        lignes.append("")
    else:
        lignes.append("Aucune vulnerabilite de severite HIGH. Porte verte.")
        lignes.append("")

    return verdict("SAST", len(bloquants), lignes)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
