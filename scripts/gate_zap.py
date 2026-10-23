#!/usr/bin/env python3
"""
PORTE DAST — analyse dynamique de l'application en cours d'execution
(rapport OWASP ZAP, scan actif zap-full-scan.py).

REGLE DE BLOCAGE
    Toute alerte de risque HIGH (riskcode = 3) arrete le pipeline.
    Les alertes MEDIUM / LOW / INFO sont affichees comme avertissements.

Codes de risque ZAP :  3 = High, 2 = Medium, 1 = Low, 0 = Informational.

Pourquoi HIGH seulement ? Un scan ZAP sur une application web renvoie toujours
une serie d'alertes MEDIUM d'en-tetes manquants (CSP, X-Frame-Options...) :
ce sont des durcissements souhaitables, pas des failles exploitables. Les
alertes HIGH, elles, correspondent a une exploitation reellement demontree par
ZAP pendant le scan actif (injection SQL confirmee, XSS reflechi execute...) :
c'est exactement ce que l'enonce demande de bloquer.

Difference avec la porte SAST : ici l'application TOURNE. ZAP ne lit pas le
code, il envoie de vraies requetes d'attaque et observe les reponses. Il trouve
donc des failles invisibles a l'analyse statique (et inversement).

Usage : python scripts/gate_zap.py reports/zap.json
"""

import sys

from gate_common import lire_rapport, titre, verdict

# Niveau de risque qui arrete le pipeline
RISQUE_BLOQUANT = 3  # High

NOM_DU_RISQUE = {3: "High", 2: "Medium", 1: "Low", 0: "Informational"}

# ---------------------------------------------------------------------------
# EXCEPTIONS DOCUMENTEES
#
# Format :  "pluginid" : "justification — qui, quand"
# Pour ignorer durablement une alerte, preferer le fichier .zap/rules.tsv
# (lu par ZAP lui-meme). Ce dictionnaire sert aux cas ponctuels ou l'on veut
# garder l'alerte VISIBLE dans le rapport sans bloquer la fusion.
# ---------------------------------------------------------------------------
EXCEPTIONS = {}


def extraire_alertes(rapport):
    """Aplatit les alertes de tous les sites scannes."""
    alertes = []
    for site in rapport.get("site", []) or []:
        for alerte in site.get("alerts", []) or []:
            alertes.append((site.get("@name", "?"), alerte))
    return alertes


def code_de_risque(alerte):
    """riskcode est une chaine dans le JSON de ZAP ("3", "2"...)."""
    try:
        return int(alerte.get("riskcode", 0))
    except (TypeError, ValueError):
        return 0


def main(chemin_rapport):
    titre("PORTE DAST — OWASP ZAP (scan actif de l'application lancee)")
    rapport = lire_rapport(chemin_rapport)
    alertes = extraire_alertes(rapport)

    comptes = {3: 0, 2: 0, 1: 0, 0: 0}
    bloquants = []
    ignores = []

    for site, alerte in alertes:
        risque = code_de_risque(alerte)
        comptes[risque] = comptes.get(risque, 0) + 1
        if risque < RISQUE_BLOQUANT:
            continue
        if alerte.get("pluginid") in EXCEPTIONS:
            ignores.append((site, alerte))
        else:
            bloquants.append((site, alerte))

    print(f"Version de ZAP : {rapport.get('@version', '?')}")
    print(f"Cible scannee  : {', '.join(s.get('@name', '?') for s in rapport.get('site', []))}")
    print(
        "Alertes : "
        f"{comptes.get(3, 0)} High, "
        f"{comptes.get(2, 0)} Medium, "
        f"{comptes.get(1, 0)} Low, "
        f"{comptes.get(0, 0)} Info"
    )
    print()

    for site, alerte in bloquants:
        print(f"[BLOQUANT] {alerte.get('name')} (risque High)")
        print(f"  Site      : {site}")
        print(f"  CWE       : CWE-{alerte.get('cweid', '?')}")
        print(f"  Confiance : {alerte.get('confidence', '?')}")
        # Les "instances" montrent l'URL exacte et la charge utile qui a marche :
        # c'est la preuve de l'exploitation, tres utile pour corriger.
        for instance in (alerte.get("instances") or [])[:3]:
            print(f"  -> {instance.get('method', '?')} {instance.get('uri', '?')}")
            if instance.get("param"):
                print(f"     parametre vulnerable : {instance['param']}")
            if instance.get("attack"):
                print(f"     charge utile         : {instance['attack'][:120]}")
            if instance.get("evidence"):
                print(f"     preuve dans la reponse : {instance['evidence'][:120]}")
        solution = (alerte.get("solution") or "").strip().replace("\n", " ")
        if solution:
            print(f"  Correction : {solution[:200]}")
        print()

    for site, alerte in ignores:
        print(
            f"[EXCEPTION ACCEPTEE] {alerte.get('name')} "
            f"({alerte.get('pluginid')}) — {EXCEPTIONS[alerte['pluginid']]}"
        )

    for site, alerte in alertes:
        if code_de_risque(alerte) == 2:
            print(f"[AVERTISSEMENT] {alerte.get('name')} (Medium) — {site}")

    # Resume affiche sur la page du run GitHub Actions
    lignes = [
        "## Porte DAST — OWASP ZAP (scan actif)",
        "",
        "| Risque | Alertes | Bloquant |",
        "|---|---|---|",
        f"| High | {comptes.get(3, 0)} | oui |",
        f"| Medium | {comptes.get(2, 0)} | non |",
        f"| Low | {comptes.get(1, 0)} | non |",
        f"| Informational | {comptes.get(0, 0)} | non |",
        "",
    ]
    if bloquants:
        lignes.append("**Failles exploitees par ZAP sur l'application lancee :**")
        lignes.append("")
        for _, alerte in bloquants:
            instances = alerte.get("instances") or [{}]
            lignes.append(
                f"- **{alerte.get('name')}** (CWE-{alerte.get('cweid', '?')}) "
                f"— `{instances[0].get('uri', '?')}` "
                f"parametre `{instances[0].get('param', '—')}`"
            )
        lignes.append("")
    else:
        lignes.append("Aucune alerte de risque High. Porte verte.")
        lignes.append("")

    return verdict("DAST", len(bloquants), lignes)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
