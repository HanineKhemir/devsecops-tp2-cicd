"""
Fonctions communes aux trois "portes" de securite du pipeline (TP2).

Une PORTE (quality gate) = un script qui lit le rapport JSON d'un scanner et
decide si le pipeline continue ou s'arrete :

    code de sortie 0  -> la porte est verte, le job reussit
    code de sortie 1  -> la porte est rouge, le job echoue et la PR est bloquee

Pourquoi un script maison plutot que le code de sortie du scanner ?
  1. les scanners echouent sur TOUTE anomalie, meme informative : le pipeline
     serait rouge en permanence et l'equipe finirait par l'ignorer ;
  2. nous voulons une regle explicite et ecrite ("seules les severites
     HIGH/CRITICAL bloquent"), identique en local et dans la CI ;
  3. nous voulons un resume lisible dans l'interface GitHub Actions.

Dependances : bibliotheque standard uniquement (aucun pip install).
"""

import json
import os
import pathlib
import sys

# Largeur du cadre des messages console
LARGEUR = 78


def titre(texte):
    """Affiche un titre encadre dans les logs du job."""
    print("=" * LARGEUR)
    print(texte.center(LARGEUR))
    print("=" * LARGEUR)


def lire_rapport(chemin):
    """Charge un rapport JSON de scanner.

    Un rapport absent ou illisible fait ECHOUER la porte : un scanner qui n'a
    pas tourne ne doit jamais etre confondu avec un scanner qui n'a rien trouve
    (sinon il suffirait de casser le scanner pour passer la porte).
    """
    fichier = pathlib.Path(chemin)
    if not fichier.is_file():
        print(f"ERREUR : rapport introuvable : {chemin}")
        print("Le scanner n'a pas produit de rapport -> porte consideree ROUGE.")
        sys.exit(1)
    try:
        return json.loads(fichier.read_text(encoding="utf-8"))
    except json.JSONDecodeError as erreur:
        print(f"ERREUR : rapport illisible ({chemin}) : {erreur}")
        sys.exit(1)


def resume_github(lignes_markdown):
    """Publie un resume Markdown sur la page du run GitHub Actions.

    GitHub expose le fichier via la variable d'environnement GITHUB_STEP_SUMMARY.
    En local, cette variable n'existe pas : on ne fait rien.
    """
    chemin = os.environ.get("GITHUB_STEP_SUMMARY")
    if not chemin:
        return
    with open(chemin, "a", encoding="utf-8") as fichier:
        fichier.write("\n".join(lignes_markdown) + "\n")


def verdict(nom_porte, bloquants, lignes_markdown):
    """Affiche le verdict de la porte et renvoie le code de sortie attendu."""
    resume_github(lignes_markdown)
    print("-" * LARGEUR)
    if bloquants:
        print(f"PORTE {nom_porte} : ROUGE — {bloquants} probleme(s) bloquant(s).")
        print("Le pipeline s'arrete : cette modification ne peut pas etre fusionnee.")
        return 1
    print(f"PORTE {nom_porte} : VERTE — aucun probleme bloquant.")
    return 0
