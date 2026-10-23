#!/usr/bin/env python3
"""
Rendu PDF d'un document Markdown (rapport, fiche de presentation).

Chaine de rendu :  Markdown  ->  HTML + CSS d'impression  ->  PDF (Chrome)

Pourquoi Chrome et pas pandoc/weasyprint ? Aucun des deux n'est installe sur le
poste, alors que Chrome l'est : son moteur d'impression gere nativement le CSS
`@page`, les tableaux et les images du depot.

Usage :
    python scripts/build_pdf.py RAPPORT.md RAPPORT.pdf
    python scripts/build_pdf.py FICHE-presentation.md FICHE-presentation.pdf

Dependance : le paquet `markdown` (pip install markdown).
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile

import markdown

CHROME_CANDIDATS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "google-chrome",
    "chromium",
]

# Feuille de style d'impression. `.pagebreak` force un saut de page (utilise
# apres la page de garde, comme dans le rapport du TP1).
CSS = """
@page { size: A4; margin: 18mm 16mm; }
body {
  font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
  font-size: 10.5pt; line-height: 1.5; color: #1b1b1b; margin: 0;
}
h1 { font-size: 20pt; margin: 0 0 .4em; }
h2 { font-size: 14pt; margin: 1.6em 0 .5em; padding-bottom: .2em;
     border-bottom: 2px solid #d8d8d8; page-break-after: avoid; }
h3 { font-size: 11.5pt; margin: 1.2em 0 .4em; page-break-after: avoid; }
h4 { font-size: 10.5pt; margin: 1em 0 .3em; }
p, li { orphans: 3; widows: 3; }
a { color: #0b57d0; text-decoration: none; word-break: break-all; }
code {
  font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 9pt;
  background: #f3f4f6; padding: .1em .3em; border-radius: 3px;
}
pre {
  background: #f7f8fa; border: 1px solid #e3e5e8; border-left: 3px solid #6b7280;
  border-radius: 4px; padding: .7em .9em; overflow-x: auto;
  page-break-inside: avoid;
}
pre code { background: none; padding: 0; font-size: 8.6pt; line-height: 1.42; }
table {
  border-collapse: collapse; width: 100%; margin: .9em 0; font-size: 9.2pt;
  page-break-inside: avoid;
}
th, td { border: 1px solid #d5d7da; padding: .38em .55em; text-align: left;
         vertical-align: top; }
th { background: #f1f2f4; font-weight: 600; }
blockquote {
  margin: 1em 0; padding: .5em .9em; background: #fff8e1;
  border-left: 4px solid #f0b429; color: #4a3a0b;
}
img { max-width: 100%; }
hr { border: none; border-top: 1px solid #dcdcdc; margin: 1.6em 0; }
.pagebreak { page-break-after: always; }
"""

MODELE_HTML = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>{titre}</title>
<style>{css}</style>
</head>
<body>
{corps}
</body>
</html>
"""


def trouver_chrome():
    for candidat in CHROME_CANDIDATS:
        if pathlib.Path(candidat).is_file():
            return candidat
        trouve = shutil.which(candidat)
        if trouve:
            return trouve
    sys.exit(
        "ERREUR : aucun navigateur Chrome/Chromium trouve pour le rendu PDF.\n"
        "Installez Google Chrome, ou convertissez le Markdown avec un autre outil."
    )


def convertir(chemin_md, chemin_pdf):
    source = pathlib.Path(chemin_md)
    if not source.is_file():
        sys.exit(f"ERREUR : fichier introuvable : {chemin_md}")

    corps = markdown.markdown(
        source.read_text(encoding="utf-8"),
        extensions=["tables", "fenced_code", "attr_list", "md_in_html", "sane_lists"],
    )
    html = MODELE_HTML.format(titre=source.stem, css=CSS, corps=corps)

    # Le HTML temporaire est ecrit A COTE du Markdown pour que les chemins
    # relatifs des images (docs/assets/..., docs/screenshots/...) restent valides.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".html", delete=False,
        dir=str(source.parent),
    ) as fichier_html:
        fichier_html.write(html)
        chemin_html = pathlib.Path(fichier_html.name)

    try:
        chrome = trouver_chrome()
        sortie = pathlib.Path(chemin_pdf).resolve()
        commande = [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--no-pdf-header-footer",
            # laisse le temps aux images de se charger avant l'impression
            "--virtual-time-budget=4000",
            f"--print-to-pdf={sortie}",
            chemin_html.resolve().as_uri(),
        ]
        resultat = subprocess.run(commande, capture_output=True, text=True)
        if not sortie.is_file():
            sys.exit(
                "ERREUR : Chrome n'a pas produit de PDF.\n"
                f"{resultat.stderr[-800:]}"
            )
        taille = sortie.stat().st_size // 1024
        print(f"PDF genere : {sortie} ({taille} Ko)")
    finally:
        chemin_html.unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    convertir(sys.argv[1], sys.argv[2])
