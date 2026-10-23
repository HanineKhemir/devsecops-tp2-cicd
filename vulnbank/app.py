import os
import re
import tempfile

import requests
import yaml
from flask import Flask, redirect, render_template, request, session, url_for

from vulnbank.db import get_connection, init_db
from vulnbank.security import hash_password, verify_password

app = Flask(__name__)
# FAILLE : Secret ecrit en dur   |   DETECTE PAR : Bandit (regle B105)
# AVANT (vulnerable) :  app.config["SECRET_KEY"] = "s3cr3t-dev-key-..."
# POURQUOI FAUX : un secret ecrit en dur est visible par tous dans le code
#   source (et sur GitHub). Il sert a signer les cookies de session : s'il
#   fuit, un attaquant peut forger des sessions et usurper un utilisateur.
# CORRECTION : on le lit depuis une variable d'environnement.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(24).hex()

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")
RATES_URL = "https://api.exchangerate.host/latest?base=TND"
ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def load_config():
    with open(CONFIG_PATH) as handle:
        # FAILLE : Chargement YAML non securise   |   DETECTE PAR : Bandit (regle B506)
# AVANT (vulnerable) :  return yaml.load(handle.read())
        # POURQUOI FAUX : yaml.load() peut instancier des objets Python
        #   arbitraires. Un fichier YAML piege peut donc executer du code
        #   (RCE) au moment du chargement.
        # CORRECTION : safe_load() ne cree que des types de base (dict, list...).
        return yaml.safe_load(handle.read())


@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html", user=session.get("username"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_connection()
    # FAILLE : Injection SQL   |   DETECTE PAR : Bandit (regle B608)
    # AVANT (vulnerable) :
    #   query = f"SELECT ... WHERE username = '{username}' AND password = '{password}'"
    #   row = conn.execute(query).fetchone()
    # POURQUOI FAUX : la saisie est collee directement dans la requete SQL.
    #   En tapant   admin' --   l'apostrophe ferme la chaine et "--" met la
    #   verification du mot de passe en commentaire -> connexion sans mot de passe.
    # CORRECTION : requete PARAMETREE. Le "?" est une valeur liee : la saisie
    #   est traitee comme une donnee, jamais comme du code SQL.
    row = conn.execute(
        "SELECT id, username, role, password FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if row is None or not verify_password(row["password"], password):
        return render_template("index.html", error="Identifiants invalides"), 401

    session["username"] = row["username"]
    session["role"] = row["role"]
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/accounts")
def accounts():
    owner = request.args.get("owner", "")
    conn = get_connection()
    # FAILLE : Injection SQL   |   DETECTE PAR : Bandit (regle B608)
    # AVANT (vulnerable) :
    #   "SELECT ... WHERE owner LIKE '%" + owner + "%'"
    # POURQUOI FAUX : encore une concatenation. En tapant   ' OR '1'='1
    #   la condition devient toujours vraie -> tous les comptes de tous les
    #   clients sont affiches (fuite de donnees).
    # CORRECTION : le motif de recherche est passe comme parametre lie ("?").
    rows = conn.execute(
        "SELECT owner, iban, balance FROM accounts WHERE owner LIKE ?",
        (f"%{owner}%",),
    ).fetchall()
    conn.close()
    return render_template("index.html", accounts=rows, user=session.get("username"))


@app.route("/search")
def search():
    """Recherche rapide de comptes (version securisee)."""
    terme = request.args.get("q", "")

    # FAILLE CORRIGEE : Injection SQL   |   DETECTEE PAR : OWASP ZAP (scan
    #   actif, alerte High "SQL Injection") et Bandit (regle B608, severite
    #   moyenne : il voit la concatenation mais ne peut pas l'exploiter).
    # AVANT (vulnerable) :
    #   requete = "... WHERE owner LIKE '%" + terme + "%'"
    #   lignes = conn.execute(requete).fetchall()
    # POURQUOI FAUX : la saisie etait collee dans la requete SQL. ZAP a envoye
    #   la charge utile   %' OR '1'='1' --   et a obtenu TOUS les comptes.
    # CORRECTION : requete PARAMETREE. Le "?" est une valeur liee : la saisie
    #   est une donnee, jamais du code SQL.
    conn = get_connection()
    lignes = conn.execute(
        "SELECT owner, iban, balance FROM accounts WHERE owner LIKE ?",
        (f"%{terme}%",),
    ).fetchall()
    conn.close()

    # FAILLE CORRIGEE : XSS reflechi   |   DETECTEE PAR : OWASP ZAP (scan
    #   actif, alerte High "Cross Site Scripting (Reflected)").
    # AVANT (vulnerable) :
    #   page = "<h2>Resultats pour " + terme + "</h2>..."
    #   return render_template_string(page)
    # POURQUOI FAUX : render_template_string() compile la chaine comme un
    #   template. La saisie devenait donc du code HTML (et meme du Jinja2) :
    #   ZAP a injecte <script>alert(1)</script> et l'a vu s'executer.
    # CORRECTION : un vrai template. Jinja2 echappe automatiquement les
    #   variables : les balises s'affichent comme du texte.
    return render_template("search.html", terme=terme, resultats=lignes)


@app.route("/comment", methods=["POST"])
def comment():
    message = request.form.get("message", "")
    # FAILLE : XSS (Cross-Site Scripting)   |   DETECTE PAR : aucun scanner
    #   automatique -> identifiee a la main (revue de code). Montre les limites
    #   des scanners : SonarQube Community (pas d'analyse de flux) et Bandit ne
    #   signalent pas render_template_string.
    # AVANT (vulnerable) :
    #   page = f"<div>{message}</div>"
    #   return render_template_string(page)
    # POURQUOI FAUX : le message de l'utilisateur est injecte brut dans la page.
    #   En tapant   <img src=x onerror="alert(1)">   le JavaScript s'execute
    #   dans le navigateur de la victime (faille XSS).
    # CORRECTION : on passe par un template. Jinja2 echappe automatiquement le
    #   contenu : les balises s'affichent comme du texte, elles ne s'executent pas.
    return render_template("comment.html", message=message)


@app.route("/export")
def export():
    account = request.args.get("account", "all")
    # FAILLE : Injection de commande   |   DETECTE PAR : Bandit (regle B605)
    # AVANT (vulnerable) :
    #   os.system(f"sqlite3 {DB_PATH} '.dump' > /tmp/export_{account}.sql")
    # POURQUOI FAUX : la saisie passe dans une commande shell. En tapant
    #   account=x; rm -rf /   l'attaquant execute ses propres commandes sur le
    #   serveur (injection de commande).
    # CORRECTION : (1) on valide le nom avec une liste blanche (regex), (2) on
    #   n'utilise plus le shell : l'export se fait via l'API SQLite (iterdump()).
    if not ACCOUNT_NAME.match(account):
        return "Nom de compte invalide", 400
    export_path = os.path.join(
        tempfile.gettempdir(), f"vulnbank_export_{account}.sql"
    )
    conn = get_connection()
    with open(export_path, "w") as handle:
        for line in conn.iterdump():
            handle.write(line + "\n")
    conn.close()
    return f"Export de {account} termine", 200


@app.route("/rates")
def rates():
    # FAILLE : Certificat TLS non verifie   |   DETECTE PAR : Bandit (B501) +
    #   SonarQube (vulnerabilite python:S4830)
    # AVANT (vulnerable) :  requests.get(RATES_URL, verify=False, ...)
    # POURQUOI FAUX : verify=False desactive la verification du certificat TLS.
    #   On ne sait plus si on parle au vrai serveur -> attaque "man-in-the-middle"
    #   possible (interception/modification des echanges).
    # CORRECTION : on garde la verification du certificat (verify=True par defaut).
    # NOTE (TP2) : l'appel reseau est encapsule dans un try/except. Pendant le
    #   scan DAST du pipeline, l'API externe peut etre injoignable ou lente : sans
    #   ce repli, la route renverrait une erreur 500 et rendrait le pipeline
    #   instable (echecs aleatoires). La verification TLS reste active.
    try:
        response = requests.get(RATES_URL, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return {"base": "TND", "rates": {}, "source": "indisponible"}, 200


if __name__ == "__main__":
    init_db()
    # FAILLE : Mode debug actif (B201) + ecoute sur toutes les interfaces (B104)
    #   DETECTE PAR : Bandit (regles B201 et B104)
    # AVANT (vulnerable) :  app.run(host="0.0.0.0", port=5000, debug=True)
    # POURQUOI FAUX : debug=True expose la console interactive Werkzeug en cas
    #   d'erreur -> un attaquant peut y executer du code Python. "0.0.0.0" en dur
    #   expose aussi l'app sur toutes les interfaces reseau.
    # CORRECTION : debug et host viennent de variables d'environnement, avec des
    #   valeurs sures par defaut (debug off, ecoute locale 127.0.0.1).
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=5000, debug=debug)
