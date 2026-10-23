"""
Tests unitaires de VulnBank — TP2.

Ces tests sont des tests de NON-REGRESSION DE SECURITE : chacun rejoue une des
failles corrigees au TP1 et verifie que l'application la refuse toujours.

Interet dans un pipeline CI/CD : si un developpeur reintroduit une faille (par
copier-coller, par un "revert" malheureux ou par ignorance), le job "build-test"
echoue avant meme les scanners. C'est la premiere porte du garde-fou, et la plus
rapide : quelques secondes, sans Docker ni scanner.
"""

import pytest
import requests

from vulnbank import app as app_module
from vulnbank import db as db_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Application Flask branchee sur une base SQLite jetable.

    get_connection() relit db.DB_PATH a chaque appel : il suffit donc de
    rediriger cette variable vers le dossier temporaire du test pour ne jamais
    toucher la base du poste de travail.
    """
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "test_bank.db"))
    db_module.init_db()
    app_module.app.config.update(TESTING=True, SECRET_KEY="cle-de-test")
    with app_module.app.test_client() as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# 1. Fonctionnement nominal (le pipeline doit aussi verifier que ca MARCHE)
# ---------------------------------------------------------------------------

def test_page_accueil_repond(client):
    reponse = client.get("/")
    assert reponse.status_code == 200
    assert b"VulnBank" in reponse.data


def test_connexion_valide(client):
    """alice/password est un compte de test seme par init_db()."""
    reponse = client.post(
        "/login", data={"username": "alice", "password": "password"}
    )
    assert reponse.status_code == 302  # redirection vers l'accueil = succes


def test_connexion_mauvais_mot_de_passe_refusee(client):
    reponse = client.post(
        "/login", data={"username": "alice", "password": "mauvais"}
    )
    assert reponse.status_code == 401


# ---------------------------------------------------------------------------
# 2. Non-regression : injection SQL  (TP1, Bandit B608)
# ---------------------------------------------------------------------------

def test_injection_sql_dans_login_refusee(client):
    """admin' --  ouvrait la session sans mot de passe sur la version vulnerable.

    L'apostrophe fermait la chaine et "--" mettait la verification du mot de
    passe en commentaire. Avec une requete parametree, cette saisie n'est qu'un
    nom d'utilisateur inexistant -> 401.
    """
    reponse = client.post(
        "/login", data={"username": "admin' --", "password": "nimporte-quoi"}
    )
    assert reponse.status_code == 401


def test_injection_sql_dans_comptes_ne_fuit_aucune_donnee(client):
    """' OR '1'='1  affichait tous les comptes de tous les clients.

    Le motif est desormais passe comme parametre lie : aucun IBAN ne doit
    apparaitre dans la reponse.
    """
    reponse = client.get("/accounts", query_string={"owner": "' OR '1'='1"})
    assert reponse.status_code == 200
    assert b"TN59" not in reponse.data  # prefixe des IBAN de test


def test_recherche_de_compte_legitime_fonctionne(client):
    """Contre-epreuve : la recherche normale doit continuer a renvoyer les donnees."""
    reponse = client.get("/accounts", query_string={"owner": "alice"})
    assert reponse.status_code == 200
    assert b"TN59" in reponse.data


# ---------------------------------------------------------------------------
# 2 bis. Non-regression : la route /search  (failles trouvees par OWASP ZAP)
#
# Ces deux tests verrouillent les failles que le scan DAST avait exploitees
# sur la premiere version de /search (injection SQL, XSS reflechi et injection
# de template). Ils tournent en 3 secondes, la ou le scan ZAP prend 3 minutes :
# la porte DAST trouve la faille, le test unitaire l'empeche de revenir.
# ---------------------------------------------------------------------------

def test_injection_sql_dans_recherche_ne_fuit_aucune_donnee(client):
    """ZAP obtenait tous les comptes avec la charge utile   %' OR '1'='1' --"""
    reponse = client.get("/search", query_string={"q": "%' OR '1'='1' -- "})
    assert reponse.status_code == 200
    assert b"TN59" not in reponse.data


def test_xss_et_template_dans_recherche_sont_echappes(client):
    """ZAP executait <script> et evaluait {{ 2756*1993 }} dans la page.

    Avec un vrai template, les deux doivent ressortir en texte echappe.
    """
    reponse = client.get(
        "/search", query_string={"q": "<script>alert(1)</script>{{7*7}}"}
    )
    assert reponse.status_code == 200
    assert b"<script>" not in reponse.data  # balise inactive
    assert b"&lt;script&gt;" in reponse.data  # affichee comme du texte
    assert b"49" not in reponse.data  # le template n'a pas ete evalue


def test_recherche_legitime_fonctionne(client):
    """Contre-epreuve : la fonctionnalite est conservee, pas supprimee."""
    reponse = client.get("/search", query_string={"q": "alice"})
    assert reponse.status_code == 200
    assert b"TN59" in reponse.data


# ---------------------------------------------------------------------------
# 3. Non-regression : XSS  (TP1, trouvee en revue de code, par aucun scanner)
# ---------------------------------------------------------------------------

def test_xss_dans_commentaire_est_echappee(client):
    """Le message doit s'AFFICHER comme du texte, pas s'executer.

    Jinja2 echappe automatiquement les variables de template : < devient &lt;.
    """
    charge = '<img src=x onerror="alert(1)">'
    reponse = client.post("/comment", data={"message": charge})
    assert reponse.status_code == 200
    assert b"<img" not in reponse.data  # la balise ne doit pas etre active
    assert b"&lt;img" in reponse.data  # elle est affichee, echappee


# ---------------------------------------------------------------------------
# 4. Non-regression : injection de commande  (TP1, Bandit B605)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "nom_de_compte",
    [
        "x; rm -rf /",  # enchainement de commandes
        "a && whoami",  # idem
        "../../etc/passwd",  # traversee de repertoire
        "$(id)",  # substitution de commande
    ],
)
def test_injection_commande_dans_export_refusee(client, nom_de_compte):
    """L'export valide le nom par liste blanche (regex ACCOUNT_NAME) -> 400."""
    reponse = client.get("/export", query_string={"account": nom_de_compte})
    assert reponse.status_code == 400


def test_export_de_compte_valide_accepte(client):
    """Contre-epreuve : un nom conforme a la liste blanche doit passer."""
    reponse = client.get("/export", query_string={"account": "alice"})
    assert reponse.status_code == 200


# ---------------------------------------------------------------------------
# 5. Non-regression : chargement YAML non securise  (TP1, Bandit B506)
# ---------------------------------------------------------------------------

def test_configuration_chargee_en_mode_sur():
    """safe_load() ne construit que des types de base : le resultat est un dict."""
    configuration = app_module.load_config()
    assert isinstance(configuration, dict)
    assert configuration["app_name"] == "VulnBank"


# ---------------------------------------------------------------------------
# 6. Robustesse de /rates (ajout TP2 : stabilite du scan DAST)
# ---------------------------------------------------------------------------

def test_taux_repond_meme_si_api_externe_injoignable(client, monkeypatch):
    """Si l'API externe tombe, la route repond quand meme (pas de 500).

    Sans ce repli, le scan DAST du pipeline echouerait de maniere aleatoire
    selon la disponibilite reseau du runner GitHub.
    """

    def lever_erreur_reseau(*args, **kwargs):
        raise requests.exceptions.ConnectionError("API externe indisponible")

    monkeypatch.setattr(requests, "get", lever_erreur_reseau)
    reponse = client.get("/rates")
    assert reponse.status_code == 200
    assert reponse.get_json()["source"] == "indisponible"
