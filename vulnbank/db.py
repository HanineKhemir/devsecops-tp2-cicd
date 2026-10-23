import os
import sqlite3

from vulnbank.security import hash_password

DB_PATH = os.path.join(os.path.dirname(__file__), "bank.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS accounts;

        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'client'
        );

        CREATE TABLE accounts (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            owner   TEXT NOT NULL,
            iban    TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0
        );
        """
    )
    # FAILLE : Mots de passe hachés en MD5   |   DETECTE PAR : Bandit (B324)
    # AVANT (vulnerable) : les mots de passe etaient stockes en MD5 ecrits en dur
    #   ("alice", "5f4dcc3b5aa765d61d8327deb882cf99", ...) = md5("password").
    # POURQUOI FAUX : empreintes MD5 non salees, cassables instantanement via des
    #   bases de hash publiques (rainbow tables).
    # CORRECTION : on hache les mots de passe au demarrage avec hash_password()
    #   (pbkdf2 + sel). Voir vulnbank/security.py.
    seed = [
        ("alice", hash_password("password"), "client"),
        ("bob", hash_password("123456"), "client"),
        ("admin", hash_password("admin"), "admin"),
    ]
    conn.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)", seed
    )
    conn.executemany(
        "INSERT INTO accounts (owner, iban, balance) VALUES (?, ?, ?)",
        [
            ("alice", "TN59 1000 6035 1234 5678 9012", 4210.55),
            ("bob", "TN59 1000 6035 9876 5432 1098", 980.00),
            ("admin", "TN59 1000 6035 0000 0000 0001", 150000.00),
        ],
    )
    conn.commit()
    conn.close()
