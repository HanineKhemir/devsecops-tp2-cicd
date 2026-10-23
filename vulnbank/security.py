from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password):
    # FAILLE : Hachage faible (MD5)   |   DETECTE PAR : Bandit (B324) +
    #   SonarQube (hotspot "hachage a verifier")
    # AVANT (vulnerable) :  return hashlib.md5(password.encode()).hexdigest()
    # POURQUOI FAUX : MD5 est un algorithme casse et tres rapide a calculer.
    #   Sans sel, deux utilisateurs avec le meme mot de passe ont la meme
    #   empreinte, et une attaque par dictionnaire casse les hash en secondes.
    # CORRECTION : generate_password_hash() utilise pbkdf2:sha256, lent et avec
    #   un sel unique par utilisateur -> resistant aux attaques par force brute.
    return generate_password_hash(password)


def verify_password(stored_hash, candidate):
    return check_password_hash(stored_hash, candidate)
