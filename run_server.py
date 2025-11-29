# -*- coding: utf-8 -*-
"""
Serveur Flask sécurisé avec Authentification Basic, SQLite et Bcrypt
"""

from functools import wraps
from flask import Flask, request, Response
import os
import sqlite3
import bcrypt

# --- CONFIGURATION ---
SECRET_MESSAGE = "parasaurolophus"
SSL_CONTEXT = "ssl/"
SSL_DOMAIN = "localhost+1"
DB_NAME = "users.db"

app = Flask(__name__)

# --- SÉCURITÉ (BCRYPT) ---

def hash_password(password):
    """
    Hache le mot de passe avec un sel (salt) aléatoire via Bcrypt.
    Retourne une chaîne de caractères (string) prête à être stockée.
    """
    # bcrypt travaille avec des bytes, on encode donc le password
    pwd_bytes = password.encode('utf-8')
    # On génère le sel et on hache
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    # On retourne le hash en format string pour la base de données
    return hashed.decode('utf-8')

def verify_password(plain_password, stored_hash):
    """
    Vérifie si le mot de passe en clair correspond au hash stocké.
    """
    # On a besoin de bytes pour bcrypt
    pwd_bytes = plain_password.encode('utf-8')
    hash_bytes = stored_hash.encode('utf-8')
    
    # checkpw compare le mot de passe et le hash (qui contient le sel)
    try:
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except ValueError:
        # Cette erreur survient si la base de données contient d'anciens formats de hash
        print(f"\n[ERREUR SECURITE] Le mot de passe stocké n'est pas un hash Bcrypt valide.")
        print(f"Action requise : Veuillez SUPPRIMER le fichier '{DB_NAME}' et relancer le serveur.\n")
        return False

# --- BASE DE DONNÉES ---

def init_db():
    """Initialise la base de données avec des utilisateurs par défaut."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Si la table est vide, on ajoute l'admin par défaut
    cursor.execute('SELECT count(*) FROM users')
    if cursor.fetchone()[0] == 0:
        print("--- Initialisation de la Base de Données (Bcrypt) ---")
        
        # Création du hash pour 'adminpass'
        pwd_hash = hash_password("adminpass")
        
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ("admin", pwd_hash))
        conn.commit()
        print(f"Utilisateur 'admin' créé (Hash: {pwd_hash[:15]}...)")
    
    conn.close()

# --- AUTHENTIFICATION HTTP ---

def check_auth(username, password):
    """Récupère le hash en DB et le vérifie avec bcrypt."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        stored_hash = row[0]
        # Utilisation de la fonction de vérification bcrypt
        return verify_password(password, stored_hash)
    
    return False

def authenticate():
    return Response(
        'Connexion requise.\n'
        'Veuillez entrer un identifiant et un mot de passe valides.', 401,
        {'WWW-Authenticate': 'Basic realm="Accès Sécurisé Bcrypt"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route("/")
@requires_auth
def get_secret_message():
    user = request.authorization.username
    return f"Bonjour {user} ! Authentification forte (Bcrypt) réussie. Secret : {SECRET_MESSAGE}"


if __name__ == "__main__":
    print("--- Démarrage du Serveur Sécurisé ---")
    
    # Initialisation de la DB
    init_db()
    
    # Configuration SSL
    cert_file = os.path.join(SSL_CONTEXT, f"{SSL_DOMAIN}.pem")
    key_file = os.path.join(SSL_CONTEXT, f"{SSL_DOMAIN}-key.pem")

    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"SSL OK. Accès via https://localhost:8081")
        app.run(debug=True, host="0.0.0.0", port=8081, ssl_context=(cert_file, key_file))
    else:
        print(f"[ERREUR] Certificats non trouvés dans {SSL_CONTEXT}")