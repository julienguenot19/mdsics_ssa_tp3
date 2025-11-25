# -*- coding: utf-8 -*-
"""
Serveur Flask sécurisé avec Authentification Basic et Base de Données SQLite
"""

from functools import wraps
from flask import Flask, request, Response
import os
import sqlite3
import hashlib

# --- CONFIGURATION ---
SECRET_MESSAGE = "diplodocus"

# Configuration SSL (dossier et nom de fichier)
SSL_CONTEXT = "ssl/"
SSL_DOMAIN = "localhost+1"

# Nom de la base de données locale
DB_NAME = "users.db"

app = Flask(__name__)

# --- GESTION DE LA BASE DE DONNÉES (SQLite) ---

def hash_password(password):
    """Hache le mot de passe (SHA-256) pour ne pas le stocker en clair."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def init_db():
    """Crée la table et ajoute un utilisateur admin si la base est vide."""
    # Connexion (crée le fichier s'il n'existe pas)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Création de la table 'users'
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')
    
    cursor.execute('SELECT count(*) FROM users')
    if cursor.fetchone()[0] == 0:
        print("--- Initialisation de la Base de Données ---")
        # Ajout de l'utilisateur par défaut : admin / adminpass
        pwd_hash = hash_password("adminpass")
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ("admin", pwd_hash))
        conn.commit()
        print("Utilisateur 'admin' créé avec le mot de passe 'adminpass'.")
    
    conn.close()

# --- SÉCURITÉ & AUTHENTIFICATION ---

def check_auth(username, password):
    """Vérifie le login/mot de passe dans la base de données."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Récupération du hash stocké pour cet utilisateur
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        stored_hash = row[0]
        # On compare le hash du mot de passe saisi avec celui stocké
        return stored_hash == hash_password(password)
    
    return False

def authenticate():
    """Envoie une réponse 401 pour déclencher la fenêtre de connexion du navigateur."""
    return Response(
        'Connexion requise.\n'
        'Veuillez entrer un identifiant et un mot de passe valides.', 401,
        {'WWW-Authenticate': 'Basic realm="Accès Sécurisé"'})

def requires_auth(f):
    """Décorateur pour protéger les routes Flask."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# --- ROUTES ---

@app.route("/")
@requires_auth  # <-- Protection activée ici
def get_secret_message():
    user = request.authorization.username
    return f"Bonjour {user} ! Le mot de passe est : {SECRET_MESSAGE}"


if __name__ == "__main__":
    print("--- Démarrage du Serveur ---")
    
    # 1. Initialiser la DB (crée le fichier users.db si absent)
    #init_db()
    
    # 2. Vérification des certificats SSL
    cert_file = SSL_CONTEXT + SSL_DOMAIN + ".pem"
    key_file = SSL_CONTEXT + SSL_DOMAIN + "-key.pem"

    # HTTP version (commentée par défaut)
    # app.run(debug=True, host="0.0.0.0", port=8081)

    # HTTPS version
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"Certificats trouvés. Accès via https://localhost:8081")
        app.run(
            debug=True, 
            host="0.0.0.0", 
            port=8081, 
            ssl_context=(cert_file, key_file)
        )
    else:
        print(f"[ERREUR] Fichiers SSL introuvables : {cert_file}")
        print("Veuillez générer les certificats ou vérifier le chemin.")