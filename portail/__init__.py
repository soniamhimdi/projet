import flask
from . import config
from pathlib import Path
from werkzeug.security import generate_password_hash
import sqlite3
import logging, sys
import os
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect  # CORRECTION : protection CSRF

# Chargement des variables d'environnement depuis le fichier .env
load_dotenv()

app = flask.Flask(__name__)

# CORRECTION (CWE-798) : clé secrète codée en dur supprimée
# app.secret_key = 'CHANGE_ME_SECRET_KEY'
# Nouvelle clé chargée depuis la variable d'environnement SECRET_KEY (définie dans .env)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-fallback-changer-en-production')

app.static_folder = 'static'

# CORRECTION (CWE-352) : activation de la protection CSRF sur tous les formulaires POST
csrf = CSRFProtect(app)

app.logger.setLevel(logging.INFO)
app.logger.propagate = True

fh = logging.FileHandler('audit.log')
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
app.logger.addHandler(fh)

# CORRECTION (CWE-693, CWE-1021) : en-têtes de sécurité HTTP ajoutés à chaque réponse
# Corrige les alertes ZAP : CSP absent, clickjacking, MIME sniffing, version serveur exposée
@app.after_request
def add_security_headers(response):
    # Interdit le chargement de ressources externes non autorisées (protection XSS)
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    # Interdit l'intégration dans une iframe (protection clickjacking)
    response.headers['X-Frame-Options'] = 'DENY'
    # Empêche le MIME sniffing par le navigateur
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Masque la version du serveur (Werkzeug/Python exposés par défaut)
    response.headers['Server'] = 'Apache'
    return response

def init_db():
    if not Path(config.Config.DATABASE_PATH).exists():
        with sqlite3.connect(config.Config.DATABASE_PATH) as conn:

            conn.executescript(
                "CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT NOT NULL);"
                "CREATE TABLE rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, capacity INTEGER NOT NULL);"
                "CREATE TABLE reservations (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, room_id INTEGER, datetime TEXT, FOREIGN KEY(username) REFERENCES users(username), FOREIGN KEY(room_id) REFERENCES rooms(id), UNIQUE(room_id, datetime));"
                "INSERT INTO rooms(name,capacity) VALUES('Salle A',8);"
                "INSERT INTO rooms(name,capacity) VALUES('Salle B',12);"
            )
            #ancien code creant un seul utilisateur admin
            #admin_hash = generate_password_hash("admin", method="pbkdf2:sha256")
            #conn.execute("INSERT INTO users(username, password) VALUES (?, ?)", ("admin", admin_hash))
            
            # Utilisateurs créés seulement au premier démarrage
            default_users = [
                ("admin", "admin"),
                ("sonia", "sonia123"),
                ("asma", "asma123"),
                ("test", "test123"),
            ]
            for username, password in default_users:
                password_hash = generate_password_hash(password, method="pbkdf2:sha256")
                conn.execute(
                    "INSERT INTO users(username, password) VALUES (?, ?)",
                    (username, password_hash)
                )
            conn.commit()


init_db()