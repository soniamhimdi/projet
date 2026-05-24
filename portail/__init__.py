import flask
from . import config
from pathlib import Path
from werkzeug.security import generate_password_hash
import sqlite3
import logging, sys

app = flask.Flask(__name__)
app.secret_key = 'CHANGE_ME_SECRET_KEY'
app.static_folder = 'static'

app.logger.setLevel(logging.INFO)
app.logger.propagate = True

fh = logging.FileHandler('audit.log')
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
app.logger.addHandler(fh)

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