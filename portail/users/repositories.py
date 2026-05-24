import sqlite3
from ..config import Config
from .models import User

def get_user(username):
    with sqlite3.connect(Config.DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        if user is None:
            return None
        return User(user['username'], user['password'])
            