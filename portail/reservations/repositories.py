import sqlite3
from ..config import Config


def list_rooms():
    """
    Retourne la liste de toutes les salles disponibles.
    Utilisé pour remplir le menu déroulant de réservation.
    """

    with sqlite3.connect(Config.DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row

        return conn.execute(
            "SELECT * FROM rooms"
        ).fetchall()


def get_reserved_rooms(username):
    """
    Retourne uniquement les réservations de l'utilisateur connecté.

    Exemple :
    si Sonia est connectée, cette fonction affiche seulement
    les réservations faites par Sonia.
    """

    with sqlite3.connect(Config.DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row

        return conn.execute(
            """
            SELECT 
                r.id,
                r.name,
                r.capacity,
                res.datetime
            FROM rooms r
            JOIN reservations res 
                ON res.room_id = r.id
            WHERE res.username = ?
            ORDER BY res.datetime DESC
            """,
            (username,)
        ).fetchall()


def get_other_users_reservations(username):
    """
    Retourne les réservations faites par les autres utilisateurs.

    Cette fonction répond directement à l'exigence du travail :
    afficher les salles réservées par d'autres utilisateurs.

    Sécurité :
    on utilise une requête paramétrée avec ? pour éviter l'injection SQL.
    """

    with sqlite3.connect(Config.DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row

        return conn.execute(
            """
            SELECT 
                res.id,
                res.username,
                r.name,
                r.capacity,
                res.datetime
            FROM reservations res
            JOIN rooms r
                ON res.room_id = r.id
            WHERE res.username != ?
            ORDER BY res.datetime DESC
            """,
            (username,)
        ).fetchall()


def reserve_room(username, room_id, datetime):
    """
    Insère une nouvelle réservation dans la base de données.

    La date est normalisée à l'heure pile avec strftime.
    Exemple :
    2026-05-24 14:35 devient 2026-05-24 14:00:00.

    Si la salle est déjà réservée à cette heure,
    SQLite déclenche une IntegrityError à cause de UNIQUE(room_id, datetime).
    """

    try:
        with sqlite3.connect(Config.DATABASE_PATH) as conn:
            conn.execute(
                """
                INSERT INTO reservations(username, room_id, datetime)
                VALUES (?, ?, datetime(strftime('%Y-%m-%d %H:00:00', ?)))
                """,
                (username, room_id, datetime)
            )

            return True

    except sqlite3.IntegrityError:
        return False

  
def search_reservations_vulnerable(keyword):
    """
    VERSION VOLONTAIREMENT VULNÉRABLE À L'INJECTION SQL.

    Cette fonction concatène directement la saisie utilisateur
    dans la requête SQL.

    Elle est ajoutée seulement pour la démonstration du TP.
    Ne doit jamais être utilisée en production.
    """

    with sqlite3.connect(Config.DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row

        query = f"""
            SELECT
                res.id,
                res.username,
                r.name,
                r.capacity,
                res.datetime
            FROM reservations res
            JOIN rooms r
                ON res.room_id = r.id
            WHERE r.name = '{keyword}'
            ORDER BY res.datetime DESC
        """
        print("REQUETE VULNERABLE =")
        print(query)
        return conn.execute(query).fetchall()


def search_reservations_secure(keyword):
    """
    VERSION CORRIGÉE.

    Cette fonction utilise une requête paramétrée.
    La donnée utilisateur est traitée comme une valeur,
    pas comme du code SQL.
    """

    with sqlite3.connect(Config.DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row

        query = """
            SELECT
                res.id,
                res.username,
                r.name,
                r.capacity,
                res.datetime
            FROM reservations res
            JOIN rooms r
                ON res.room_id = r.id
            WHERE r.name = ?
            ORDER BY res.datetime DESC
        """
        results = conn.execute(query, (keyword,)).fetchall()   
        print("RECHERCHE SECURE =", keyword)
        print("NOMBRE RESULTATS =", len(results))

        return results