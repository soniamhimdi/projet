from flask import render_template, request, redirect, url_for, session
from portail import app
from portail.reservations.repositories import (
    reserve_room,
    search_reservations_vulnerable,
    search_reservations_secure
)


@app.route("/reserve", methods=["POST"])
def reserve():
    """
    Route appelée quand l'utilisateur soumet le formulaire
    pour réserver une salle.
    """

    # Si aucun utilisateur n'est connecté,
    # on le redirige vers la page de connexion.
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Récupération des champs envoyés par le formulaire HTML.
    room_id = request.form["room_id"]
    datetime = request.form["datetime"]

    # Création de la réservation en base de données.
    # session["user_id"] contient ici le username de l'utilisateur.
    success = reserve_room(session["user_id"], room_id, datetime)

    # Journalisation de l'action dans audit.log.
    app.logger.info(
        "Salle [id=%s] réservée par utilisateur %s pour %s",
        room_id,
        session["user_id"],
        datetime
    )

    # Si success == False, on renvoie error=True à la page home.
    return redirect(url_for("home", error=not success or None))


@app.route('/search-vulnerable')
def search_vulnerable():
    """
    Route de démonstration vulnérable à l'injection SQL.

    Exemple de test :
    /search-vulnerable?q=' OR '1'='1
    """

    if 'user_id' not in session:
        return redirect(url_for('login'))

    keyword = request.args.get('q', '').strip()

    results = search_reservations_vulnerable(keyword)

    return render_template(
        'search.html',
        keyword=keyword,
        results=results,
        mode='vulnerable'
    )


@app.route('/search')
def search_secure():
    """
    Route corrigée contre l'injection SQL.

    Elle utilise une requête paramétrée.
    """

    if 'user_id' not in session:
        return redirect(url_for('login'))

    keyword = request.args.get('q', '').strip()

    results = search_reservations_secure(keyword)

    return render_template(
        'search.html',
        keyword=keyword,
        results=results,
        mode='secure'
    )