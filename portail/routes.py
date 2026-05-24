from flask import render_template, redirect, url_for, session, request
from .users.repositories import get_user
from .reservations.repositories import list_rooms, get_reserved_rooms, get_other_users_reservations
from . import app

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    rooms = list_rooms()
    user = get_user(session['user_id'])
    reservations = get_reserved_rooms(session['user_id'])

    # Nouvelle liste : réservations faites par les autres utilisateurs
    other_reservations = get_other_users_reservations(session['user_id'])

    return render_template(
        'index.html',
        rooms=rooms,
        user=user,
        reservations=reservations,
        other_reservations=other_reservations,
        error=request.args.get('error', None)
    )