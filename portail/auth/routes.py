from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash
from portail.users.repositories import get_user
from portail import app

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username);
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.username
            app.logger.info("Utilisateur connecté: %s", username)
            return redirect(url_for('home'))
        app.logger.warning("Tentative de connexion échouée: %s", username)
        return render_template('login.html', error='Identifiants invalides')
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session['user_id']
    session.clear()
    app.logger.info("Utilisateur déconnecté: %s", username)
    return redirect(url_for('login'))