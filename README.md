# Projet

## Démarrage du portail
1. Il est d'abord recommandé de créer un environnement virtuel Python afin d'y installer toutes les dépendances sans affecter les paquets installés sur le système:
    ```bash
    python3 -m venv env
    source env/bin/activate
    ```
2. Ensuite, on installe les dépendances
    ```bash
    pip install -r requirements.txt
    ```

3. Finalement, on démarre l'application Python/Flask
    ```bash
    python3 -m flask run
    ```

L'application démarre alors un serveur de développement qui expose l'application sur 0.0.0.0 (http://127.0.0.1:5000 et toutes les interfaces disponibles)

