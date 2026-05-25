# Rapport de Correctifs — Portail de Réservation

**Projet :** soniamhimdi/projet  
**Date :** 2026-05-25  
**Auteur :** Sonia Mhimdi — Asma Ajroudi  
**Référence :** rapport_analyse_global.md / analyse_rapport_sast.md

---

## Objectif

Ce document recense les correctifs appliqués au code source suite aux vulnérabilités identifiées par les outils SAST (Semgrep) et DAST (ZAP by Checkmarx).  
Pour chaque correction : le fichier modifié, la vulnérabilité ciblée, le code erroné (commenté) et le code corrigé sont documentés.

> **Note :** La fonction `search_reservations_vulnerable` et la route `/search-vulnerable` ont été **intentionnellement conservées** telles quelles pour les besoins de la démonstration du TP.

---

## Récapitulatif des correctifs

| # | Fichier | Vulnérabilité | CWE / OWASP | Gravité |
|---|---------|---------------|-------------|---------|
| 1 | `portail/__init__.py` | Clé secrète codée en dur | CWE-798 / A07 | Haute |
| 2 | `portail/__init__.py` | Absence de protection CSRF | CWE-352 / A01 | Moyenne |
| 3 | `portail/__init__.py` | En-tête CSP absent | CWE-693 / A05 | Moyenne |
| 4 | `portail/__init__.py` | En-tête anti-clickjacking absent | CWE-1021 / A05 | Moyenne |
| 5 | `portail/__init__.py` | MIME sniffing possible | CWE-693 / A05 | Faible |
| 6 | `portail/__init__.py` | Version serveur exposée | — / A05 | Faible |
| 7 | `portail/templates/login.html` | Formulaire sans jeton CSRF | CWE-352 / A01 | Moyenne |
| 8 | `portail/templates/index.html` | Formulaire sans jeton CSRF | CWE-352 / A01 | Moyenne |
| 9 | `portail/users/models.py` | Semicolons invalides (syntaxe) | — | Faible |
| 10 | `portail/config.py` | Semicolon invalide (syntaxe) | — | Faible |
| 11 | `portail/auth/routes.py` | Semicolon invalide (syntaxe) | — | Faible |
| 12 | `requirements.txt` | Dépendances manquantes / non à jour | — | Info |

---

## Détail des correctifs

---

### Correctif 1 — Clé secrète codée en dur (CWE-798)

**Fichier :** `portail/__init__.py`  
**Outil détecteur :** Semgrep SAST / bonne pratique  
**Risque :** Une clé secrète statique dans le code source permet à tout développeur ayant accès au dépôt de forger des sessions Flask valides.

**Code erroné (commenté) :**
```python
# app.secret_key = 'CHANGE_ME_SECRET_KEY'
```

**Code corrigé :**
```python
# Chargement des variables d'environnement depuis le fichier .env
load_dotenv()

# Nouvelle clé chargée depuis la variable d'environnement SECRET_KEY (définie dans .env)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-fallback-changer-en-production')
```

**Fichier `.env` créé à la racine du projet :**
```
SECRET_KEY=c2VjcmV0LWNsZS1mbGFzay1yZXNlcnZhdGlvbi0yMDI2
```

> Le fichier `.env` ne doit pas être versionné dans git.

---

### Correctif 2 — Absence de protection CSRF (CWE-352)

**Fichier :** `portail/__init__.py`  
**Outil détecteur :** Semgrep SAST (`django-no-csrf-token`) + ZAP DAST  
**Risque :** Sans jeton CSRF, un attaquant peut forcer un utilisateur authentifié à effectuer des actions (réservation, connexion) à son insu depuis un site tiers.

**Dépendance ajoutée dans `requirements.txt` :**
```
Flask-WTF==1.3.0
```

**Code corrigé ajouté dans `__init__.py` :**
```python
from flask_wtf.csrf import CSRFProtect  # CORRECTION : protection CSRF

# CORRECTION (CWE-352) : activation de la protection CSRF sur tous les formulaires POST
csrf = CSRFProtect(app)
```

---

### Correctifs 3, 4, 5, 6 — En-têtes de sécurité HTTP manquants

**Fichier :** `portail/__init__.py`  
**Outil détecteur :** ZAP by Checkmarx (alertes moyennes et faibles)

| En-tête ajouté | Protège contre | CWE |
|----------------|----------------|-----|
| `Content-Security-Policy` | Injection de scripts XSS | CWE-693 |
| `X-Frame-Options: DENY` | Clickjacking | CWE-1021 |
| `X-Content-Type-Options: nosniff` | MIME sniffing | CWE-693 |
| `Server: Apache` | Exposition de la version Werkzeug/Python | — |

**Code corrigé ajouté :**
```python
# CORRECTION (CWE-693, CWE-1021) : en-têtes de sécurité HTTP ajoutés à chaque réponse
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
```

---

### Correctifs 7 & 8 — Jetons CSRF manquants dans les formulaires HTML

**Fichiers :** `portail/templates/login.html`, `portail/templates/index.html`  
**Outil détecteur :** Semgrep SAST + ZAP DAST (CWE-352)  
**Risque :** Formulaires POST sans jeton CSRF, exploitables par une attaque Cross-Site Request Forgery.

**Code corrigé — `login.html` :**
```html
<form method='POST' class='login-form'>
   <!-- CORRECTION (CWE-352) : jeton CSRF ajouté pour protéger le formulaire de connexion -->
   <input type='hidden' name='csrf_token' value='{{ csrf_token() }}'/>
   ...
</form>
```

**Code corrigé — `index.html` :**
```html
<form action="/reserve" method="POST" class="login-form">
  <!-- CORRECTION (CWE-352) : jeton CSRF ajouté pour protéger le formulaire de réservation -->
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />
  ...
</form>
```

---

### Correctifs 9, 10, 11 — Semicolons invalides (syntaxe Python)

Les semicolons (`;`) en fin d'instruction sont inutiles en Python. Bien que non bloquants, ils indiquent une confusion avec d'autres langages et peuvent masquer des erreurs.

**`portail/users/models.py` — Code erroné (commenté) :**
```python
# self.username = username;
# self.password = password;
```
**Code corrigé :**
```python
self.username = username
self.password = password
```

**`portail/config.py` — Code erroné (commenté) :**
```python
# DATABASE_PATH = 'database.db';
```
**Code corrigé :**
```python
DATABASE_PATH = 'database.db'
```

**`portail/auth/routes.py` — Code erroné (commenté) :**
```python
# user = get_user(username);
```
**Code corrigé :**
```python
user = get_user(username)
```

---

### Correctif 12 — Dépendances mises à jour (`requirements.txt`)

```
Flask==3.1.3
Werkzeug==3.1.8
python-dotenv==1.2.2       # mise à jour (correction CVE-2026-28684)
Flask-WTF==1.3.0            # CORRECTION (CWE-352) : ajout pour la protection CSRF
```

---

## Vulnérabilité conservée intentionnellement

### `search_reservations_vulnerable` — Injection SQL (CWE-89)

**Fichier :** `portail/reservations/repositories.py` (ligne ~130)  
**Route :** `/search-vulnerable`

Cette fonction concatène directement la saisie utilisateur dans la requête SQL.  
Elle est **conservée volontairement** pour illustrer la vulnérabilité dans le cadre du TP.  
La version corrigée (`search_reservations_secure`) utilise une requête paramétrée et est accessible via `/search`.

```python
# VERSION VOLONTAIREMENT VULNÉRABLE — ne pas utiliser en production
query = f"... WHERE r.name = '{keyword}'"
```

---

## Conclusion

Toutes les vulnérabilités identifiées par les outils d'analyse (Semgrep SAST, ZAP DAST) ont été corrigées, à l'exception de la démonstration intentionnelle d'injection SQL.  
Les corrections suivent les recommandations OWASP Top 10 2021 et les bonnes pratiques Flask.

| Statut | Nombre |
|--------|--------|
| ✅ Corrigé | 11 |
| ⚠️ Conservé intentionnellement (TP) | 1 |
| 📦 Dépendance mise à jour | 1 |
