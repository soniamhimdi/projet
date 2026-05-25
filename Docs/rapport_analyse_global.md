# Rapport d'Analyse de Sécurité Global — Portail de Réservation

**Projet :** soniamhimdi/projet  
**Date :** 2026-05-24  
**Auteur :** Sonia Mhimdi- Asma Ajroudi

---

## 1. Résumé exécutif

| Outil                   | Type d'analyse           | Vulnérabilités trouvées       |
| ----------------------- | ------------------------ | ----------------------------- |
| Semgrep (SAST)          | Analyse statique du code | 3 (1 Haute, 2 Moyennes)       |
| Semgrep (Supply Chain)  | Dépendances              | 1 CVE (Moyenne)               |
| OWASP Dependency-Check  | Dépendances / CVE        | 0 CVE confirmé                |
| ZAP by Checkmarx (DAST) | Analyse dynamique        | 3 Moyennes, 2 Faibles, 4 Info |
| SBOM (CycloneDX 1.4)    | Inventaire composants    | 3 composants — licences OK    |

---

## 2. Analyse SAST — Semgrep (Code)

**Outil :** Semgrep  
**Date du scan :** 2026-05-24  
**Fichier source :** `Semgrep_Code_Combined_Findings_2026_05_24.csv`

### 2.1 Injection SQL — Haute

| Champ    | Détail                                                    |
| -------- | --------------------------------------------------------- |
| Règle    | `python.sqlalchemy.security.sqlalchemy-execute-raw-query` |
| Fichier  | `portail/reservations/repositories.py` ligne 137          |
| Sévérité | **Haute**                                                 |
| OWASP    | A03 — Injection                                           |
| CWE      | CWE-89                                                    |

**Description :** Une requête SQL est construite par concaténation de chaînes, ce qui permet une injection SQL.

**Recommandation :**

```python
# Avant (vulnérable)
conn.execute("SELECT * FROM reservations WHERE username='" + username + "'")

# Après (sécurisé)
conn.execute("SELECT * FROM reservations WHERE username=?", (username,))
```

---

### 2.2 Requête SQL formatée — Moyenne

| Champ    | Détail                                           |
| -------- | ------------------------------------------------ |
| Règle    | `python.lang.security.audit.formatted-sql-query` |
| Fichier  | `portail/reservations/repositories.py` ligne 137 |
| Sévérité | **Moyenne**                                      |
| CWE      | CWE-89                                           |

**Description :** Même zone de code — Semgrep détecte un formatage de chaîne dans une requête SQL.

**Recommandation :** Utiliser exclusivement des requêtes paramétrées 
correction disponible dans le code de search(requete parametrée)
---

### 2.3 Absence de jeton CSRF — Moyenne

| Champ    | Détail                                        |
| -------- | --------------------------------------------- |
| Règle    | `python.django.security.django-no-csrf-token` |
| Fichier  | `portail/templates/login.html` ligne 19       |
| Sévérité | **Moyenne**                                   |
| OWASP    | A01 — Broken Access Control                   |
| CWE      | CWE-352                                       |

**Description :** Le formulaire de connexion ne contient pas de jeton CSRF, exposant l'application à des attaques Cross-Site Request Forgery.

**Recommandation :** Ajouter Flask-WTF et inclure `{{ form.csrf_token }}` dans les formulaires.

---

## 3. Analyse Supply Chain — Semgrep

**Fichier source :** `Semgrep_Supply_Chain_Findings_2026_05_24.csv`

### CVE-2026-28684 — python-dotenv 1.0.1

| Champ         | Détail                                             |
| ------------- | -------------------------------------------------- |
| CVE           | CVE-2026-28684                                     |
| Package       | python-dotenv 1.0.1                                |
| Sévérité      | **Moyenne**                                        |
| EPSS          | 0.0% (faible probabilité d'exploitation)           |
| Type          | Link Following / UNIX Symlink Following            |
| Accessibilité | Pas d'analyse de portée (No Reachability Analysis) |

**Description :** python-dotenv 1.0.1 est vulnérable à une résolution incorrecte de liens symboliques UNIX avant l'accès aux fichiers.

**Recommandation :** Mettre à jour python-dotenv vers la version corrigée dès qu'elle est disponible.

---

## 4. Analyse DAST — ZAP by Checkmarx

**Outil :** ZAP 2.17.0  
**Date du scan :** 2026-05-24 23:40  
**Cibles :** `http://127.0.0.1:5000` et `http://192.168.2.14:5000`  
**Fichier source :** `2026-05-24-ZAP-Report- 1.html`

### Résumé des alertes

| Risque      | Nombre |
| ----------- | ------ |
| Haut        | 0      |
| Moyen       | 3      |
| Faible      | 2      |
| Information | 4      |
| **Total**   | **9**  |

### 4.1 Content Security Policy (CSP) Header Not Set — Moyenne

| Champ     | Détail   |
| --------- | -------- |
| CWE       | CWE-693  |
| OWASP     | A05:2021 |
| Confiance | Haute    |

**Description :** L'en-tête HTTP `Content-Security-Policy` est absent. Sans CSP, le navigateur n'a aucune restriction sur les sources de scripts, ce qui facilite les attaques XSS.

**Recommandation :**

```python
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

### 4.2 Missing Anti-Clickjacking Header — Moyenne

| Champ     | Détail   |
| --------- | -------- |
| CWE       | CWE-1021 |
| OWASP     | A05:2021 |
| Confiance | Moyenne  |

**Description :** L'en-tête `X-Frame-Options` ou la directive `frame-ancestors` de CSP sont absents. L'application peut être embarquée dans une iframe et exposée au Clickjacking.

**Recommandation :**

```python
response.headers['X-Frame-Options'] = 'DENY'
```

---

### 4.3 Absence de Jetons Anti-CSRF — Moyenne

| Champ     | Détail   |
| --------- | -------- |
| CWE       | CWE-352  |
| OWASP     | A01:2021 |
| Confiance | Faible   |

**Description :** ZAP confirme l'absence de protection CSRF sur les formulaires (déjà détecté par Semgrep SAST).

---

### 4.4 Server Leaks Version Information — Faible

**Description :** L'en-tête de réponse `Server: Werkzeug/3.1.8 Python/3.13.3` expose la version de la stack technique, facilitant le ciblage d'attaques.

**Recommandation :**

```python
@app.after_request
def remove_server_header(response):
    response.headers['Server'] = 'Apache'
    return response
```

---

### 4.5 X-Content-Type-Options Header Missing — Faible

**Description :** Absence de l'en-tête `X-Content-Type-Options: nosniff`, ce qui peut permettre du MIME sniffing.

**Recommandation :**

```python
response.headers['X-Content-Type-Options'] = 'nosniff'
```

---

## 5. SBOM — Inventaire des composants

**Format :** CycloneDX 1.4  
**Outil :** Semgrep  
**Fichier source :** `sbom-...json`

| Package       | Version | Licence      | Statut           |
| ------------- | ------- | ------------ | ---------------- |
| flask         | 3.1.3   | BSD-3-Clause | ✓ À jour         |
| werkzeug      | 3.1.8   | BSD-3-Clause | ✓ À jour         |
| python-dotenv | 1.0.1   | BSD-3-Clause | ⚠ CVE-2026-28684 |

Toutes les licences sont **BSD-3-Clause** (permissive, sans contrainte de redistribution).

---

## 6. OWASP Dependency-Check

**Outil :** Dependency-Check 12.1.0  
**Date :** 2026-05-21  
**Résultat :** Aucune CVE confirmée dans les dépendances Python directes du projet.

> Note : Le scan a analysé des fichiers JS internes à Werkzeug et urllib3 sans trouver de vulnérabilité connue.

---

## 7. Synthèse globale des vulnérabilités

| #   | Vulnérabilité                 | Outil                | Sévérité  | Fichier                            | OWASP | Statut   |
| --- | ----------------------------- | -------------------- | --------- | ---------------------------------- | ----- | -------- |
| 1   | Injection SQL                 | Semgrep SAST         | **Haute** | `reservations/repositories.py:137` | A03   | ⚠ Ouvert |
| 2   | Requête SQL formatée          | Semgrep SAST         | Moyenne   | `reservations/repositories.py:137` | A03   | ⚠ Ouvert |
| 3   | Pas de jeton CSRF             | Semgrep SAST + ZAP   | Moyenne   | `templates/login.html:19`          | A01   | ⚠ Ouvert |
| 4   | CVE-2026-28684 python-dotenv  | Semgrep Supply Chain | Moyenne   | `requirements.txt`                 | A06   | ⚠ Ouvert |
| 5   | CSP Header absent             | ZAP DAST             | Moyenne   | Toutes les routes                  | A05   | ⚠ Ouvert |
| 6   | Anti-Clickjacking absent      | ZAP DAST             | Moyenne   | Toutes les routes                  | A05   | ⚠ Ouvert |
| 7   | Version serveur exposée       | ZAP DAST             | Faible    | En-tête HTTP                       | A05   | ⚠ Ouvert |
| 8   | X-Content-Type-Options absent | ZAP DAST             | Faible    | En-tête HTTP                       | A05   | ⚠ Ouvert |

---

## 8. Plan de remédiation prioritaire

### Priorité 1 — Critique

- **Corriger l'injection SQL** (`repositories.py:137`) : remplacer la concaténation par des requêtes paramétrées.

### Priorité 2 — Importante

- **Ajouter la protection CSRF** : intégrer Flask-WTF avec jeton CSRF sur tous les formulaires.
- **Mettre à jour python-dotenv** dès qu'une version corrigée de CVE-2026-28684 est disponible.

### Priorité 3 — Renforcement

- **Ajouter les en-têtes de sécurité HTTP** via un middleware Flask : `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, masquage du header `Server`.

```python
@app.after_request
def security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Server'] = 'Apache'
    return response
```

---

## 9. Conclusion

L'analyse multi-outils du portail de réservation révèle **8 vulnérabilités**, dont une de sévérité haute (injection SQL). Aucune vulnérabilité critique n'a été détectée, mais l'absence de plusieurs mécanismes de protection standard (CSRF, CSP, en-têtes HTTP de sécurité) affaiblit significativement la posture de sécurité de l'application. La mise en œuvre du plan de remédiation proposé permettrait d'atteindre un niveau de sécurité conforme aux recommandations OWASP Top 10.
