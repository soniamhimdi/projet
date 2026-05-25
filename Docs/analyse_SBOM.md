# Analyse du fichier SBOM (Software Bill of Materials) généré par **Semgrep**.

## Informations générales

| Champ  | Valeur               |
| ------ | -------------------- |
| Format | CycloneDX 1.4        |
| Outil  | Semgrep              |
| Projet | soniamhimdi/projet   |
| Date   | 2026-05-24 17:40 UTC |

## Dépendances détectées (3)

| Package       | Version | Licence      | Statut   |
| ------------- | ------- | ------------ | -------- |
| flask         | 3.1.3   | BSD-3-Clause | ✓ À jour |
| werkzeug      | 3.1.8   | BSD-3-Clause | ✓ À jour |
| python-dotenv | 1.0.1   | BSD-3-Clause | ✓ À jour |

## Observations

- Aucune vulnérabilité signalée dans ce SBOM — il liste seulement les composants, pas les CVEs.
- Toutes les licences sont **BSD-3-Clause** (licence permissive, pas de problème légal).
- Les versions correspondent au fichier `requirements.txt`.
- (Ce SBOM ne remplace pas un scan de vulnérabilités `dependency-check`qui lui cherche les CVEs).
