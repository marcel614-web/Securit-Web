# SSL Scanner — Outil d'analyse SSL/TLS

Outil Python d'analyse SSL/TLS en ligne de commande et via interface web,
inspiré de SSL Labs. Fonctionne entièrement avec la bibliothèque standard Python
(+ Flask optionnel pour l'interface web).

---

## Nouveautés de la v2.1

- **Cipher suites côté serveur** : utilise `shared_ciphers()` pour n'afficher que les algorithmes réellement supportés par la cible.
- **Détection fiable de TLS 1.0** (correction `TLSv1_0`).
- **Timeouts cohérents** : toutes les vérifications (protocoles, ciphers, HSTS) respectent le timeout défini.
- **Option `--no-headers`** en CLI, `check_headers` dans l’API pour ignorer la vérification HSTS.
- **Score amélioré** : les pénalités de clé ne s'appliquent que si la taille est connue (>0).
- **Historique avec port** : un même hôte sur plusieurs ports ne s'écrase plus.
- **Sécurité** : échappement XSS complet dans l'interface web.

---

## Fonctionnalités

- Analyse du certificat (sujet, émetteur, SAN, expiration, signature, clé…)
- Détection des protocoles SSLv2, SSLv3, TLS 1.0 → 1.3
- Énumération des suites de chiffrement (côté serveur)
- Vulnérabilités : POODLE, DROWN, BEAST, certificat expiré/faible, absence de PFS…
- En-têtes HTTP de sécurité (HSTS)
- Score 0–100 et note A+ à F (style SSL Labs)
- Export JSON, sauvegarde fichier
- Interface web Flask avec API REST

---

## Installation

```bash
git clone <repo>
cd ssl_scanner

# Pour l'interface web uniquement :
pip install flask