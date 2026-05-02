# SSL Scanner — Outil d'analyse SSL/TLS simplifié

Outil Python d'analyse SSL/TLS en ligne de commande et via interface web,
inspiré de SSL Labs. Fonctionne entièrement avec la bibliothèque standard Python
(+ Flask optionnel pour l'interface web).

---

## Fonctionnalités

### Analyse du certificat
- Sujet, émetteur, numéro de série
- Date d'expiration et jours restants
- Subject Alternative Names (SAN)
- Algorithme de signature
- Empreintes SHA-1 et SHA-256
- Détection certificat auto-signé / wildcard

### Protocoles SSL/TLS
- Détection SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3
- Marquage des protocoles obsolètes ou dangereux

### Cipher Suites
- Énumération des suites supportées
- Évaluation : `strong`, `acceptable`, `weak`, `insecure`
- Détection RC4, DES, MD5, NULL, EXPORT, etc.

### Vulnérabilités
- POODLE (SSLv3)
- DROWN (SSLv2)
- TLS 1.0/1.1 activés (BEAST)
- Certificat expiré ou proche de l'expiration
- Signature SHA-1 / MD5
- Cipher suites insécurisées
- Certificat auto-signé

### Sécurité HTTP
- HSTS (Strict-Transport-Security)
- max-age, includeSubDomains, preload

### Score et note
- Score de 0 à 100
- Note de A+ à F (comme SSL Labs)

---

## Installation

```bash
git clone <repo>
cd ssl_scanner

# Pour l'interface web uniquement :
pip install flask
```

Aucune dépendance externe pour la ligne de commande (uniquement stdlib Python 3.8+).

---

## Utilisation en ligne de commande

```bash
# Scan simple
python ssl_scanner.py example.com

# Port personnalisé
python ssl_scanner.py example.com --port 8443

# Plusieurs domaines
python ssl_scanner.py example.com github.com google.com

# Sortie JSON
python ssl_scanner.py example.com --json

# Sauvegarder en JSON
python ssl_scanner.py example.com --output result.json

# Sans vérification des protocoles (plus rapide)
python ssl_scanner.py example.com --no-protocols

# Timeout personnalisé
python ssl_scanner.py example.com --timeout 5
```

---

## Interface Web (Flask)

```bash
python web_server.py
# Ouvrir http://127.0.0.1:5000
```

Options :
```bash
python web_server.py --host 0.0.0.0 --port 8080 --debug
```

### API REST

```
POST /api/scan
Content-Type: application/json

{
  "host": "example.com",
  "port": 443,
  "check_protocols": true,
  "timeout": 15.0
}
```

```
GET /api/scan/example.com?port=443
GET /api/history
```

---

## Utilisation comme bibliothèque Python

```python
from ssl_scanner import SSLScanner

scanner = SSLScanner(timeout=10.0, check_protocols=True)

# Objet ScanResult
result = scanner.scan("example.com", 443)
print(f"Grade: {result.grade} ({result.score}/100)")
print(f"Expire dans: {result.certificate.days_until_expiry} jours")

# Dictionnaire
data = scanner.scan_to_dict("example.com")

# JSON
json_str = scanner.scan_to_json("example.com", indent=2)
print(json_str)
```

---

## Structure du projet

```
ssl_scanner/
├── ssl_scanner.py      # Module principal (CLI + bibliothèque)
├── web_server.py       # Serveur Flask (interface web)
├── requirements.txt    # Dépendances (Flask)
├── README.md           # Documentation
└── templates/
    └── index.html      # Interface web
```

---

## Exemple de sortie CLI

```
════════════════════════════════════════════════════════════
  SSL SCAN REPORT — example.com:443
════════════════════════════════════════════════════════════
  IP Address  : 93.184.216.34
  Scan Time   : 2024-01-15 10:32:11 UTC
  Duration    : 3241.5 ms
  Grade       : A  (Score: 88/100)

  CERTIFICAT
    Sujet         : www.example.com
    Émetteur      : DigiCert Inc
    Algo. signat. : sha256WithRSAEncryption
    Expiration    : 2024-03-14 23:59:59 UTC (58j)
    Auto-signé    : non

  PROTOCOLES
    SSLv2     : ✔ inactif
    SSLv3     : ✔ inactif
    TLS 1.0   : ✔ inactif
    TLS 1.1   : ✔ inactif
    TLS 1.2   : ✔ activé
    TLS 1.3   : ✔ activé

  VULNÉRABILITÉS
    ✔ [INFO    ] POODLE (SSLv3)
    ✔ [INFO    ] DROWN (SSLv2)
    ✔ [INFO    ] TLS 1.0 activé
    ✔ [INFO    ] Certificat expiré
    ✔ [INFO    ] Algorithme de signature faible
════════════════════════════════════════════════════════════
```

---

## Notes

- L'outil utilise uniquement le module `ssl` de la bibliothèque standard Python
- Certaines détections de protocoles peuvent être limitées par les capacités du système
- SSLv2/SSLv3 sont désactivés dans Python >= 3.10 par défaut (toujours marqués comme inactifs)
- L'outil ne teste pas Heartbleed (nécessite une bibliothèque externe)