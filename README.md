# Auth Server — TP3 Authentification Forte

## Objectif TP3
Changer le protocole d'authentification : le mot de passe ne circule plus sur le réseau.
Le client prouve qu'il connaît le secret sans l'envoyer directement via HMAC + nonce + timestamp.

## Comment ça marche

### Étape 1 — Le client calcule une preuve
- Génère un nonce (UUID aléatoire)
- Récupère le timestamp actuel (epoch secondes)
- Calcule : `message = email + ":" + nonce + ":" + timestamp`
- Calcule : `hmac = HMAC_SHA256(clé = password, données = message)`
- Envoie : `email, nonce, timestamp, hmac` (jamais le mot de passe)

### Étape 2 — Le serveur vérifie
1. L'email existe en base
2. Le timestamp est dans la fenêtre ± 60 secondes
3. Le nonce n'a pas déjà été utilisé
4. Recalcule le HMAC et compare en temps constant
5. Retourne un `accessToken` si tout est valide

## Lancer le projet

### Prérequis
- Java 21
- Maven
- IntelliJ IDEA

### Lancer le serveur
Ouvrir le dossier `server/pom.xml` dans IntelliJ → Run `AuthApplication`

L'API démarre sur `http://localhost:8080`

### Lancer le client
Ouvrir le dossier `client/pom.xml` dans IntelliJ → Run `HelloApplication`

### Compte de test
- Email : `toto@example.com`
- Mot de passe : `Bonjour@123456`

## Endpoints

### POST /api/auth/register
```json
{
  "email": "user@example.com",
  "password": "Bonjour@123456"
}
```

### POST /api/auth/login
```json
{
  "email": "user@example.com",
  "nonce": "uuid-aleatoire",
  "timestamp": "1234567890",
  "hmac": "abc123..."
}
```
Retourne :
```json
{
  "accessToken": "uuid-token",
  "expiresAt": "1234567890000"
}
```

### GET /api/auth/me?token=xxx
Retourne les infos de l'utilisateur connecté.

## Analyse de sécurité TP3

### Ce qui est amélioré
- Le mot de passe ne circule jamais sur le réseau
- Le timestamp limite la fenêtre d'attaque à 60 secondes
- Le nonce empêche le rejeu d'une requête capturée
- La comparaison HMAC se fait en temps constant (anti timing attack)

### Ce qui reste fragile
- Le mot de passe est stocké en clair en base (corrigé au TP4 avec AES)
- Ce mécanisme est pédagogique — en production on utiliserait OAuth2 ou JWT
- TLS est supposé actif mais non configuré ici

## Qualité
- 15 tests JUnit passent
- SonarCloud configuré depuis TP2
- Tags Git : v3.0-start → v3.1-db-nonce → v3.2-hmac-client → v3.3-hmac-server → v3.4-anti-replay → v3.5-token → v3.6-tests-80 → v3-tp3