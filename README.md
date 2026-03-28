# Auth Server — TP2 Authentification Fragile

## Objectif TP2
Améliorer l'authentification du TP1 en ajoutant :
- Politique de mot de passe stricte (12 caractères, majuscule, minuscule, chiffre, caractère spécial)
- Stockage du mot de passe avec BCrypt (hash adaptatif)
- Anti brute-force : 5 échecs → blocage 2 minutes
- Indicateur de force du mot de passe côté client (rouge/orange/vert)
- Analyse qualité avec SonarCloud

## Lancer le projet

### Prérequis
- Java 17
- Maven
- MySQL

### Configurer la base de données
Dans `src/main/resources/application.properties` :
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db
spring.datasource.username=TON_USER
spring.datasource.password=TON_PASSWORD
spring.jpa.hibernate.ddl-auto=update
```

### Lancer l'API
```bash
mvn spring-boot:run
```

### Compte de test
- Email : `toto@example.com`
- Mot de passe : `pswd123`

## Analyse de sécurité TP2
- Le mot de passe est maintenant haché avec BCrypt (plus en clair)
- Le brute-force est limité par un système de blocage
- Malgré tout, le mot de passe reste transmis directement lors du login
- Une requête capturée peut encore être rejouée (corrigé en TP3)