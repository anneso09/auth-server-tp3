package com.example.auth.service;

import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.repository.AuthNonceRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;

/**
 * Service gérant le protocole de login HMAC avec nonce et timestamp.
 * TP3 : le mot de passe ne circule plus sur le réseau.
 * Le client prouve qu'il connaît le secret sans l'envoyer directement.
 */
@Service
public class LoginService {

    private static final long TIMESTAMP_TOLERANCE_SECONDS = 60;

    private final AuthService authService;
    private final HmacService hmacService;
    private final AuthNonceRepository authNonceRepository;

    public LoginService(AuthService authService, HmacService hmacService,
                        AuthNonceRepository authNonceRepository) {
        this.authService = authService;
        this.hmacService = hmacService;
        this.authNonceRepository = authNonceRepository;
    }

    /**
     * Vérifie l'identité du client via HMAC, nonce et timestamp.
     * @return le token d'accès si authentification réussie
     */
    public String login(String email, String nonce, long timestamp, String hmac) {

        // 1. Vérifier que l'utilisateur existe
        User user = authService.findByEmail(email)
                .orElseThrow(() -> new AuthenticationFailedException("Email ou mot de passe incorrect."));

        // 2. Vérifier le timestamp (fenêtre de 60 secondes)
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - timestamp) > TIMESTAMP_TOLERANCE_SECONDS) {
            throw new AuthenticationFailedException("Timestamp invalide ou expiré.");
        }

        // 3. Vérifier le nonce anti-rejeu
        authNonceRepository.findByUserIdAndNonce(user.getId(), nonce).ifPresent(n -> {
            throw new AuthenticationFailedException("Nonce déjà utilisé.");
        });

        // 4. Enregistrer le nonce
        AuthNonce authNonce = new AuthNonce(user.getId(), nonce);
        authNonceRepository.save(authNonce);

        // 5. Recalculer le HMAC côté serveur
        String message = email + ":" + nonce + ":" + timestamp;
        String expectedHmac;
        try {
            expectedHmac = hmacService.compute(user.getPassword(), message);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Erreur lors de la vérification.");
        }

        // 6. Comparer en temps constant
        if (!hmacService.compareConstantTime(expectedHmac, hmac)) {
            throw new AuthenticationFailedException("Email ou mot de passe incorrect.");
        }

        // 7. Générer et retourner le token
        return authService.generateToken(user);
    }
}