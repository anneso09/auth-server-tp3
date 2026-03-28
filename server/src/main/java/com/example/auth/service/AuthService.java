package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import com.example.auth.validator.PasswordPolicyValidator;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service principal d'authentification.
 * TP2 : améliore le stockage avec BCrypt mais ne protège pas encore contre le rejeu.
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyValidator passwordPolicyValidator = new PasswordPolicyValidator();

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Inscrit un nouvel utilisateur.
     */
    public void register(String email, String password) {
        // Validation email
        if (email == null || email.isEmpty()) {
            throw new InvalidInputException("L'email ne peut pas être vide.");
        }
        if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")) {
            throw new InvalidInputException("Format d'email invalide.");
        }

        // Validation politique mot de passe
        String policyError = passwordPolicyValidator.getErrorMessage(password);
        if (policyError != null) {
            throw new InvalidInputException(policyError);
        }

        // Email unique
        if (userRepository.findByEmail(email).isPresent()) {
            throw new ResourceConflictException("Email déjà utilisé.");
        }

        // Hacher le mot de passe
        String hash = passwordEncoder.encode(password);
        User user = new User(email, hash);
        userRepository.save(user);
    }

    /**
     * Connecte un utilisateur existant.
     */
    /**
     * Connecte un utilisateur existant.
     * Anti brute-force : 5 échecs consécutifs bloquent le compte 2 minutes.
     */
    public String login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationFailedException("Email ou mot de passe incorrect."));

        // Vérifier si le compte est bloqué
        if (user.getLockUntil() != null && user.getLockUntil().isAfter(LocalDateTime.now())) {
            throw new AuthenticationFailedException("Compte temporairement bloqué. Réessayez dans 2 minutes.");
        }

        // Vérifier le mot de passe
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            // Incrémenter les échecs
            user.setFailedAttempts(user.getFailedAttempts() + 1);

            // Bloquer si 5 échecs
            if (user.getFailedAttempts() >= 5) {
                user.setLockUntil(LocalDateTime.now().plusMinutes(2));
                userRepository.save(user);
                throw new AuthenticationFailedException("Compte temporairement bloqué. Réessayez dans 2 minutes.");
            }

            userRepository.save(user);
            throw new AuthenticationFailedException("Email ou mot de passe incorrect.");
        }

        // Login OK : réinitialiser les compteurs
        user.setFailedAttempts(0);
        user.setLockUntil(null);

        // Générer un token
        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);

        return token;
    }

    /**
     * Récupère un utilisateur par son token.
     */
    public java.util.Optional<User> getUserByToken(String token) {
        return userRepository.findByToken(token);
    }
}