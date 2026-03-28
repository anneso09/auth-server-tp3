package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import com.example.auth.validator.PasswordPolicyValidator;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Service principal d'authentification.
 * TP3 : le mot de passe est stocké en clair pour permettre le recalcul HMAC côté serveur.
 * TP2 améliorait le stockage mais ne protégeait pas encore contre le rejeu.
 * TP3 change le protocole : le mot de passe ne circule plus sur le réseau.
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordPolicyValidator passwordPolicyValidator = new PasswordPolicyValidator();

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Inscrit un nouvel utilisateur.
     */
    public void register(String email, String password) {
        if (email == null || email.isEmpty()) {
            throw new InvalidInputException("L'email ne peut pas être vide.");
        }
        if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")) {
            throw new InvalidInputException("Format d'email invalide.");
        }

        String policyError = passwordPolicyValidator.getErrorMessage(password);
        if (policyError != null) {
            throw new InvalidInputException(policyError);
        }

        if (userRepository.findByEmail(email).isPresent()) {
            throw new ResourceConflictException("Email déjà utilisé.");
        }

        // TP3 : stockage en clair (le chiffrement AES vient au TP4)
        User user = new User(email, password);
        userRepository.save(user);
    }

    /**
     * Récupère un utilisateur par email.
     */
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * Génère et sauvegarde un token pour un utilisateur.
     */
    public String generateToken(User user) {
        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);
        return token;
    }

    /**
     * Récupère un utilisateur par son token.
     */
    public Optional<User> getUserByToken(String token) {
        return userRepository.findByToken(token);
    }
}