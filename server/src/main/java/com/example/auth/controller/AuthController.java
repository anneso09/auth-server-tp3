package com.example.auth.controller;

import com.example.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.auth.exception.AuthenticationFailedException;

/**
 * Controller REST gérant les endpoints d'authentification.
 * ATTENTION : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Inscrit un nouvel utilisateur.
     * @param email l'email de l'utilisateur
     * @param password le mot de passe en clair
     * @return message de succès
     */
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestParam String email,
                                           @RequestParam String password) {
        authService.register(email, password);
        return ResponseEntity.ok("Utilisateur enregistré avec succès");
    }

    /**
     * Connecte un utilisateur existant.
     * @param email l'email de l'utilisateur
     * @param password le mot de passe en clair
     * @return message de succès
     */
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String email,
                                        @RequestParam String password) {
        String token = authService.login(email, password);
        return ResponseEntity.ok("Connexion réussie. Token: " + token);
    }

    /**
     * Route protégée accessible uniquement si authentifié.
     * @param token le token de l'utilisateur
     * @return les infos de l'utilisateur
     */
    @GetMapping("/me")
    public ResponseEntity<String> me(@RequestParam String token) {
        return authService.getUserByToken(token)
                .map(user -> ResponseEntity.ok("Utilisateur connecté : " + user.getEmail()))
                .orElseThrow(() -> new AuthenticationFailedException("Token invalide"));
    }
}