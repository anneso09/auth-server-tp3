package com.example.auth.controller;

import com.example.auth.service.AuthService;
import com.example.auth.service.LoginService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.auth.exception.AuthenticationFailedException;

import java.util.Map;

/**
 * Controller REST gérant les endpoints d'authentification.
 * TP3 : le login utilise désormais un protocole HMAC avec nonce et timestamp.
 * Le mot de passe ne circule plus sur le réseau.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final LoginService loginService;

    public AuthController(AuthService authService, LoginService loginService) {
        this.authService = authService;
        this.loginService = loginService;
    }

    /**
     * Inscrit un nouvel utilisateur.
     */
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestParam String email,
                                           @RequestParam String password) {
        authService.register(email, password);
        return ResponseEntity.ok("Utilisateur enregistré avec succès");
    }

    /**
     * Connecte un utilisateur via le protocole HMAC.
     * Le client envoie : email, nonce, timestamp, hmac
     * Le mot de passe ne circule pas.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String nonce = body.get("nonce");
        String hmac = body.get("hmac");
        long timestamp = Long.parseLong(body.get("timestamp"));

        String token = loginService.login(email, nonce, timestamp, hmac);

        return ResponseEntity.ok(Map.of(
                "accessToken", token,
                "expiresAt", String.valueOf(System.currentTimeMillis() + 15 * 60 * 1000)
        ));
    }

    /**
     * Route protégée accessible uniquement si authentifié.
     */
    @GetMapping("/me")
    public ResponseEntity<String> me(@RequestParam String token) {
        return authService.getUserByToken(token)
                .map(user -> ResponseEntity.ok("Utilisateur connecté : " + user.getEmail()))
                .orElseThrow(() -> new AuthenticationFailedException("Token invalide"));
    }
}