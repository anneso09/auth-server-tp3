package com.example.auth.exception;

/**
 * Exception levée quand l'authentification échoue (email ou mot de passe incorrect).
 * ATTENTION : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
public class AuthenticationFailedException extends RuntimeException {
    public AuthenticationFailedException(String message) {
        super(message);
    }
}