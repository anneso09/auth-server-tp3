package com.example.auth.validator;

/**
 * Validateur de politique de mot de passe pour TP2.
 * Vérifie que le mot de passe respecte les règles de sécurité minimales.
 */
public class PasswordPolicyValidator {

    private static final int MIN_LENGTH = 12;

    /**
     * Vérifie si le mot de passe respecte la politique.
     * @param password le mot de passe à valider
     * @return true si valide, false sinon
     */
    public boolean isValid(String password) {
        if (password == null || password.length() < MIN_LENGTH) return false;
        if (!password.matches(".*[A-Z].*")) return false;  // majuscule
        if (!password.matches(".*[a-z].*")) return false;  // minuscule
        if (!password.matches(".*[0-9].*")) return false;  // chiffre
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{}|;':\",./<>?].*")) return false;  // spécial
        return true;
    }

    /**
     * Retourne un message d'erreur explicite si le mot de passe est invalide.
     * @param password le mot de passe à valider
     * @return message d'erreur, ou null si valide
     */
    public String getErrorMessage(String password) {
        if (password == null || password.length() < MIN_LENGTH)
            return "Le mot de passe doit contenir au moins 12 caractères.";
        if (!password.matches(".*[A-Z].*"))
            return "Le mot de passe doit contenir au moins une majuscule.";
        if (!password.matches(".*[a-z].*"))
            return "Le mot de passe doit contenir au moins une minuscule.";
        if (!password.matches(".*[0-9].*"))
            return "Le mot de passe doit contenir au moins un chiffre.";
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{}|;':\",./<>?].*"))
            return "Le mot de passe doit contenir au moins un caractère spécial.";
        return null;
    }
}