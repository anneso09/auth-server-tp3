package com.example.authclient;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Controller JavaFX du client d'authentification.
 * TP2 : ajout indicateur de force du mot de passe et double saisie.
 */
public class HelloController {

    @FXML private TextField emailField;
    @FXML private PasswordField passwordField;
    @FXML private PasswordField passwordConfirmField;
    @FXML private TextField tokenField;
    @FXML private Label resultLabel;
    @FXML private Label strengthLabel;

    private final HttpClient client = HttpClient.newHttpClient();
    private static final String BASE_URL = "http://localhost:8080/api/auth";

    /**
     * Appelé automatiquement par JavaFX après le chargement du FXML.
     * On écoute les changements du champ mot de passe pour mettre à jour l'indicateur.
     */
    @FXML
    public void initialize() {
        passwordField.textProperty().addListener((obs, oldVal, newVal) -> {
            updateStrengthIndicator(newVal);
        });
    }

    /**
     * Met à jour l'indicateur de force du mot de passe.
     * Rouge = non conforme, Orange = conforme mais faible, Vert = bon niveau.
     */
    private void updateStrengthIndicator(String password) {
        boolean hasLength = password.length() >= 12;
        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasLower = password.matches(".*[a-z].*");
        boolean hasDigit = password.matches(".*[0-9].*");
        boolean hasSpecial = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{}|;':\",./<>?].*");

        boolean allRules = hasLength && hasUpper && hasLower && hasDigit && hasSpecial;
        int score = (hasLength ? 1 : 0) + (hasUpper ? 1 : 0) + (hasLower ? 1 : 0)
                + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);

        if (!allRules) {
            // Rouge : pas encore conforme
            strengthLabel.setText("Force du mot de passe : ❌ Faible");
            strengthLabel.setStyle("-fx-font-weight: bold; -fx-text-fill: red;");
        } else if (score == 5 && password.length() < 16) {
            // Orange : conforme mais longueur limite
            strengthLabel.setText("Force du mot de passe : ⚠️ Moyen");
            strengthLabel.setStyle("-fx-font-weight: bold; -fx-text-fill: orange;");
        } else {
            // Vert : bon niveau
            strengthLabel.setText("Force du mot de passe : ✅ Fort");
            strengthLabel.setStyle("-fx-font-weight: bold; -fx-text-fill: green;");
        }
    }

    @FXML
    protected void onRegister() {
        String email = emailField.getText();
        String password = passwordField.getText();
        String passwordConfirm = passwordConfirmField.getText();

        // Vérification double saisie côté client
        if (!password.equals(passwordConfirm)) {
            resultLabel.setText("Erreur : les mots de passe ne correspondent pas.");
            return;
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + "/register?email=" + email + "&password=" + password))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            resultLabel.setText("Réponse : " + response.body());
        } catch (Exception e) {
            resultLabel.setText("Erreur : " + e.getMessage());
        }
    }

    @FXML
    protected void onLogin() {
        String email = emailField.getText();
        String password = passwordField.getText();
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + "/login?email=" + email + "&password=" + password))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String body = response.body();
            resultLabel.setText("Réponse : " + body);
            if (body.contains("Token: ")) {
                String token = body.split("Token: ")[1].trim();
                tokenField.setText(token);
            }
        } catch (Exception e) {
            resultLabel.setText("Erreur : " + e.getMessage());
        }
    }

    @FXML
    protected void onMe() {
        String token = tokenField.getText();
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8080/api/auth/me?token=" + token))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            resultLabel.setText("Réponse : " + response.body());
        } catch (Exception e) {
            resultLabel.setText("Erreur : " + e.getMessage());
        }
    }
}