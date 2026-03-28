package com.example.authclient;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Controller JavaFX du client d'authentification.
 * TP3 : le login utilise désormais HMAC + nonce + timestamp.
 * Le mot de passe ne circule plus sur le réseau.
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

    @FXML
    public void initialize() {
        passwordField.textProperty().addListener((obs, oldVal, newVal) -> {
            updateStrengthIndicator(newVal);
        });
    }

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
            strengthLabel.setText("Force du mot de passe : ❌ Faible");
            strengthLabel.setStyle("-fx-font-weight: bold; -fx-text-fill: red;");
        } else if (score == 5 && password.length() < 16) {
            strengthLabel.setText("Force du mot de passe : ⚠️ Moyen");
            strengthLabel.setStyle("-fx-font-weight: bold; -fx-text-fill: orange;");
        } else {
            strengthLabel.setText("Force du mot de passe : ✅ Fort");
            strengthLabel.setStyle("-fx-font-weight: bold; -fx-text-fill: green;");
        }
    }

    /**
     * Calcule un HMAC-SHA256 avec le mot de passe comme clé.
     */
    private String computeHmac(String secret, String message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        mac.init(keySpec);
        byte[] result = mac.doFinal(message.getBytes("UTF-8"));
        return HexFormat.of().formatHex(result);
    }

    @FXML
    protected void onRegister() {
        String email = emailField.getText();
        String password = passwordField.getText();
        String passwordConfirm = passwordConfirmField.getText();

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
            // 1. Préparer nonce et timestamp
            String nonce = UUID.randomUUID().toString();
            long timestamp = Instant.now().getEpochSecond();

            // 2. Calculer le HMAC
            String message = email + ":" + nonce + ":" + timestamp;
            String hmac = computeHmac(password, message);

            // 3. Construire le JSON
            String json = String.format(
                    "{\"email\":\"%s\",\"nonce\":\"%s\",\"timestamp\":\"%d\",\"hmac\":\"%s\"}",
                    email, nonce, timestamp, hmac
            );

            // 4. Envoyer la requête
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + "/login"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String body = response.body();
            resultLabel.setText("Réponse : " + body);

            // 5. Extraire le token
            if (body.contains("accessToken")) {
                String token = body.split("\"accessToken\":\"")[1].split("\"")[0];
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