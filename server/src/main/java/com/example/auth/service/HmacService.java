package com.example.auth.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Service responsable du calcul et de la vérification HMAC-SHA256.
 * Le mot de passe sert de clé secrète partagée entre le client et le serveur.
 * Cette implémentation est pédagogique - en production on utiliserait une clé dérivée.
 */
@Service
public class HmacService {

    private static final String ALGORITHM = "HmacSHA256";

    /**
     * Calcule un HMAC-SHA256.
     * @param secret le mot de passe en clair (clé secrète)
     * @param message email:nonce:timestamp
     * @return le HMAC en hexadécimal
     */
    public String compute(String secret, String message) throws Exception {
        Mac mac = Mac.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), ALGORITHM);
        mac.init(keySpec);
        byte[] result = mac.doFinal(message.getBytes("UTF-8"));
        return HexFormat.of().formatHex(result);
    }

    /**
     * Compare deux HMAC en temps constant pour éviter les timing attacks.
     * @param a premier hmac
     * @param b deuxième hmac
     * @return true si identiques
     */
    public boolean compareConstantTime(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(), b.getBytes());
    }
}