package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un nonce utilisé pour l'anti-rejeu.
 * Chaque nonce est unique par utilisateur et expire après 2 minutes.
 */
@Entity
@Table(name = "auth_nonce", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"user_id", "nonce"})
})
public class AuthNonce {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false)
    private String nonce;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private boolean consumed = false;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public AuthNonce() {}

    public AuthNonce(Long userId, String nonce) {
        this.userId = userId;
        this.nonce = nonce;
        this.expiresAt = LocalDateTime.now().plusSeconds(120);
        this.createdAt = LocalDateTime.now();
        this.consumed = false;
    }

    public Long getId() { return id; }

    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }

    public boolean isConsumed() { return consumed; }
    public void setConsumed(boolean consumed) { this.consumed = consumed; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}