package com.example.auth.repository;

import com.example.auth.entity.AuthNonce;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Repository pour la gestion des nonces anti-rejeu.
 */
public interface AuthNonceRepository extends JpaRepository<AuthNonce, Long> {

    Optional<AuthNonce> findByUserIdAndNonce(Long userId, String nonce);
}
