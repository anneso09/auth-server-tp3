package com.example.auth;

import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.service.AuthService;
import com.example.auth.service.HmacService;
import com.example.auth.service.LoginService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
class AuthApplicationTests {

	@Autowired
	private AuthService authService;

	@Autowired
	private LoginService loginService;

	@Autowired
	private HmacService hmacService;

	private static final String BON_MOT_DE_PASSE = "Bonjour@123456";

	// ---- Tests inscription ----

	// Test 1 - Inscription OK
	@Test
	void testInscriptionOK() {
		assertDoesNotThrow(() -> authService.register("nouveau@example.com", BON_MOT_DE_PASSE));
	}

	// Test 2 - Email vide
	@Test
	void testEmailVide() {
		assertThrows(InvalidInputException.class, () ->
				authService.register("", BON_MOT_DE_PASSE));
	}

	// Test 3 - Format email incorrect
	@Test
	void testEmailFormatIncorrect() {
		assertThrows(InvalidInputException.class, () ->
				authService.register("pasunemail", BON_MOT_DE_PASSE));
	}

	// Test 4 - Mot de passe trop court
	@Test
	void testMotDePasseTropCourt() {
		assertThrows(InvalidInputException.class, () ->
				authService.register("test@example.com", "ab"));
	}

	// Test 5 - Email déjà existant
	@Test
	void testEmailDejaExistant() {
		authService.register("doublon@example.com", BON_MOT_DE_PASSE);
		assertThrows(ResourceConflictException.class, () ->
				authService.register("doublon@example.com", BON_MOT_DE_PASSE));
	}

	// ---- Tests login HMAC ----

	private String buildHmac(String email, String nonce, long timestamp, String password) throws Exception {
		String message = email + ":" + nonce + ":" + timestamp;
		return hmacService.compute(password, message);
	}

	// Test 6 - Login OK avec HMAC valide
	@Test
	void testLoginOK() throws Exception {
		authService.register("login@example.com", BON_MOT_DE_PASSE);
		String nonce = UUID.randomUUID().toString();
		long timestamp = Instant.now().getEpochSecond();
		String hmac = buildHmac("login@example.com", nonce, timestamp, BON_MOT_DE_PASSE);
		String token = loginService.login("login@example.com", nonce, timestamp, hmac);
		assertNotNull(token);
	}

	// Test 7 - Login KO HMAC invalide
	@Test
	void testLoginHmacInvalide() {
		authService.register("test2@example.com", BON_MOT_DE_PASSE);
		String nonce = UUID.randomUUID().toString();
		long timestamp = Instant.now().getEpochSecond();
		assertThrows(AuthenticationFailedException.class, () ->
				loginService.login("test2@example.com", nonce, timestamp, "hmac-faux"));
	}

	// Test 8 - Login KO email inconnu
	@Test
	void testLoginEmailInconnu() {
		String nonce = UUID.randomUUID().toString();
		long timestamp = Instant.now().getEpochSecond();
		assertThrows(AuthenticationFailedException.class, () ->
				loginService.login("inconnu@example.com", nonce, timestamp, "hmac"));
	}

	// Test 9 - Login KO timestamp expiré
	@Test
	void testLoginTimestampExpire() throws Exception {
		authService.register("expire@example.com", BON_MOT_DE_PASSE);
		String nonce = UUID.randomUUID().toString();
		long timestamp = Instant.now().getEpochSecond() - 120; // 2 minutes dans le passé
		String hmac = buildHmac("expire@example.com", nonce, timestamp, BON_MOT_DE_PASSE);
		assertThrows(AuthenticationFailedException.class, () ->
				loginService.login("expire@example.com", nonce, timestamp, hmac));
	}

	// Test 10 - Login KO nonce déjà utilisé
	@Test
	void testLoginNonceDejaUtilise() throws Exception {
		authService.register("nonce@example.com", BON_MOT_DE_PASSE);
		String nonce = UUID.randomUUID().toString();
		long timestamp = Instant.now().getEpochSecond();
		String hmac = buildHmac("nonce@example.com", nonce, timestamp, BON_MOT_DE_PASSE);
		loginService.login("nonce@example.com", nonce, timestamp, hmac);
		assertThrows(AuthenticationFailedException.class, () ->
				loginService.login("nonce@example.com", nonce, timestamp, hmac));
	}

	// Test 11 - Accès /api/me sans token
	@Test
	void testAccesMeSansToken() {
		assertTrue(authService.getUserByToken("token-invalide").isEmpty());
	}

	// Test 12 - Accès /api/me après login OK
	@Test
	void testAccesMeApresLogin() throws Exception {
		authService.register("me@example.com", BON_MOT_DE_PASSE);
		String nonce = UUID.randomUUID().toString();
		long timestamp = Instant.now().getEpochSecond();
		String hmac = buildHmac("me@example.com", nonce, timestamp, BON_MOT_DE_PASSE);
		String token = loginService.login("me@example.com", nonce, timestamp, hmac);
		assertTrue(authService.getUserByToken(token).isPresent());
	}

	// Test 13 - Comparaison temps constant OK
	@Test
	void testComparaisonTempsConstantOK() {
		assertTrue(hmacService.compareConstantTime("abc123", "abc123"));
	}

	// Test 14 - Comparaison temps constant KO
	@Test
	void testComparaisonTempsConstantKO() {
		assertFalse(hmacService.compareConstantTime("abc123", "xyz999"));
	}

	// Test 15 - Token émis valide après login
	@Test
	void testTokenEmisValide() throws Exception {
		authService.register("token@example.com", BON_MOT_DE_PASSE);
		String nonce = UUID.randomUUID().toString();
		long timestamp = Instant.now().getEpochSecond();
		String hmac = buildHmac("token@example.com", nonce, timestamp, BON_MOT_DE_PASSE);
		String token = loginService.login("token@example.com", nonce, timestamp, hmac);
		assertNotNull(token);
		assertFalse(token.isEmpty());
	}
}