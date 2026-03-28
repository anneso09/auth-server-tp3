package com.example.auth;

import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
class AuthApplicationTests {

	@Autowired
	private AuthService authService;

	private static final String BON_MOT_DE_PASSE = "Bonjour@123456";

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

	// Test 6 - Login OK
	@Test
	void testLoginOK() {
		authService.register("login@example.com", BON_MOT_DE_PASSE);
		String token = authService.login("login@example.com", BON_MOT_DE_PASSE);
		assertNotNull(token);
	}

	// Test 7 - Login KO mauvais mot de passe
	@Test
	void testLoginMauvaisMotDePasse() {
		authService.register("test2@example.com", BON_MOT_DE_PASSE);
		assertThrows(AuthenticationFailedException.class, () ->
				authService.login("test2@example.com", "mauvais"));
	}

	// Test 8 - Login KO email inconnu
	@Test
	void testLoginEmailInconnu() {
		assertThrows(AuthenticationFailedException.class, () ->
				authService.login("inconnu@example.com", BON_MOT_DE_PASSE));
	}

	// Test 9 - Accès /api/me sans token
	@Test
	void testAccesMeSansToken() {
		assertTrue(authService.getUserByToken("token-invalide").isEmpty());
	}

	// Test 10 - Accès /api/me après login
	@Test
	void testAccesMeApresLogin() {
		authService.register("me@example.com", BON_MOT_DE_PASSE);
		String token = authService.login("me@example.com", BON_MOT_DE_PASSE);
		assertTrue(authService.getUserByToken(token).isPresent());
	}
}