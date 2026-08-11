package com.example.demo.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;

class JwtServiceTests {

	// Any base64 256-bit value; independent of the application's real secret.
	private static final String SECRET = "Y6ZYlhtc39Nk+AcNQltRaTvoC1dUK4dfqwtRe5R1gNs=";

	// Must also decode to a full 256 bits, or jjwt rejects it as a weak key.
	private static final String OTHER_SECRET = "8u0oiX9FCtaxqmvkguD4JiDorF3VMTFBEwSZpvgi85I=";

	@Test
	void roundTripsSubject() {
		JwtService service = new JwtService(SECRET, 60_000);

		String token = service.generateToken("user@example.com");

		assertThat(service.extractSubject(token)).isEqualTo("user@example.com");
	}

	@Test
	void rejectsExpiredToken() {
		// Negative lifetime means the token expires before it is even returned.
		JwtService service = new JwtService(SECRET, -1_000);

		String token = service.generateToken("user@example.com");

		assertThatThrownBy(() -> service.extractSubject(token))
				.isInstanceOf(JwtException.class);
	}

	@Test
	void rejectsTokenSignedWithDifferentKey() {
		String foreignToken = new JwtService(OTHER_SECRET, 60_000).generateToken("user@example.com");
		JwtService service = new JwtService(SECRET, 60_000);

		assertThatThrownBy(() -> service.extractSubject(foreignToken))
				.isInstanceOf(JwtException.class);
	}

	@Test
	void rejectsGarbageToken() {
		JwtService service = new JwtService(SECRET, 60_000);

		assertThatThrownBy(() -> service.extractSubject("not-a-jwt"))
				.isInstanceOf(JwtException.class);
	}

	@Test
	void rejectsBlankToken() {
		JwtService service = new JwtService(SECRET, 60_000);

		assertThatThrownBy(() -> service.extractSubject(""))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
