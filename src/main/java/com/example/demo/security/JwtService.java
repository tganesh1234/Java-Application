package com.example.demo.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

	/**
	 * Must be SecretKey, not java.security.Key: JwtParserBuilder.verifyWith only has
	 * SecretKey and PublicKey overloads, so a Key field does not compile.
	 */
	private final SecretKey key;

	private final long expirationMs;

	public JwtService(@Value("${app.jwt.secret}") String base64Secret,
			@Value("${app.jwt.expiration-ms}") long expirationMs) {
		// The property holds base64. Without decoding, the ASCII bytes of the base64 text
		// become the key material - still 256-bit, so it runs, but signs with the wrong key.
		this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
		this.expirationMs = expirationMs;
	}

	public String generateToken(String email) {
		Date now = new Date();
		return Jwts.builder()
				.subject(email)
				.issuedAt(now)
				.expiration(new Date(now.getTime() + expirationMs))
				.signWith(key)
				.compact();
	}

	/**
	 * @throws io.jsonwebtoken.JwtException if the token is malformed, tampered or expired
	 * @throws IllegalArgumentException if the token is null or blank
	 */
	public String extractSubject(String token) {
		return Jwts.parser()
				.verifyWith(key)
				.build()
				.parseSignedClaims(token)
				.getPayload()
				.getSubject();
	}
}
