package com.example.demo.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class AuthDtos {

	private AuthDtos() {
	}

	/**
	 * Records generate toString(), so never log these - the password would be exposed.
	 */
	public record SignupRequest(
			@NotBlank @Email String email,
			@NotBlank @Size(min = 8, max = 100) String password) {
	}

	public record LoginRequest(
			@NotBlank @Email String email,
			@NotBlank String password) {
	}

	/** Response never carries the password hash. */
	public record AuthResponse(String token, String email) {
	}

	public record MeResponse(String email, String role) {
	}
}
