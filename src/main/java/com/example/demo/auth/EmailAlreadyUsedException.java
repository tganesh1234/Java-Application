package com.example.demo.auth;

public class EmailAlreadyUsedException extends RuntimeException {

	public EmailAlreadyUsedException(String email) {
		super("Email already registered: " + email);
	}
}
