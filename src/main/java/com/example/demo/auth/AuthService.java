package com.example.demo.auth;

import com.example.demo.auth.AuthDtos.AuthResponse;
import com.example.demo.auth.AuthDtos.LoginRequest;
import com.example.demo.auth.AuthDtos.SignupRequest;
import com.example.demo.entity.Role;
import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;

	public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
			AuthenticationManager authenticationManager, JwtService jwtService) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		this.jwtService = jwtService;
	}

	/**
	 * The existsByEmail check gives a clean 409; the unique constraint is the real
	 * guarantee under concurrency, and ApiExceptionHandler maps its violation to 409 too.
	 */
	@Transactional
	public AuthResponse signup(SignupRequest request) {
		String email = normalise(request.email());
		if (userRepository.existsByEmail(email)) {
			throw new EmailAlreadyUsedException(email);
		}

		User user = new User(email, passwordEncoder.encode(request.password()), Role.USER);
		userRepository.save(user);

		return new AuthResponse(jwtService.generateToken(email), email);
	}

	/**
	 * Delegates to AuthenticationManager so password comparison and the
	 * BadCredentialsException on failure follow Spring Security's own rules.
	 */
	public AuthResponse login(LoginRequest request) {
		String email = normalise(request.email());
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(email, request.password()));

		return new AuthResponse(jwtService.generateToken(email), email);
	}

	/** Emails are case-insensitive in practice; store and compare them lowercased. */
	private String normalise(String email) {
		return email.trim().toLowerCase();
	}
}
