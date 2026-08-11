package com.example.demo.web;

import com.example.demo.auth.EmailAlreadyUsedException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Without this, a duplicate email surfaces as a 500 from the DB constraint and a wrong
 * password as a 500 from the uncaught BadCredentialsException.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

	@ExceptionHandler(EmailAlreadyUsedException.class)
	ResponseEntity<Map<String, Object>> handleEmailTaken(EmailAlreadyUsedException ex) {
		return body(HttpStatus.CONFLICT, ex.getMessage());
	}

	/** Backstop for the check-then-insert race that existsByEmail cannot close. */
	@ExceptionHandler(DataIntegrityViolationException.class)
	ResponseEntity<Map<String, Object>> handleConstraintViolation(DataIntegrityViolationException ex) {
		return body(HttpStatus.CONFLICT, "Email already registered");
	}

	/** Same 401 for both, so a probe cannot tell unknown email from wrong password. */
	@ExceptionHandler({ BadCredentialsException.class, UsernameNotFoundException.class })
	ResponseEntity<Map<String, Object>> handleBadCredentials(Exception ex) {
		return body(HttpStatus.UNAUTHORIZED, "Invalid email or password");
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
		Map<String, Object> response = base(HttpStatus.BAD_REQUEST, "Validation failed");
		Map<String, String> fields = new LinkedHashMap<>();
		ex.getBindingResult().getFieldErrors()
				.forEach(error -> fields.put(error.getField(), error.getDefaultMessage()));
		response.put("fields", fields);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
	}

	private ResponseEntity<Map<String, Object>> body(HttpStatus status, String message) {
		return ResponseEntity.status(status).body(base(status, message));
	}

	private Map<String, Object> base(HttpStatus status, String message) {
		Map<String, Object> response = new LinkedHashMap<>();
		response.put("status", status.value());
		response.put("error", status.getReasonPhrase());
		response.put("message", message);
		return response;
	}
}
