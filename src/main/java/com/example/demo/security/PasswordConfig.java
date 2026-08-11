package com.example.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Separate from SecurityConfig so that AuthService can inject the encoder without
 * forming SecurityConfig -> UserDetailsService -> PasswordEncoder -> SecurityConfig.
 * Boot 3 disables circular references, so that cycle fails the context outright.
 */
@Configuration
public class PasswordConfig {

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
