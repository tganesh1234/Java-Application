package com.example.demo.security;

import com.example.demo.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Depends on UserRepository only - never on PasswordEncoder. Password comparison is
 * DaoAuthenticationProvider's job, and injecting the encoder here would close a
 * circular dependency that Boot 3 refuses to start.
 */
@Service
public class AppUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	public AppUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		return userRepository.findByEmail(email)
				.map(UserPrincipal::new)
				.orElseThrow(() -> new UsernameNotFoundException("No user with email " + email));
	}
}
