package com.example.demo.security;

import com.example.demo.entity.User;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * UserDetails adapter over the User entity. Authorities are snapshotted in the
 * constructor so nothing is lazily loaded later - spring.jpa.open-in-view is false,
 * so a lazy access during authorization would throw.
 */
public class UserPrincipal implements UserDetails {

	private final Long id;
	private final String email;
	private final String passwordHash;
	private final List<GrantedAuthority> authorities;

	public UserPrincipal(User user) {
		this.id = user.getId();
		this.email = user.getEmail();
		this.passwordHash = user.getPasswordHash();
		this.authorities = List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
	}

	public Long getId() {
		return id;
	}

	public String getEmail() {
		return email;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return passwordHash;
	}

	/** Email is the username: this app has no separate username concept. */
	@Override
	public String getUsername() {
		return email;
	}
}
