package com.example.demo.security;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Not a @Component on purpose: that would also auto-register it in the plain servlet
 * chain, running it twice per request. SecurityConfig constructs it instead.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final String BEARER_PREFIX = "Bearer ";

	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;

	public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
		this.jwtService = jwtService;
		this.userDetailsService = userDetailsService;
	}

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response, @NonNull FilterChain chain)
			throws ServletException, IOException {

		String header = request.getHeader("Authorization");

		// No bearer token: stay anonymous. Covers /hello, the auth endpoints and the
		// H2 console. Authorization decides whether that is acceptable.
		if (header == null || !header.startsWith(BEARER_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}

		if (SecurityContextHolder.getContext().getAuthentication() != null) {
			chain.doFilter(request, response);
			return;
		}

		try {
			String token = header.substring(BEARER_PREFIX.length());
			String email = jwtService.extractSubject(token);
			UserDetails user = userDetailsService.loadUserByUsername(email);

			var authentication = new UsernamePasswordAuthenticationToken(
					user, null, user.getAuthorities());
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		catch (JwtException | IllegalArgumentException | UsernameNotFoundException ex) {
			// Never rethrow: an exception escaping here leaves the security chain and
			// surfaces as 500. Staying anonymous lets the entry point return a clean 401.
			SecurityContextHolder.clearContext();
		}

		chain.doFilter(request, response);
	}
}
