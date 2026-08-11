package com.example.demo.web;

import com.example.demo.auth.AuthDtos.MeResponse;
import com.example.demo.security.UserPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Protected endpoint proving the token actually authenticates a request. */
@RestController
@RequestMapping("/api")
public class SecureController {

	@GetMapping("/me")
	public MeResponse me(@AuthenticationPrincipal UserPrincipal principal) {
		String role = principal.getAuthorities().iterator().next().getAuthority();
		return new MeResponse(principal.getEmail(), role);
	}
}
