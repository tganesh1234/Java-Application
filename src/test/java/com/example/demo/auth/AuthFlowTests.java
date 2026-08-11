package com.example.demo.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.demo.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowTests {

	private static final String EMAIL = "user@example.com";
	private static final String PASSWORD = "password123";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@BeforeEach
	void clearUsers() {
		// The in-memory DB is shared across tests in this class.
		userRepository.deleteAll();
	}

	@Test
	void helloRemainsPublic() throws Exception {
		mockMvc.perform(get("/hello"))
				.andExpect(status().isOk())
				.andExpect(content().string("Spring Boot is running"));
	}

	@Test
	void protectedEndpointReturns401WhenAnonymous() throws Exception {
		mockMvc.perform(get("/api/me"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void signupReturns201WithToken() throws Exception {
		mockMvc.perform(signupRequest(EMAIL, PASSWORD))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.email").value(EMAIL))
				.andExpect(jsonPath("$.token").isNotEmpty());
	}

	@Test
	void signupStoresBcryptHashNotPlaintext() throws Exception {
		mockMvc.perform(signupRequest(EMAIL, PASSWORD)).andExpect(status().isCreated());

		String stored = userRepository.findByEmail(EMAIL).orElseThrow().getPasswordHash();

		assertThat(stored).isNotEqualTo(PASSWORD).startsWith("$2");
		assertThat(passwordEncoder.matches(PASSWORD, stored)).isTrue();
	}

	@Test
	void duplicateSignupReturns409() throws Exception {
		mockMvc.perform(signupRequest(EMAIL, PASSWORD)).andExpect(status().isCreated());

		mockMvc.perform(signupRequest(EMAIL, PASSWORD))
				.andExpect(status().isConflict());
	}

	@Test
	void signupRejectsInvalidEmailAndShortPassword() throws Exception {
		mockMvc.perform(signupRequest("not-an-email", PASSWORD))
				.andExpect(status().isBadRequest());

		mockMvc.perform(signupRequest(EMAIL, "short"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void loginReturnsTokenForCorrectPassword() throws Exception {
		mockMvc.perform(signupRequest(EMAIL, PASSWORD)).andExpect(status().isCreated());

		mockMvc.perform(loginRequest(EMAIL, PASSWORD))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.token").isNotEmpty());
	}

	@Test
	void loginReturns401ForWrongPassword() throws Exception {
		mockMvc.perform(signupRequest(EMAIL, PASSWORD)).andExpect(status().isCreated());

		mockMvc.perform(loginRequest(EMAIL, "wrongpassword"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void loginReturns401ForUnknownEmail() throws Exception {
		mockMvc.perform(loginRequest("nobody@example.com", PASSWORD))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void tokenFromSignupGrantsAccessToProtectedEndpoint() throws Exception {
		String token = extractToken(mockMvc.perform(signupRequest(EMAIL, PASSWORD))
				.andExpect(status().isCreated())
				.andReturn().getResponse().getContentAsString());

		mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.email").value(EMAIL))
				.andExpect(jsonPath("$.role").value("ROLE_USER"));
	}

	/** A malformed token must not escape the filter as a 500. */
	@Test
	void garbageTokenReturns401NotServerError() throws Exception {
		mockMvc.perform(get("/api/me").header("Authorization", "Bearer garbage"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void emptyBearerTokenReturns401() throws Exception {
		mockMvc.perform(get("/api/me").header("Authorization", "Bearer "))
				.andExpect(status().isUnauthorized());
	}

	/** Token valid in shape and signature, but the user no longer exists. */
	@Test
	void tokenForDeletedUserReturns401() throws Exception {
		String token = extractToken(mockMvc.perform(signupRequest(EMAIL, PASSWORD))
				.andExpect(status().isCreated())
				.andReturn().getResponse().getContentAsString());

		userRepository.deleteAll();

		mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void emailIsNormalisedSoLoginIsCaseInsensitive() throws Exception {
		mockMvc.perform(signupRequest("User@Example.com", PASSWORD))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.email").value(EMAIL));

		mockMvc.perform(loginRequest("USER@EXAMPLE.COM", PASSWORD))
				.andExpect(status().isOk());
	}

	private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder signupRequest(
			String email, String password) throws Exception {
		return post("/api/auth/signup")
				.contentType(MediaType.APPLICATION_JSON)
				.content(json(email, password));
	}

	private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder loginRequest(
			String email, String password) throws Exception {
		return post("/api/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content(json(email, password));
	}

	private String json(String email, String password) throws Exception {
		return objectMapper.writeValueAsString(
				new AuthDtos.SignupRequest(email, password));
	}

	private String extractToken(String responseBody) throws Exception {
		JsonNode node = objectMapper.readTree(responseBody);
		return node.get("token").asText();
	}
}
