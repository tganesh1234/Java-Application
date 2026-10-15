package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HelloController {

	@Value("${app.secret-id}")
	private String id;

	@GetMapping("/hello")
	public String hello() {
		System.out.println("Secret ID: " + id);
		return "Spring Boot is running";
	}
	@GetMapping("/data")
	public String getMethodName() {
		return "id" + id;
	}
	
}
