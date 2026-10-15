package com.example.demo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class HelloController {

    private final AwsSecretService awsSecretService;

    public HelloController(AwsSecretService awsSecretService) {
        this.awsSecretService = awsSecretService;
    }

    @GetMapping("/hello")
    public String hello() {
        return "Spring Boot is running";
    }

    @GetMapping("/data")
    public String getData() {
        String secret = awsSecretService.getAppSecretId();

        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(
                "AWS Secrets Manager returned an empty secret"
            );
        }

        return "Secret retrieved successfully from AWS Secrets Manager";
    }
}
