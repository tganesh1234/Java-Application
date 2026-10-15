
package com.example.demo;

import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

@Service
public class AwsSecretService {

    private final SecretsManagerClient client;

    public AwsSecretService() {
        this.client = SecretsManagerClient.builder()
                .region(Region.US_EAST_2)
                .build();
    }

    public String getAppSecretId() {
        return client.getSecretValue(
                GetSecretValueRequest.builder()
                        .secretId("java-application/app-secret-id")
                        .build()
        ).secretString();
    }
}
