package ch.admin.bit.eid.issuer_management.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
@AllArgsConstructor
public class ApiClientConfiguration {
    private StatusListProperties statusListProperties;

    @Bean
    public RestClient controllerRestClient() {
        return RestClient.create(statusListProperties.getControllerUrl());
    }
}
