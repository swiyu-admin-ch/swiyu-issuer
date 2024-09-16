package ch.admin.bit.eid.issuer_management.config;

import ch.admin.bit.eid.issuer_management.exceptions.ConfigurationException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.client.RestClient;

@Slf4j
@Configuration
@Validated
@Data
@ConfigurationProperties(prefix = "application.status-list")
public class StatusListConfig {
    private String controllerUrl;
    private String privateKey;
    private JWK statusListKey;

    @PostConstruct
    public void init() {
        try {
            statusListKey = JWK.parseFromPEMEncodedObjects(privateKey);
        } catch (JOSEException e) {
            log.error("Status List Signing key can not be parsed", e);
            throw new ConfigurationException("Status List Signing key can not be parsed");
        }
    }


    @Bean
    public RestClient controllerRestClient() {
        return RestClient.create(controllerUrl);
    }
}
