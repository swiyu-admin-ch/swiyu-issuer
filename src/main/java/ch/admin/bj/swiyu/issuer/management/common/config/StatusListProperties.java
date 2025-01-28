package ch.admin.bj.swiyu.issuer.management.common.config;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Slf4j
@Configuration
@Validated
@Data
@ConfigurationProperties(prefix = "application.status-list")
public class StatusListProperties {
    private String privateKey;
    private String verificationMethod;
    @NotNull
    private String keyManagementMethod;
    private HSMProperties hsm;

}
