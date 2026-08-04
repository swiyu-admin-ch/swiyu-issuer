package ch.admin.bj.swiyu.issuer.common.config;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.UrlRestriction;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@AllArgsConstructor
public class AttestationConfig {

    private final ApplicationProperties applicationProperties;

    /**
     * Creates a {@link DidJwtValidator} restricted to the configured attestation hosts.
     *
     * <p>The allowlist is derived from the {@code application.accepted-registry-hosts} property,
     * ensuring that trust statement JWTs are only accepted when their {@code kid} resolves
     * to the same host as the configured TMS or Status Registry endpoint.</p>
     *
     * @return the {@link DidJwtValidator} bean named {@code trustStatementDidJwtValidator}
     * @throws IllegalArgumentException if the configured {@code api-url} is malformed
     */
    @Bean
    @Primary
    public DidJwtValidator jwtValidator() {
        Set<String> hosts = new HashSet<>(applicationProperties.getAcceptedRegistryHosts());
        log.info("Configuring trust statement JWT validator with allowed host: {}", hosts);
        return new DidJwtValidator(new UrlRestriction(hosts));
    }
}
