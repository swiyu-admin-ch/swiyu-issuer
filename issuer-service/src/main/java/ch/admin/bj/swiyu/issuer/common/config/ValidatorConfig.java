package ch.admin.bj.swiyu.issuer.common.config;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.UrlRestriction;
import ch.admin.bj.swiyu.sdjwtvalidator.SdJwtVcValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for the centralized swiyu JWT and SD-JWT VC validator beans.
 *
 * <p>Instantiates {@link DidJwtValidator} and {@link SdJwtVcValidator} as singleton beans,
 * configured with the Base Registry allowlist defined in {@link ApplicationProperties#getBaseRegistryAllowedHosts()}.
 * The allowlist prevents CSRF and "phone home" attacks by rejecting DID URLs whose host is
 * not explicitly permitted.</p>
 */
@Configuration
@RequiredArgsConstructor
public class ValidatorConfig {

    private final ApplicationProperties applicationProperties;

    /**
     * Creates a {@link DidJwtValidator} bean enforcing the configured Base Registry allowlist.
     *
     * @return configured {@code DidJwtValidator} instance
     */
    @Bean
    public DidJwtValidator didJwtValidator() {
        return new DidJwtValidator(new UrlRestriction(applicationProperties.getAcceptedIdentifierHosts()));
    }

    /**
     * Creates a {@link SdJwtVcValidator} bean that delegates DID-based signature verification
     * to the {@link DidJwtValidator} and enforces the Swiss Profile SD-JWT VC rules.
     *
     * @param didJwtValidator the underlying DID-based JWT validator
     * @return configured {@code SdJwtVcValidator} instance
     */
    @Bean
    public SdJwtVcValidator sdJwtVcValidator(DidJwtValidator didJwtValidator) {
        return new SdJwtVcValidator(didJwtValidator);
    }
}

