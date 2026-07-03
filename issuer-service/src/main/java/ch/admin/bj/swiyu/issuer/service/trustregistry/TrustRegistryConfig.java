package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.core.trust.client.api.TrustProtocol20Api;
import ch.admin.bj.swiyu.core.trust.client.invoker.ApiClient;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.UrlRestriction;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Set;

/**
 * Spring configuration for the Trust Registry sidechannel API client.
 *
 * <p>Only active when {@code swiyu.trust-registry.api-url} is configured.
 * Uses HTTP Basic Auth (customer key / secret) to authenticate against the trust registry.</p>
 */
@Slf4j
@Configuration
@AllArgsConstructor
@ConditionalOnExpression("'${swiyu.trust-registry.api-url:}'.length() > 0")
public class TrustRegistryConfig {

    private final SwiyuProperties swiyuProperties;
    private final WebClient webClient;

    /**
     * Creates the WebClient-backed {@link ApiClient} for the Trust Registry sidechannel,
     * injecting HTTP Basic Auth credentials from configuration.
     *
     * @return configured {@link ApiClient}
     */
    @Bean
    public ApiClient trustRegistryApiClient() {
        var props = swiyuProperties.trustRegistry();

        ApiClient client = new ApiClient(webClient);
        client.setBasePath(props.apiUrl().toExternalForm());
        log.info("Initializing Trust Registry sidechannel API client for {}", props.apiUrl());
        return client;
    }

    /**
     * Exposes the generated {@link TrustProtocol20Api} as a Spring bean.
     *
     * @param trustRegistryApiClient the configured API client
     * @return the Trust Protocol 2.0 API facade
     */
    @Bean
    public TrustProtocol20Api trustProtocol20Api(ApiClient trustRegistryApiClient) {
        return new TrustProtocol20Api(trustRegistryApiClient);
    }

    /**
     * Creates a {@link DidJwtValidator} restricted to the Trust Registry's host.
     *
     * <p>The allowlist is derived from the configured {@code swiyu.trust-registry.api-url} host,
     * so that Trust Statement JWTs whose {@code kid} resolves to a different host are rejected.</p>
     *
     * @return a {@link DidJwtValidator} scoped to the Trust Registry's DID domain
     */
    @Bean
    public DidJwtValidator trustStatementDidJwtValidator() {
        String trustRegistryHost = swiyuProperties.trustRegistry().apiUrl().getHost();
        log.info("Configuring trust statement JWT validator with allowed DID host: {}", trustRegistryHost);
        return new DidJwtValidator(new UrlRestriction(Set.of(trustRegistryHost)));
    }
}
