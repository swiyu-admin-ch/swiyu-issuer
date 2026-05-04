package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.core.trust.client.api.TrustStatementApi;
import ch.admin.bj.swiyu.core.trust.client.invoker.ApiClient;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Base64;

/**
 * Spring configuration for the Trust Registry sidechannel API client.
 *
 * <p>Only active when {@code swiyu.trust-registry.api-url} is configured.
 * Uses HTTP Basic Auth (customer key / secret) to authenticate against the trust registry.</p>
 */
@Slf4j
@Configuration
@AllArgsConstructor
@ConditionalOnProperty(prefix = "swiyu.trust-registry", name = "api-url")
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
        var credentials = props.customerKey() + ":" + props.customerSecret();
        var encoded = Base64.getEncoder().encodeToString(credentials.getBytes());

        var reConfigured = webClient.mutate()
                .filter((request, next) -> next.exchange(
                        ClientRequest.from(request)
                                .header(HttpHeaders.AUTHORIZATION, "Basic " + encoded)
                                .build()))
                .build();

        var client = new ApiClient(reConfigured);
        client.setBasePath(props.apiUrl().toExternalForm());
        log.info("Initializing Trust Registry sidechannel API client for {}", props.apiUrl());
        return client;
    }

    /**
     * Exposes the generated {@link TrustStatementApi} as a Spring bean.
     *
     * @param trustRegistryApiClient the configured API client
     * @return the Trust Statement API facade
     */
    @Bean
    public TrustStatementApi trustStatementApi(ApiClient trustRegistryApiClient) {
        return new TrustStatementApi(trustRegistryApiClient);
    }
}

