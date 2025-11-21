package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.Health;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * Health checker for the external Status Registry integration.
 * <p>
 * Performs lightweight reachability probes (HTTP GET) against the configured token and API URLs.
 * If either endpoint throws an exception (client/server error or connection issue), the overall
 * health for this checker is marked DOWN and details include the failing endpoint message.
 * Always adds the configured business partner id as a detail.
 * </p>
 */
@Component
@RequiredArgsConstructor
public class StatusRegistryIssuerHealthChecker extends CachedHealthChecker {

    private static final Logger log = LoggerFactory.getLogger(StatusRegistryIssuerHealthChecker.class);
    private final RestTemplate restTemplate = new RestTemplate();

    private final SwiyuProperties swiyuProperties;

    /**
     * Executes the reachability checks and enriches the {@link Health.Builder} with details.
     * Marks DOWN if any endpoint is unreachable.
     */
    @Override
    protected void performCheck(Health.Builder builder) {
        log.info("Checking Status Registry Issuer endpoints");

        String tokenUrl = swiyuProperties.statusRegistry().tokenUrl().toExternalForm();
        String apiUrl = swiyuProperties.statusRegistry().apiUrl().toExternalForm();
        String partnerId = swiyuProperties.businessPartnerId().toString();

        try {
            assertServiceReachable(tokenUrl);
            builder.withDetail("tokenUrl", "reachable");
        } catch (IllegalStateException | RestClientException e) {
            builder.down().withDetail("tokenUrl", "unreachable: " + e.getMessage());
        }

        try {
            assertServiceReachable(apiUrl);
            builder.withDetail("apiUrl", "reachable");
        } catch (IllegalStateException | RestClientException e) {
            builder.down().withDetail("apiUrl", "unreachable: " + e.getMessage());
        }

        builder.withDetail("partnerId", partnerId);
    }

    /**
     * Checks if the given service endpoint is reachable via HTTP HEAD request.
     * <p>
     * Treats 2xx and 4xx responses as reachable (service responds).
     * Throws an exception for 5xx errors or network failures.
     * </p>
     *
     * @param url the endpoint URL to check
     * @throws IllegalStateException if the service returns a 5xx error
     */
    private void assertServiceReachable(String url) {
        try {
            final ResponseEntity<Void> response = restTemplate.exchange(
                    url,
                    HttpMethod.HEAD,
                    null,
                    Void.class
            );
            if (response.getStatusCode().is5xxServerError()) {
                throw new IllegalStateException("Server returned 5xx: " + response.getStatusCode());
            }
        } catch (HttpStatusCodeException e) {
            if (e.getStatusCode().is4xxClientError()) {
                return;
            }
            throw e;
        }
    }
}
