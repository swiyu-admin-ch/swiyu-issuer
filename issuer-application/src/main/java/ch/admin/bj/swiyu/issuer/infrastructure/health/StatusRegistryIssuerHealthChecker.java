package ch.admin.bj.swiyu.issuer.infrastructure.health;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;
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
public class StatusRegistryIssuerHealthChecker extends CachedHealthChecker {

    private static final Logger log = LoggerFactory.getLogger(StatusRegistryIssuerHealthChecker.class);
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${swiyu.status-registry.token-url}")
    private String tokenUrl;

    @Value("${swiyu.status-registry.api-url}")
    private String apiUrl;

    @Value("${swiyu.business-partner-id}")
    private String partnerId;

    /**
     * Executes the reachability checks and enriches the {@link Health.Builder} with details.
     * Marks DOWN if any endpoint is unreachable.
     */
    @Override
    protected void performCheck(Health.Builder builder) {
        log.info("Checking Status Registry Issuer endpoints");

        try {
            restTemplate.getForEntity(tokenUrl, String.class);
            builder.withDetail("tokenUrl", "reachable");
        } catch (Exception e) {
            builder.down().withDetail("tokenUrl", "unreachable: " + e.getMessage());
        }

        try {
            restTemplate.getForEntity(apiUrl, String.class);
            builder.withDetail("apiUrl", "reachable");
        } catch (Exception e) {
            builder.down().withDetail("apiUrl", "unreachable: " + e.getMessage());
        }

        builder.withDetail("partnerId", partnerId);
    }
}
