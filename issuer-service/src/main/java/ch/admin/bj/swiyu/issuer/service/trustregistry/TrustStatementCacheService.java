package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.core.trust.client.api.TrustStatementApi;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Service that fetches and caches Trust Statements (idTS and piaTS) from the
 * Trust Registry sidechannel API.
 *
 * <p>Each trust statement JWT is cached until its individual {@code exp} claim expires,
 * implementing dynamic per-entry TTL via Caffeine's {@link Expiry} interface.
 * This ensures that revoked or refreshed trust statements are picked up without delay
 * once the current statement expires.</p>
 *
 * <p>The issuer DID is passed per call to correctly support {@code ConfigurationOverride},
 * which allows individual credentials to be issued under a different DID than the default
 * {@code application.issuer-id}. Cache entries are keyed by the actual issuer DID used.</p>
 *
 * <p>Only active when a {@link TrustStatementApi} bean is present
 * (i.e. {@code swiyu.trust-registry.api-url} is configured).</p>
 */
@Slf4j
@Service
@ConditionalOnBean(TrustStatementApi.class)
public class TrustStatementCacheService {

    private final TrustStatementApi trustStatementApi;
    private final ObjectMapper objectMapper;
    private final long maxCacheSize;
    private final long clockSkewBufferSeconds;

    /** Caffeine cache with dynamic per-entry TTL derived from each JWT's {@code exp} claim.
     * Note: {@code @Cacheable} is intentionally NOT used here because Spring's cache abstraction
     * only supports a static TTL per cache, not a dynamic per-entry TTL. Caffeine is used
     * directly to implement exp-based eviction as required by the trust statement lifecycle.
     */
    private final Cache<String, String> idTsCache;
    private final Cache<String, String> piaTsCache;

    /**
     * Creates a new {@code TrustStatementCacheService}.
     *
     * @param trustStatementApi generated API client for the trust sidechannel
     * @param swiyuProperties   application properties providing cache tuning parameters
     * @param objectMapper      Jackson mapper for JWT payload parsing
     */
    public TrustStatementCacheService(TrustStatementApi trustStatementApi,
                                      SwiyuProperties swiyuProperties,
                                      ObjectMapper objectMapper) {
        this.trustStatementApi = trustStatementApi;
        this.objectMapper = objectMapper;
        this.maxCacheSize = swiyuProperties.trustRegistry().maxCacheSize();
        this.clockSkewBufferSeconds = swiyuProperties.trustRegistry().clockSkewBufferSeconds();
        this.idTsCache = buildCache();
        this.piaTsCache = buildCache();
    }

    /**
     * Returns the cached Identity Trust Statement (idTS) JWT for the given issuer DID,
     * fetching it from the trust registry if not yet cached or already expired.
     *
     * <p>Use the effective issuer DID as resolved via
     * {@code ConfigurationOverride.issuerDidOrDefault(applicationProperties.getIssuerId())}.</p>
     *
     * @param issuerDid the effective issuer DID for which to retrieve the trust statement
     * @return the idTS JWT string, or {@code null} if unavailable
     */
    @Nullable
    public String getIdentityTrustStatement(String issuerDid) {
        return idTsCache.get(issuerDid, this::fetchIdentityTrustStatement);
    }

    /**
     * Returns the cached Protected Issuance Authorization Trust Statement (piaTS) JWT
     * for the given issuer DID, fetching it from the trust registry if not yet cached
     * or already expired.
     *
     * <p>Use the effective issuer DID as resolved via
     * {@code ConfigurationOverride.issuerDidOrDefault(applicationProperties.getIssuerId())}.</p>
     *
     * @param issuerDid the effective issuer DID for which to retrieve the trust statement
     * @return the piaTS JWT string, or {@code null} if unavailable
     */
    @Nullable
    public String getProtectedIssuanceAuthorizationTrustStatement(String issuerDid) {
        return piaTsCache.get(issuerDid, this::fetchProtectedIssuanceAuthorizationTrustStatement);
    }

    @Nullable
    private String fetchIdentityTrustStatement(String issuerDid) {
        try {
            var response = trustStatementApi.getIdentityTrustStatements(issuerDid, true).block();
            return extractFirstJwt(response != null ? response.getContent() : null, "idTS", issuerDid);
        } catch (Exception e) {
            log.warn("Failed to fetch identity trust statement (idTS) for issuer {}: {}", issuerDid, e.getMessage());
            return null;
        }
    }

    @Nullable
    private String fetchProtectedIssuanceAuthorizationTrustStatement(String issuerDid) {
        try {
            var response = trustStatementApi.getProtectedIssuanceAuthorizationTrustStatements(issuerDid, true).block();
            return extractFirstJwt(response != null ? response.getContent() : null, "piaTS", issuerDid);
        } catch (Exception e) {
            log.warn("Failed to fetch protected issuance authorization trust statement (piaTS) for issuer {}: {}", issuerDid, e.getMessage());
            return null;
        }
    }

    @Nullable
    private String extractFirstJwt(@Nullable List<String> content, String type, String issuerDid) {
        if (content == null || content.isEmpty()) {
            log.warn("No {} trust statement found for issuer {}", type, issuerDid);
            return null;
        }
        return content.getFirst();
    }

    /**
     * Builds a Caffeine cache with dynamic per-entry TTL and a bounded maximum size.
     * The expiry of each entry is calculated from the {@code exp} claim of the cached JWT,
     * minus a clock-skew buffer to ensure served statements are still valid upon receipt.
     */
    private Cache<String, String> buildCache() {
        return Caffeine.newBuilder()
                .maximumSize(maxCacheSize)
                .expireAfter(new Expiry<String, String>() {
                    @Override
                    public long expireAfterCreate(String key, String jwt, long currentTime) {
                        return computeNanosUntilExpiry(jwt);
                    }

                    @Override
                    public long expireAfterUpdate(String key, String jwt, long currentTime, long currentDuration) {
                        return computeNanosUntilExpiry(jwt);
                    }

                    @Override
                    public long expireAfterRead(String key, String jwt, long currentTime, long currentDuration) {
                        return currentDuration;
                    }
                })
                .build();
    }

    /**
     * Parses the JWT payload to extract the {@code exp} claim and computes
     * the remaining lifetime in nanoseconds, minus a clock-skew buffer.
     *
     * <p>The {@code CLOCK_SKEW_BUFFER_SECONDS} buffer ensures that cached statements
     * are evicted before they actually expire, so downstream receivers (wallets, verifiers)
     * still see a valid JWT even accounting for network latency and clock drift.</p>
     *
     * <p>If parsing fails or the adjusted expiry is already in the past,
     * a minimum TTL of 1 second is returned to prevent poison-cache scenarios.</p>
     *
     * @param jwt the serialized JWT string
     * @return remaining lifetime in nanoseconds
     */
    private long computeNanosUntilExpiry(String jwt) {
        return extractExpFromJwt(jwt)
                .map(exp -> {
                    long remainingSeconds = (exp - clockSkewBufferSeconds) - Instant.now().getEpochSecond();
                    if (remainingSeconds <= 0) {
                        log.warn("Trust statement JWT expires too soon or is already expired (exp={})", exp);
                        return TimeUnit.SECONDS.toNanos(1);
                    }
                    log.debug("Caching trust statement JWT for {} seconds (exp={}, buffer={}s)",
                            remainingSeconds, exp, clockSkewBufferSeconds);
                    return TimeUnit.SECONDS.toNanos(remainingSeconds);
                })
                .orElseGet(() -> {
                    log.warn("Could not extract exp from trust statement JWT – using 60s fallback TTL");
                    return TimeUnit.SECONDS.toNanos(60);
                });
    }

    /**
     * Decodes the JWT payload (without signature verification) and extracts the {@code exp} claim.
     *
     * @param jwt the serialized JWT string
     * @return the {@code exp} epoch-second value, or empty if parsing fails
     */
    private Optional<Long> extractExpFromJwt(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                return Optional.empty();
            }
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode payload = objectMapper.readTree(payloadBytes);
            if (payload.has("exp")) {
                return Optional.of(payload.get("exp").asLong());
            }
        } catch (Exception e) {
            log.warn("Failed to parse JWT payload for exp extraction: {}", e.getMessage());
        }
        return Optional.empty();
    }
}







