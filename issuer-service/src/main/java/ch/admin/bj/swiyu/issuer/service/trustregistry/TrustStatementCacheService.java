package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.core.trust.client.api.TrustProtocol20Api;
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
 * <p>Only active when a {@link TrustProtocol20Api} bean is present
 * (i.e. {@code swiyu.trust-registry.api-url} is configured).</p>
 */
@Slf4j
@Service
@ConditionalOnBean(TrustProtocol20Api.class)
public class TrustStatementCacheService {

    private final TrustProtocol20Api trustProtocol20Api;
    private final ObjectMapper objectMapper;
    private final long maxCacheSize;
    private final long clockSkewBufferSeconds;

    /**
     * Optional hard upper bound for the cache TTL in seconds.
     * When set, effective TTL = min(exp-based TTL, maxCacheTtlSeconds).
     * When null, TTL is derived exclusively from the JWT exp claim.
     */
    private final Long maxCacheTtlSeconds;

    /**
     * Note: {@code @Cacheable} is intentionally NOT used here because Spring's cache abstraction
     * only supports a static TTL per cache, not a dynamic per-entry TTL. Caffeine is used
     * directly to implement exp-based eviction as required by the trust statement lifecycle.
     */
    private final Cache<String, String> idTsCache;
    private final Cache<String, String> piaTsCache;

    /**
     * Creates a new {@code TrustStatementCacheService}.
     *
     * @param trustProtocol20Api generated API client for the trust sidechannel
     * @param objectMapper       Jackson mapper for JWT payload parsing
     * @param swiyuProperties    application properties for cache tuning
     */
    public TrustStatementCacheService(TrustProtocol20Api trustProtocol20Api,
                                      ObjectMapper objectMapper,
                                      SwiyuProperties swiyuProperties) {
        this.trustProtocol20Api = trustProtocol20Api;
        this.objectMapper = objectMapper;
        var trustRegistry = swiyuProperties.trustRegistry();
        this.maxCacheSize = trustRegistry != null ? trustRegistry.maxCacheSize() : 1_000;
        this.clockSkewBufferSeconds = trustRegistry != null ? trustRegistry.clockSkewBufferSeconds() : 60;
        this.maxCacheTtlSeconds = trustRegistry != null ? trustRegistry.maxCacheTtlSeconds() : null;
        this.idTsCache = buildCache();
        this.piaTsCache = buildCache();
    }

    /**
     * Returns the cached Identity Trust Statement (idTS) JWT for the given issuer DID,
     * fetching it from the trust registry if not yet cached or already expired.
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
            var response = trustProtocol20Api.listIdTS(issuerDid, true, null, null, null).block();
            return extractFirstJwt(response != null ? response.getContent() : null, "idTS", issuerDid);
        } catch (Exception e) {
            log.warn("Failed to fetch identity trust statement (idTS) for issuer {}: {}", issuerDid, e.getMessage());
            return null;
        }
    }

    @Nullable
    private String fetchProtectedIssuanceAuthorizationTrustStatement(String issuerDid) {
        try {
            var response = trustProtocol20Api.listPiaTS(issuerDid, true, null, null, null).block();
            return extractFirstJwt(response != null ? response.getContent() : null, "piaTS", issuerDid);
        } catch (Exception e) {
            log.warn("Failed to fetch protected issuance authorization trust statement (piaTS) for issuer {}: {}", issuerDid, e.getMessage());
            return null;
        }
    }

    /**
     * Invalidates the cached Identity Trust Statement (idTS) for the given issuer DID.
     *
     * <p>Call this when idTS verification fails (e.g. signature invalid, DID key rotated)
     * to force a fresh fetch from the Trust Registry on the next request.</p>
     *
     * @param issuerDid the issuer DID whose cached idTS should be invalidated
     */
    public void invalidateIdentityTrustStatement(String issuerDid) {
        log.info("Invalidating cached idTS for issuer {}", issuerDid);
        idTsCache.invalidate(issuerDid);
    }

    /**
     * Invalidates the cached Protected Issuance Authorization Trust Statement (piaTS)
     * for the given issuer DID.
     *
     * <p>Call this when piaTS verification fails (e.g. signature invalid, DID key rotated)
     * to force a fresh fetch from the Trust Registry on the next request.</p>
     *
     * @param issuerDid the issuer DID whose cached piaTS should be invalidated
     */
    public void invalidateProtectedIssuanceAuthorizationTrustStatement(String issuerDid) {
        log.info("Invalidating cached piaTS for issuer {}", issuerDid);
        piaTsCache.invalidate(issuerDid);
    }

    /**
     * Invalidates all cached Trust Statements (idTS and piaTS) for the given issuer DID.
     *
     * <p>Convenience method combining both invalidations. Useful when a general
     * trust failure is detected and all statements for an issuer should be refreshed.</p>
     *
     * @param issuerDid the issuer DID whose cached trust statements should be invalidated
     */
    public void invalidateAllTrustStatements(String issuerDid) {
        log.info("Invalidating all cached trust statements for issuer {}", issuerDid);
        idTsCache.invalidate(issuerDid);
        piaTsCache.invalidate(issuerDid);
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
     * <p>If {@code maxCacheTtlSeconds} is configured, the effective TTL is
     * {@code min(exp-based TTL, maxCacheTtlSeconds)} – this allows aligning the
     * trust statement cache with the DID public key cache TTL to avoid serving
     * statements whose referenced DID key has already been rotated.</p>
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
                    // Apply optional hard upper bound
                    if (maxCacheTtlSeconds != null && remainingSeconds > maxCacheTtlSeconds) {
                        log.debug("Capping trust statement cache TTL at {}s (exp-based would be {}s)", maxCacheTtlSeconds, remainingSeconds);
                        remainingSeconds = maxCacheTtlSeconds;
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
