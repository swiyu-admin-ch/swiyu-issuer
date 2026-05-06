package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.core.trust.client.api.TrustProtocol20Api;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.service.enc.CacheMaintenanceService;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
 * <p>API failures and empty responses are negatively cached (via {@code Optional.empty()})
 * for a short duration to prevent retry storms and cascading failures when the
 * Trust Registry is unavailable.</p>
 *
 * <p>Only active when {@code swiyu.trust-registry.api-url} is configured.</p>
 */
@Slf4j
@Service
@ConditionalOnProperty(prefix = "swiyu.trust-registry", name = "api-url")
public class TrustStatementCacheService {

    /**
     * Fallback TTL in seconds used when the JWT {@code exp} claim cannot be parsed.
     * Keeps the cache from growing stale indefinitely while allowing a retry after a short window.
     */
    private static final long FALLBACK_TTL_SECONDS = 60;

    private final TrustProtocol20Api trustProtocol20Api;
    private final ObjectMapper objectMapper;
    private final long maxCacheSize;
    private final long clockSkewBufferSeconds;
    private final CacheMaintenanceService cacheMaintenanceService;

    /**
     * Optional hard upper bound for the cache TTL in seconds.
     * When set, effective TTL = min(exp-based TTL, maxCacheTtlSeconds).
     * When null, TTL is derived exclusively from the JWT exp claim.
     */
    private final Long maxCacheTtlSeconds;

    /**
     * Optional validator for trust statement signatures.
     * Present only when {@code swiyu.trust-registry.api-url} is configured AND
     * {@code trustStatementDidJwtValidator} bean is available.
     * When absent, trust statements are cached without signature verification.
     */
    private final Optional<TrustStatementValidator> trustStatementValidator;

    /**
     * Two separate caches keyed by issuer DID – one per statement type (idTS / piaTS).
     * Separate caches ensure that invalidating one type does not affect the other,
     * and that each statement type has its own independent TTL per issuer.
     *
     * <p>Note: {@code @Cacheable} is intentionally NOT used here because Spring's cache
     * abstraction only supports a static TTL per cache, not a dynamic per-entry TTL.
     * Caffeine is used directly to implement exp-based eviction.</p>
     */
    private final Cache<String, Optional<String>> idTsCache;
    private final Cache<String, Optional<String>> piaTsCache;

    /**
     * Creates a new {@code TrustStatementCacheService}.
     *
     * @param trustProtocol20Api generated API client for the trust sidechannel
     * @param objectMapper       Jackson mapper for JWT payload parsing
     * @param swiyuProperties    application properties for cache tuning
     */
    public TrustStatementCacheService(TrustProtocol20Api trustProtocol20Api,
                                      ObjectMapper objectMapper,
                                      SwiyuProperties swiyuProperties,
                                      Optional<TrustStatementValidator> trustStatementValidator,
                                      CacheMaintenanceService cacheMaintenanceService) {
        this.trustProtocol20Api = trustProtocol20Api;
        this.objectMapper = objectMapper;
        this.trustStatementValidator = trustStatementValidator;
        this.cacheMaintenanceService = cacheMaintenanceService;
        var trustRegistry = swiyuProperties.trustRegistry();
        this.maxCacheSize = trustRegistry.maxCacheSize();
        this.clockSkewBufferSeconds = trustRegistry.clockSkewBufferSeconds();
        this.maxCacheTtlSeconds = trustRegistry.maxCacheTtlSeconds();
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
        Optional<String> cached = idTsCache.get(issuerDid, this::fetchIdentityTrustStatement);
        return cached.isPresent() ? cached.orElse(null) : null;
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
        Optional<String> cached = piaTsCache.get(issuerDid, this::fetchProtectedIssuanceAuthorizationTrustStatement);
        return cached.isPresent() ? cached.orElse(null) : null;
    }

    private Optional<String> fetchIdentityTrustStatement(String issuerDid) {
        try {
            String jwt = trustProtocol20Api.getIdTS(issuerDid).block();
            if (jwt == null) {
                log.warn("No idTS trust statement found for issuer {}", issuerDid);
            } else {
                validateTrustStatement(jwt, "idTS", issuerDid);
            }
            return Optional.ofNullable(jwt);
        } catch (JwtValidatorException e) {
            log.warn("idTS signature validation failed for issuer {}: {}", issuerDid, e.getMessage());
            return Optional.empty();
        } catch (Exception e) {
            log.warn("Failed to fetch idTS for issuer {}: {}", issuerDid, e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<String> fetchProtectedIssuanceAuthorizationTrustStatement(String issuerDid) {
        try {
            var response = trustProtocol20Api.listPiaTS(issuerDid, true, null, null, null).block();
            String jwt = extractFirstJwt(response != null ? response.getContent() : null, "piaTS", issuerDid);
            if (jwt != null) {
                validateTrustStatement(jwt, "piaTS", issuerDid);
            }
            return Optional.ofNullable(jwt);
        } catch (JwtValidatorException e) {
            log.warn("piaTS signature validation failed for issuer {}: {}", issuerDid, e.getMessage());
            return Optional.empty();
        } catch (Exception e) {
            log.warn("Failed to fetch protected issuance authorization trust statement (piaTS) for issuer {}: {}", issuerDid, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Runs the pre-cache allowlist check via {@link TrustStatementValidator} (no HTTP call).
     * If no validator is configured, the check is skipped and a warning is logged.
     *
     * @param jwt       the trust statement JWT to check
     * @param type      the statement type label for logging ("idTS" or "piaTS")
     * @param issuerDid the issuer DID for logging context
     * @throws JwtValidatorException if the DID URL resolved from the JWT is not on the allowlist
     */
    private void validateTrustStatement(String jwt, String type, String issuerDid) {
        if (trustStatementValidator.isEmpty()) {
            log.warn("No TrustStatementValidator configured – skipping allowlist check for {} of issuer {}", type, issuerDid);
            return;
        }
        trustStatementValidator.get().validateAllowlist(jwt);
        log.debug("{} allowlist check passed for issuer {}", type, issuerDid);
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
     * <p>In addition, it triggers the clearing of the public key and encryption metadata
     * caches to ensure that potentially rotated keys are reloaded.</p>
     *
     * @param issuerDid the issuer DID whose cached trust statements should be invalidated
     */
    public void invalidateAllTrustStatements(String issuerDid) {
        log.info("Invalidating all cached trust statements for issuer {}", issuerDid);
        idTsCache.invalidate(issuerDid);
        piaTsCache.invalidate(issuerDid);
        cacheMaintenanceService.evictEncryptionMetadataManually(issuerDid);
        cacheMaintenanceService.evictPublicKeyManually(issuerDid);
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
    private Cache<String, Optional<String>> buildCache() {
        return Caffeine.newBuilder()
                .maximumSize(maxCacheSize)
                .expireAfter(buildExpiry())
                .build();
    }

    /**
     * Returns a Caffeine {@link Expiry} that derives the per-entry TTL from the JWT {@code exp} claim.
     * On read, the remaining duration is preserved unchanged.
     */
    private Expiry<String, Optional<String>> buildExpiry() {
        return new Expiry<>() {
            @Override
            public long expireAfterCreate(String key, Optional<String> jwtOpt, long currentTime) {
                return jwtOpt.map(TrustStatementCacheService.this::computeNanosUntilExpiry)
                        // Negative Caching: Bei API-Fehler für 30 Sekunden nicht mehr probieren!
                        .orElseGet(() -> TimeUnit.SECONDS.toNanos(30));
            }

            @Override
            public long expireAfterUpdate(String key, Optional<String> jwtOpt, long currentTime, long currentDuration) {
                return jwtOpt.map(TrustStatementCacheService.this::computeNanosUntilExpiry)
                        .orElseGet(() -> TimeUnit.SECONDS.toNanos(30));
            }

            @Override
            public long expireAfterRead(String key, Optional<String> jwtOpt, long currentTime, long currentDuration) {
                return currentDuration;
            }
        };
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
     * <p>If parsing fails, {@link #FALLBACK_TTL_SECONDS} is used as fallback.</p>
     *
     * @param jwt the serialized JWT string
     * @return remaining lifetime in nanoseconds (minimum 1 second)
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
                    log.warn("Could not extract exp from trust statement JWT – using {}s fallback TTL", FALLBACK_TTL_SECONDS);
                    return TimeUnit.SECONDS.toNanos(FALLBACK_TTL_SECONDS);
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
