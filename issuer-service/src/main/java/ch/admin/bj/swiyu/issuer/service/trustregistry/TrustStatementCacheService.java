package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.core.trust.client.api.TrustProtocol20Api;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.service.enc.CacheMaintenanceService;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.nimbusds.jwt.JWTParser;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
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

    /**
     * Negative cache TTL in seconds applied when the TMS API returns empty or fails.
     * Prevents retry storms within this window.
     */
    private static final long NEGATIVE_CACHE_TTL_SECONDS = 30;

    private final TrustProtocol20Api trustProtocol20Api;
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
     *
     * <p>The piaTS cache stores a list of all active piaTS JWTs per issuer DID,
     * because the Trust Registry issues one piaTS per authorised credential type (VCT).
     * Callers must match individual JWTs to credential configurations by their {@code vct} claim.</p>
     */
    private final Cache<String, Optional<String>> idTsCache;
    private final Cache<String, Optional<List<String>>> piaTsCache;

    /**
     * Creates a new {@code TrustStatementCacheService}.
     *
     * @param trustProtocol20Api generated API client for the trust sidechannel
     * @param swiyuProperties    application properties for cache tuning
     */
    public TrustStatementCacheService(TrustProtocol20Api trustProtocol20Api,
                                      SwiyuProperties swiyuProperties,
                                      Optional<TrustStatementValidator> trustStatementValidator,
                                      CacheMaintenanceService cacheMaintenanceService) {
        this.trustProtocol20Api = trustProtocol20Api;
        this.trustStatementValidator = trustStatementValidator;
        this.cacheMaintenanceService = cacheMaintenanceService;
        var trustRegistry = swiyuProperties.trustRegistry();
        this.maxCacheSize = trustRegistry.maxCacheSize();
        this.clockSkewBufferSeconds = trustRegistry.clockSkewBufferSeconds();
        this.maxCacheTtlSeconds = trustRegistry.maxCacheTtlSeconds();
        this.idTsCache = buildCache();
        this.piaTsCache = buildPiaTsCache();
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
     * Returns all cached Protected Issuance Authorization Trust Statement (piaTS) JWTs
     * for the given issuer DID, fetching them from the trust registry if not yet cached
     * or already expired.
     *
     * <p>The Trust Registry issues one piaTS per authorised credential type (VCT). The returned
     * list therefore contains one JWT per authorisation. Callers must match each JWT to the
     * correct {@code CredentialConfiguration} by extracting the {@code vct} claim from the
     * JWT payload.</p>
     *
     * @param issuerDid the effective issuer DID for which to retrieve the trust statements
     * @return an unmodifiable list of piaTS JWT strings; empty if none are available
     */
    public List<String> getAllProtectedIssuanceAuthorizationTrustStatements(String issuerDid) {
        Optional<List<String>> cached = piaTsCache.get(issuerDid, this::fetchAllProtectedIssuanceAuthorizationTrustStatements);
        return cached.orElse(List.of());
    }

    /**
     * Returns the first cached Protected Issuance Authorization Trust Statement (piaTS) JWT
     * for the given issuer DID, fetching it from the trust registry if not yet cached
     * or already expired.
     *
     * @param issuerDid the effective issuer DID for which to retrieve the trust statement
     * @return the first piaTS JWT string, or {@code null} if unavailable
     * @deprecated Use {@link #getAllProtectedIssuanceAuthorizationTrustStatements(String)} to
     *             retrieve all piaTS JWTs and match them per credential type (VCT).
     *             The Trust Registry issues one piaTS per authorised VCT; using only the first
     *             entry may silently attach the wrong trust statement to a credential configuration.
     */
    @Nullable
    @Deprecated(since = "3.1.0", forRemoval = true)
    public String getProtectedIssuanceAuthorizationTrustStatement(String issuerDid) {
        List<String> all = getAllProtectedIssuanceAuthorizationTrustStatements(issuerDid);
        return all.isEmpty() ? null : all.getFirst();
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
        } catch (RuntimeException e) {
            log.warn("Failed to fetch idTS for issuer {}: {}", issuerDid, e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<List<String>> fetchAllProtectedIssuanceAuthorizationTrustStatements(String issuerDid) {
        try {
            var response = trustProtocol20Api.listPiaTS(issuerDid, true, null, null, null).block();
            List<String> jwts = response != null && response.getContent() != null
                    ? response.getContent()
                    : List.of();

            if (jwts.isEmpty()) {
                log.warn("No piaTS trust statements found for issuer {}", issuerDid);
                return Optional.empty();
            }

            log.debug("Fetched {} piaTS JWT(s) for issuer {}", jwts.size(), issuerDid);
            for (String jwt : jwts) {
                validateTrustStatement(jwt, "piaTS", issuerDid);
            }
            return Optional.of(List.copyOf(jwts));
        } catch (JwtValidatorException e) {
            log.warn("piaTS signature validation failed for issuer {}: {}", issuerDid, e.getMessage());
            return Optional.empty();
        } catch (RuntimeException e) {
            log.warn("API or network error fetching piaTS for issuer {}: {}", issuerDid, e.getMessage());
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
     * Builds a Caffeine cache for piaTS lists with dynamic per-entry TTL.
     *
     * <p>The TTL is derived from the <strong>earliest</strong> {@code exp} claim across all JWTs
     * in the cached list. This is intentionally conservative: as soon as any single piaTS in the
     * list expires, the entire entry is evicted and all statements are refreshed together.
     * This prevents a JWT with a short lifetime from being served after its expiry just because
     * another JWT in the same list has a later {@code exp}.</p>
     */
    private Cache<String, Optional<List<String>>> buildPiaTsCache() {
        return Caffeine.newBuilder()
                .maximumSize(maxCacheSize)
                .expireAfter(new Expiry<String, Optional<List<String>>>() {
                    @Override
                    public long expireAfterCreate(String key, Optional<List<String>> jwtsOpt, long currentTime) {
                        return computeMinNanosUntilExpiry(jwtsOpt);
                    }

                    @Override
                    public long expireAfterUpdate(String key, Optional<List<String>> jwtsOpt, long currentTime, long currentDuration) {
                        return computeMinNanosUntilExpiry(jwtsOpt);
                    }

                    @Override
                    public long expireAfterRead(String key, Optional<List<String>> jwtsOpt, long currentTime, long currentDuration) {
                        return currentDuration;
                    }
                })
                .build();
    }

    /**
     * Computes the cache TTL in nanoseconds for a list of piaTS JWTs by taking the
     * <strong>minimum</strong> remaining lifetime across all JWTs in the list.
     *
     * <p>If the list is absent or empty (negative cache), {@link #NEGATIVE_CACHE_TTL_SECONDS} is used.</p>
     *
     * @param jwtsOpt the optional list of piaTS JWT strings
     * @return TTL in nanoseconds
     */
    private long computeMinNanosUntilExpiry(Optional<List<String>> jwtsOpt) {
        return jwtsOpt
                .filter(list -> !list.isEmpty())
                .map(list -> list.stream()
                        .mapToLong(TrustStatementCacheService.this::computeNanosUntilExpiry)
                        .min()
                        .orElseGet(() -> TimeUnit.SECONDS.toNanos(NEGATIVE_CACHE_TTL_SECONDS)))
                .orElseGet(() -> TimeUnit.SECONDS.toNanos(NEGATIVE_CACHE_TTL_SECONDS));
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
                        .orElseGet(() -> TimeUnit.SECONDS.toNanos(NEGATIVE_CACHE_TTL_SECONDS));
            }

            @Override
            public long expireAfterUpdate(String key, Optional<String> jwtOpt, long currentTime, long currentDuration) {
                return jwtOpt.map(TrustStatementCacheService.this::computeNanosUntilExpiry)
                        .orElseGet(() -> TimeUnit.SECONDS.toNanos(NEGATIVE_CACHE_TTL_SECONDS));
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
     * Parses the JWT (without signature verification) and extracts the {@code exp} claim.
     *
     * @param jwt the serialized JWT string
     * @return the {@code exp} epoch-second value, or empty if parsing fails
     */
    private Optional<Long> extractExpFromJwt(String jwt) {
        try {
            return Optional.ofNullable(JWTParser.parse(jwt).getJWTClaimsSet().getExpirationTime())
                    .map(expirationDate -> expirationDate.getTime() / 1000);
        } catch (ParseException e) {
            log.warn("Failed to parse JWT payload for exp extraction: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
