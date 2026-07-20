package ch.admin.bj.swiyu.issuer.service.trustregistry;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;

import ch.admin.bj.swiyu.core.trust.client.api.TrustProtocol20Api;
import ch.admin.bj.swiyu.core.trust.client.model.PagedModelString;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.service.enc.CacheMaintenanceService;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;

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
@ConditionalOnExpression("'${swiyu.trust-registry.api-url:}'.length() > 0")
public class TrustStatementCacheService {

    private final TrustProtocol20Api trustProtocol20Api;
    private final long maxCacheSize;
    private final CacheMaintenanceService cacheMaintenanceService;

    /**
     * Time after which when receiving no valid trust statements no further attempts should be made
     */
    private final long requestBackoffSeconds;

    private final TrustStatementValidator trustStatementValidator;

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
    private final Cache<String, ValidatedSingleTrustStatement> idTsCache;
    private final Cache<String, List<ValidatedSingleTrustStatement>> piaTsCache;


    /**
     * Creates a new {@code TrustStatementCacheService}.
     *
     * @param trustProtocol20Api generated API client for the trust sidechannel
     * @param swiyuProperties    application properties for cache tuning
     */
    public TrustStatementCacheService(TrustProtocol20Api trustProtocol20Api,
                                      SwiyuProperties swiyuProperties,
                                      TrustStatementValidator trustStatementValidator,
                                      CacheMaintenanceService cacheMaintenanceService) {
        this.trustProtocol20Api = trustProtocol20Api;
        this.trustStatementValidator = trustStatementValidator;
        this.cacheMaintenanceService = cacheMaintenanceService;
        var trustRegistry = swiyuProperties.trustRegistry();
        this.maxCacheSize = trustRegistry.maxCacheSize();
        this.requestBackoffSeconds = trustRegistry.requestBackoffSeconds();
        this.idTsCache = buildTrustStatementCache();
        this.piaTsCache = buildTrustStatementListCache();
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
        ValidatedSingleTrustStatement cached = idTsCache.get(issuerDid, this::fetchIdentityTrustStatement);
        return cached!=null && cached.trustStatement.isPresent() && cached.valid ? cached.trustStatement.orElse(null) : null;
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
        List<ValidatedSingleTrustStatement> statements = piaTsCache.get(issuerDid, this::fetchProtectedIssuanceAuthorizationTrustStatements);
        if (statements == null) {
            return List.of();
        }
        return statements
                .stream().map(vts -> vts.trustStatement)
                .filter(ts -> ts.isPresent())
                .map(ts -> ts.get()).toList();
    }

    /**
     * Returns either a JWT (String) or null if the fetch failed.
     */
    private ValidatedSingleTrustStatement fetchIdentityTrustStatement(String issuerDid) {
        try {
            String jwt = trustProtocol20Api.getIdTS(issuerDid).block();
            if (jwt == null) {
                log.warn("No idTS trust statement found for issuer {}", issuerDid);
            }
            return validateTrustStatement(jwt);
        } catch (JwtValidatorException e) {
            log.warn("idTS signature validation failed for issuer {}: {}", issuerDid, e.getMessage());
            return new ValidatedSingleTrustStatement(Optional.empty(), false, 0);
        } catch (RuntimeException e) {
            log.warn("Failed to fetch idTS for issuer {}: {}", issuerDid, e.getMessage());
            return null;
        }
    }

    /**
     * Returns either a List<String> of jwts or null if the fetch failed.
     */
    private List<ValidatedSingleTrustStatement> fetchProtectedIssuanceAuthorizationTrustStatements(String issuerDid) {
        try {
            var response = trustProtocol20Api.listPiaTS(issuerDid, true, null, null, null).block();
            List<String> jwts = getListOfStatements(response);


            log.debug("Fetched {} piaTS JWT(s) for issuer {}", jwts.size(), issuerDid);
            return jwts.stream()
                .map(this::validateTrustStatement)
                .filter(vts -> vts.valid)
                .toList();
        } catch (JwtValidatorException e) {
            log.warn("piaTS signature validation failed for issuer {}: {}", issuerDid, e.getMessage());
            return List.of();
        } catch (RuntimeException e) {
            log.warn("An error occured while fetching piaTS for issuer {}: {}", issuerDid, e.getMessage());
            return null;
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
    private ValidatedSingleTrustStatement validateTrustStatement(String jwt) {
        var validationResult = trustStatementValidator.trustStatementValidityWindow(jwt);
        return new ValidatedSingleTrustStatement(Optional.ofNullable(jwt), validationResult.isValid(), validationResult.valditiyWindow());
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
     * Builds a Caffeine cache for single valid trust statement with dynamic TTL.
     * derived from the minimum of JWT {@code exp} claims and Status List TTL claim.
     */
    private Cache<String, ValidatedSingleTrustStatement> buildTrustStatementCache() {
        return Caffeine.newBuilder()
                .maximumSize(this.maxCacheSize)
                .expireAfter(buildSingleTrustStatementExpiry())
                .build();
    }

    private @NonNull Expiry<String, ValidatedSingleTrustStatement> buildSingleTrustStatementExpiry() {
        return new Expiry<>() {
            @Override
            public long expireAfterCreate(String key, ValidatedSingleTrustStatement ts, long currentTime) {
                return getValidTtlOrBackoff(ts);
            }

            @Override
            public long expireAfterUpdate(String key, ValidatedSingleTrustStatement ts, long currentTime,
                    long currentDuration) {
                return getValidTtlOrBackoff(ts);
            }

            @Override
            public long expireAfterRead(String key, ValidatedSingleTrustStatement ts, long currentTime,
                    long currentDuration) {
                return currentDuration;
            }

            private long getValidTtlOrBackoff(ValidatedSingleTrustStatement value) {
                return value.valid ? value.ttl : TimeUnit.SECONDS.toNanos(requestBackoffSeconds);
            }
        };
    }

    /**
     * Builds a Caffeine cache for a lists of valid trust statements with dynamic
     * TTL.
     * The TTL of the list is the <em>minimum</em> remaining lifetime across all
     * JWTs and their Status Lists in the list,
     * so the list is evicted and re-fetched as soon as the earliest statement
     * expires.
     * Invalid Statements or no statments use a fixed TTL until fetch is
     * reattempted.
     */
    private Cache<String, List<ValidatedSingleTrustStatement>> buildTrustStatementListCache() {
        return Caffeine.newBuilder()
                .maximumSize(this.maxCacheSize)
                .expireAfter(buildListTrustStatementExpiry())
                .build();
    }

    private @NonNull Expiry<String, List<ValidatedSingleTrustStatement>> buildListTrustStatementExpiry() {
        return new Expiry<String, List<ValidatedSingleTrustStatement>>() {

            @Override
            public long expireAfterCreate(String key, List<ValidatedSingleTrustStatement> value, long currentTime) {
                return getValidTtlOrBackoff(value);
            }

            @Override
            public long expireAfterUpdate(String key, List<ValidatedSingleTrustStatement> value, long currentTime,
                    long currentDuration) {
                return getValidTtlOrBackoff(value);
            }

            @Override
            public long expireAfterRead(String key, List<ValidatedSingleTrustStatement> value, long currentTime,
                    long currentDuration) {
                return currentDuration;
            }

            /**
             * Cache the list of trust statements for the ttl. If no valid trust statement is found, cache the empty list for
             * backoff seconds to prevent spamming the registry
             * @param value the list of trust statements to be cached
             * @return cache duration in nanoseconds
             */
            private long getValidTtlOrBackoff(List<ValidatedSingleTrustStatement> value) {
                return value.stream()
                        .filter(v -> v.valid)
                        .mapToLong(v -> v.ttl)
                        .min()
                        .orElse(TimeUnit.SECONDS.toNanos(requestBackoffSeconds));
            }

        };
    }

    private List<String> getListOfStatements(PagedModelString pagedModelString) {
        if (pagedModelString == null || pagedModelString.getContent() == null) {
            return List.of();
        }
        return pagedModelString.getContent();
    }

    public record ValidatedSingleTrustStatement(@NonNull Optional<String> trustStatement, boolean valid, long ttl) {
    }
}
