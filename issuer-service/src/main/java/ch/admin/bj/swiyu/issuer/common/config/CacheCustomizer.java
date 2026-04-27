package ch.admin.bj.swiyu.issuer.common.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import static ch.admin.bj.swiyu.issuer.common.config.CacheConfig.ISSUER_METADATA_ENCRYPTION_CACHE;
import static ch.admin.bj.swiyu.issuer.common.config.CacheConfig.PUBLIC_KEY_CACHE;

/**
 * Schedules periodic evictions for all in-memory caches. Running on every pod ensures that
 * horizontally scaled deployments stay consistent: stale cache entries (e.g. outdated encryption
 * keys) are evicted on each instance independently of which pod triggered the underlying data change.
 *
 * <p>The {@link ConcurrentMapCacheManager} itself is configured in {@link CacheConfig}.
 */
@Slf4j
@Component
public class CacheCustomizer {

    /**
     * Periodically evicts all entries from the issuer metadata encryption cache on every pod,
     * ensuring that stale encryption key references are cleared in horizontally scaled deployments.
     *
     * <p>The TTL is configured via {@code caching.encryptionMetadataCacheTTL}. Because rotated keys
     * are kept in the database for a grace period of {@code 2 × encryption-key-rotation-interval}
     * before deletion, wallets that received an older public key from a stale cache entry can still
     * decrypt their requests during that window. The cache TTL must therefore be strictly less than
     * {@code 2 × encryption-key-rotation-interval}. A value of roughly one third of the rotation
     * interval (default: 5 min for a 15-min rotation) is recommended to leave a comfortable margin.
     */
    @CacheEvict(value = ISSUER_METADATA_ENCRYPTION_CACHE, allEntries = true)
    @Scheduled(fixedRateString = "${caching.encryptionMetadataCacheTTL}")
    public void emptyIssuerMetadataEncryptionCache() {
        log.debug("emptying issuer metadata encryption cache");
    }

    @CacheEvict(value = PUBLIC_KEY_CACHE, allEntries = true)
    @Scheduled(fixedRateString = "${caching.publicKeyCacheTTL}")
    public void emptyPublicKeyCache() {
        log.debug("emptying public key cache");
    }
}