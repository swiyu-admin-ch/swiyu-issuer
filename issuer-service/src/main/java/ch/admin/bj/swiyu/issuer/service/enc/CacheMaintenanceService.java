package ch.admin.bj.swiyu.issuer.service.enc;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

import static ch.admin.bj.swiyu.issuer.common.config.CacheConfig.ISSUER_METADATA_ENCRYPTION_CACHE;
import static ch.admin.bj.swiyu.issuer.common.config.CacheConfig.PUBLIC_KEY_CACHE;

/**
 * Service for manually clearing selected application caches.
 *
 * <p>This component centralizes explicit cache invalidation for caches that may need
 * to be refreshed outside their normal expiration policy, for example after key or
 * metadata rotations.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CacheMaintenanceService {

    private final CacheManager cacheManager;

    /**
     * Clears the public key cache for a SPECIFIC DID.
     */
    public void evictPublicKeyManually(String did) {
        var cache = cacheManager.getCache(PUBLIC_KEY_CACHE);
        if (cache != null) {
            log.debug("Evicting public key cache for DID: {}", did);
            cache.evict(did);
        }
    }

    /**
     * Clears the issuer metadata encryption cache for a SPECIFIC DID.
     */
    public void evictEncryptionMetadataManually(String did) {
        var cache = cacheManager.getCache(ISSUER_METADATA_ENCRYPTION_CACHE);
        if (cache != null) {
            log.debug("Evicting issuer metadata encryption cache for DID: {}", did);
            cache.evict(did);
        }
    }
}