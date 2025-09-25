package ch.admin.bj.swiyu.issuer.common.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.cache.CacheManagerCustomizer;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

import static ch.admin.bj.swiyu.issuer.common.config.CacheConfig.PUBLIC_KEY_CACHE;

@Slf4j
@Component
public class CacheCustomizer implements CacheManagerCustomizer<ConcurrentMapCacheManager> {

    @Override
    // Needed to customize the behavior of Spring's caching abstraction
    public void customize(ConcurrentMapCacheManager cacheManager) {
        cacheManager.setCacheNames(List.of(PUBLIC_KEY_CACHE));
    }

    @CacheEvict(value = PUBLIC_KEY_CACHE, allEntries = true)
    @Scheduled(fixedRateString = "${caching.publicKeyCacheTTL}")
    public void emptyPublicKeyCache() {
        log.debug("emptying public key cache");
    }
}