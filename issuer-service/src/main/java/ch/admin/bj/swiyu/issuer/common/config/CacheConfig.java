package ch.admin.bj.swiyu.issuer.common.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
public class CacheConfig {

    public static final String PUBLIC_KEY_CACHE = "PublicKeyCache";
    public static final String OPEN_ID_CONFIGURATION_CACHE = "OpenIdConfigurationCache";
    public static final String ISSUER_METADATA_CACHE = "IssuerMetadataCache";
    public static final String JWS_SIGNER_CACHE = "JwsSignerCache";

    @Bean
    public CacheManager cacheManager() {
        return new ConcurrentMapCacheManager(PUBLIC_KEY_CACHE, OPEN_ID_CONFIGURATION_CACHE, ISSUER_METADATA_CACHE, JWS_SIGNER_CACHE);
    }
}