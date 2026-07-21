package ch.admin.bj.swiyu.issuer.service.trustregistry;

import java.text.ParseException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties.TrustRegistryProperties;
import ch.admin.bj.swiyu.issuer.common.date.TimeUtil;
import ch.admin.bj.swiyu.issuer.service.did.DidKeyResolverFacade;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import ch.admin.bj.swiyu.statuslist.TokenStatusListVerifier;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListMapper;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@ConditionalOnExpression("'${swiyu.trust-registry.api-url:}'.length() > 0")
public class StatusListCacheService {
private final DidKidParser didKidParser = new DidKidParser();
    private final TrustRegistryProperties trustRegistryProperties;
    private final DidJwtValidator didJwtValidator;
    private final DidKeyResolverFacade keyResolver;
    private final StatusRegistryClient statusRegistryClient;
    private final Cache<String, Optional<TokenStatusListTokenDto>> cache;

        public StatusListCacheService(SwiyuProperties swiyuProperties, DidJwtValidator didJwtValidator,
            DidKeyResolverFacade keyResolver, StatusRegistryClient statusRegistryClient) {
        this.trustRegistryProperties = swiyuProperties.trustRegistry();
        this.didJwtValidator = didJwtValidator;
        this.keyResolver = keyResolver;
        this.statusRegistryClient = statusRegistryClient;
        this.cache = buildTokenStatusListTokenCache();
    }

    /**
     * Resolves the given URI to a verified TokenStatusListToken, caching it if possible to reduce load
     * @param uri URI where the status list is located
     * @return the TokenStatusListToken or null, if it cannot be resolved
     */
    public TokenStatusListTokenDto getTokenStatusListTokenByUri(String uri) {
        Optional<TokenStatusListTokenDto> token = cache.get(uri, this::resolveValidatedStatusList);
        return token == null ? null : token.orElse(null);
    }

    /**
     * Fetches and validates the Token Status List found at URI. Validation is for it being a valid JWT and 
     * fulfilling the basic requirements of a token status list according to the spec.
     * @param uri URI where the status list is located
     * @return the TokenStatusListToken or null, if it cannot be resolved
     */
    private Optional<TokenStatusListTokenDto> resolveValidatedStatusList(String uri) {
        try {
        String statusListJWT = statusRegistryClient.resolveStatusList(uri);
        SignedJWT tokenStatusListJWT = SignedJWT.parse(statusListJWT);
        TokenStatusListVerifier.hasValidTokenStatusListTokenHeader(tokenStatusListJWT.getHeader());
        TokenStatusListTokenDto statusList = TokenStatusListMapper.toTokenStatusListToken(tokenStatusListJWT.getJWTClaimsSet().getClaims());
        String kid = didKidParser.extractKidFromHeader(statusListJWT);
        JWK statusListKey = keyResolver.resolveKey(kid);
        didJwtValidator.validateJwt(statusListJWT, new JWKSet(statusListKey));
        return Optional.of(statusList);
        } catch (IllegalArgumentException | ParseException e) {
            log.info("Failed to load status list {}", uri, e);
            return Optional.empty();
        }
    }


    /**
     * Create a Caffeine cache for TokenStatusListTokens, taking the mimimum of expiry, ttl or a property ttl for cache lifetime duration
     * @return A new caffeine cache
     */
    private Cache<String, Optional<TokenStatusListTokenDto>> buildTokenStatusListTokenCache() {
        return Caffeine.newBuilder()
            .maximumSize(trustRegistryProperties.maxCacheSize())
            .expireAfter(buildTokenStatusListExpire(TimeUnit.SECONDS.toNanos(trustRegistryProperties.maxCacheTtlSeconds())))
            .build();
    }

    /**
     * 
     * @param maxCacheTTLNs TTL, if smaller than exp or ttl of status list overriding the status list's config
     * @return the caffeine expiry object with correct expiry times configured
     */
    private Expiry<String, Optional<TokenStatusListTokenDto>> buildTokenStatusListExpire(long maxCacheTTLNs) {
        return new Expiry<>() {

            @Override
            public long expireAfterCreate(String key, Optional<TokenStatusListTokenDto> value, long currentTime) {
                return getTtlOrBackoff(value);
            }

            @Override
            public long expireAfterUpdate(String key, Optional<TokenStatusListTokenDto> value, long currentTime,
                    long currentDuration) {
                return getTtlOrBackoff(value);
            }

            @Override
            public long expireAfterRead(String key, Optional<TokenStatusListTokenDto> value, long currentTime,
                    long currentDuration) {
                return currentDuration;
            }
            
            private long getTtlOrBackoff(Optional<TokenStatusListTokenDto> value) {
                return value
                    .map(v -> getTTLTime(v))
                    .orElse(TimeUnit.SECONDS.toNanos(trustRegistryProperties.requestBackoffSeconds()));
            }

            private long getTTLTime(TokenStatusListTokenDto value) {
                long minimumTimeout = TimeUtil.minNanosUntilExpiry(maxCacheTTLNs, TimeUtil.secondsToNanos(value.getExp()));
                return TimeUtil.minWithNullable(minimumTimeout, TimeUtil.secondsToNanos(value.getTtl()));
            }
        };
    }
}
