package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties.TrustRegistryProperties;
import ch.admin.bj.swiyu.issuer.service.did.DidKeyResolverFacade;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import ch.admin.bj.swiyu.issuer.service.trustregistry.fixtures.StatusListGenerator;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class StatusListCacheServiceTest {

    StatusListCacheService cacheService;
    SwiyuProperties swiyuProperties;
    TrustRegistryProperties trustRegistryProperties;
    DidJwtValidator didJwtValidator;
    DidKeyResolverFacade issuerPublicKeyLoader;
    StatusRegistryClient statusListResolver;


    @BeforeEach
    void setup() {
        swiyuProperties = mock(SwiyuProperties.class);
        trustRegistryProperties = mock(TrustRegistryProperties.class);
        when(swiyuProperties.trustRegistry()).thenReturn(trustRegistryProperties);
        when(trustRegistryProperties.maxCacheSize()).thenReturn(1000L);
        when(trustRegistryProperties.requestBackoffSeconds()).thenReturn(100L);
        didJwtValidator = mock(DidJwtValidator.class);
        issuerPublicKeyLoader = mock(DidKeyResolverFacade.class);
        statusListResolver = mock(StatusRegistryClient.class);
    }

    /**
     * Test mocking a valid Token Status List resolution
     */
    @Test
    void testGetTokenStatusListTokenByUri() throws Exception {
        when(trustRegistryProperties.maxCacheTtlSeconds()).thenReturn(500L);
        cacheService = new StatusListCacheService(swiyuProperties, didJwtValidator, issuerPublicKeyLoader, statusListResolver);
        ECKey testKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("did:webvh:example.com#key-1")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        when(issuerPublicKeyLoader.resolveKey(eq(testKey.getKeyID()))).thenReturn(testKey.toPublicJWK());
        var statusListJwt = StatusListGenerator.createTokenStatusListTokenVerifiableCredential(StatusListGenerator.SPEC_STATUS_LIST, testKey, "did:example", testKey.getKeyID());
        when(statusListResolver.resolveStatusList(eq(StatusListGenerator.SPEC_SUBJECT))).thenReturn(statusListJwt);

        var statusList = assertDoesNotThrow(() -> cacheService.getTokenStatusListTokenByUri(StatusListGenerator.SPEC_SUBJECT));
        assertDoesNotThrow(() -> cacheService.getTokenStatusListTokenByUri(StatusListGenerator.SPEC_SUBJECT));

        verify(didJwtValidator, times(1)).validateJwt(eq(statusListJwt), any(JWK.class));
        assertThat(statusList).isNotNull();
        assertThat(statusList.getStatusList()).isNotNull();
        assertThat(statusList.getExp()).isNotNull().isNotZero();
        assertThat(statusList.getTtl()).isNotNull().isNotZero();
    }


    /**
     * Test mocking a valid Token Status List resolution
     */
    @Test
    void testGetTokenStatusListTokenByUri_noCache() throws Exception {
        when(trustRegistryProperties.maxCacheTtlSeconds()).thenReturn(0L);
        // Must create cache serivce here, as when initiated the TTL is set for the cache
        cacheService = new StatusListCacheService(swiyuProperties, didJwtValidator, issuerPublicKeyLoader, statusListResolver);
        ECKey testKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("did:webvh:example.com#key-1")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        when(issuerPublicKeyLoader.resolveKey(eq(testKey.getKeyID()))).thenReturn(testKey.toPublicJWK());
        var statusListJwt = StatusListGenerator.createTokenStatusListTokenVerifiableCredential(StatusListGenerator.SPEC_STATUS_LIST, testKey, "did:example", testKey.getKeyID());

        when(statusListResolver.resolveStatusList(eq(StatusListGenerator.SPEC_SUBJECT))).thenReturn(statusListJwt);

        var statusList = assertDoesNotThrow(() -> cacheService.getTokenStatusListTokenByUri(StatusListGenerator.SPEC_SUBJECT));
        // Ensure data is returned
        assertThat(statusList).isNotNull();
        assertThat(statusList.getStatusList()).isNotNull();
        assertThat(statusList.getExp()).isNotNull().isNotZero();
        assertThat(statusList.getTtl()).isNotNull().isNotZero();
        // Second Invocation to prove nothing is cached
        // Note: cache.getEstimatedSize() is flaky
        assertDoesNotThrow(() -> cacheService.getTokenStatusListTokenByUri(StatusListGenerator.SPEC_SUBJECT));
        verify(didJwtValidator, times(2)).validateJwt(eq(statusListJwt), any(JWK.class));
    }
}
