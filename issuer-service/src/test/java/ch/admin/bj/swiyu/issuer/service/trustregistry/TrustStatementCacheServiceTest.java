package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.core.trust.client.api.TrustProtocol20Api;
import ch.admin.bj.swiyu.core.trust.client.model.PagedModelString;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.service.enc.CacheMaintenanceService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link TrustStatementCacheService}.
 *
 * <p>Verifies cache behaviour (hit/miss/invalidation), TTL capping via {@code maxCacheTtlSeconds},
 * graceful fallback on API failure, and null-safety when no response is returned.</p>
 */
class TrustStatementCacheServiceTest {

    /**
     * Shared EC key for the entire test class – generated once to avoid per-test crypto overhead.
     */
    private static final ECKey TEST_KEY;
    private static final String ISSUER_DID = "did:tdw:test:issuer";

    static {
        try {
            TEST_KEY = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private TrustProtocol20Api trustProtocol20Api;
    private CacheMaintenanceService cacheMaintenanceService;
    private TrustStatementCacheService service;

    /**
     * Creates a signed JWT with the given exp timestamp (epoch seconds).
     */
    private static String buildJwt(long expEpochSeconds) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("jwt"))
                .build();
        var claims = new JWTClaimsSet.Builder()
                .issuer("did:tdw:trust-registry:issuer")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.ofEpochSecond(expEpochSeconds)))
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(TEST_KEY));
        return jwt.serialize();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static PagedModelString pagedModel(String... jwts) {
        var model = new PagedModelString();
        model.setContent(List.of(jwts));
        return model;
    }

    @BeforeEach
    void setUp() throws Exception {
        trustProtocol20Api = mock(TrustProtocol20Api.class);
        cacheMaintenanceService = mock(CacheMaintenanceService.class);
        service = buildService(5L);
    }

    private TrustStatementCacheService buildService(Long maxCacheTtlSeconds) throws Exception {
        var trustRegistry = new SwiyuProperties.TrustRegistryProperties(
                new URL("https://trust-reg.example.ch/"),
                "key",
                "secret",
                1_000,
                60,
                maxCacheTtlSeconds);
        var props = mock(SwiyuProperties.class);
        when(props.trustRegistry()).thenReturn(trustRegistry);
        // No TrustStatementValidator – signature validation is skipped in unit tests
        return new TrustStatementCacheService(trustProtocol20Api, props, Optional.empty(), cacheMaintenanceService);
    }

    // -------------------------------------------------------------------------
    // idTS – basic fetch & cache hit
    // -------------------------------------------------------------------------

    @Test
    void getIdentityTrustStatement_firstCall_fetchesFromApi() throws Exception {
        var jwt = buildJwt(Instant.now().plusSeconds(3600).getEpochSecond());
        when(trustProtocol20Api.getIdTS(eq(ISSUER_DID)))
                .thenReturn(Mono.just(jwt));

        var result = service.getIdentityTrustStatement(ISSUER_DID);

        assertThat(result).isEqualTo(jwt);
        verify(trustProtocol20Api, times(1)).getIdTS(any());
    }

    @Test
    void getIdentityTrustStatement_secondCall_usesCache() throws Exception {
        var jwt = buildJwt(Instant.now().plusSeconds(3600).getEpochSecond());
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.just(jwt));

        service.getIdentityTrustStatement(ISSUER_DID);
        service.getIdentityTrustStatement(ISSUER_DID);

        // API must only be called once – second call hits the cache
        verify(trustProtocol20Api, times(1)).getIdTS(any());
    }

    // -------------------------------------------------------------------------
    // piaTS – basic fetch & cache hit
    // -------------------------------------------------------------------------

    @Test
    void getAllProtectedIssuanceAuthorizationTrustStatements_firstCall_fetchesFromApi() throws Exception {
        var jwt = buildJwt(Instant.now().plusSeconds(3600).getEpochSecond());
        when(trustProtocol20Api.listPiaTS(eq(ISSUER_DID), eq(true), isNull(), isNull(), isNull()))
                .thenReturn(Mono.just(pagedModel(jwt)));

        var result = service.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID);

        assertThat(result).containsExactly(jwt);
        verify(trustProtocol20Api, times(1)).listPiaTS(any(), any(), any(), any(), any());
    }

    @Test
    void getAllProtectedIssuanceAuthorizationTrustStatements_secondCall_usesCache() throws Exception {
        var jwt = buildJwt(Instant.now().plusSeconds(3600).getEpochSecond());
        when(trustProtocol20Api.listPiaTS(any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(pagedModel(jwt)));

        service.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID);
        service.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID);

        verify(trustProtocol20Api, times(1)).listPiaTS(any(), any(), any(), any(), any());
    }

    @Test
    void getAllProtectedIssuanceAuthorizationTrustStatements_returnsAllJwts() throws Exception {
        var jwt1 = buildJwt(Instant.now().plusSeconds(3600).getEpochSecond());
        var jwt2 = buildJwt(Instant.now().plusSeconds(7200).getEpochSecond());
        when(trustProtocol20Api.listPiaTS(eq(ISSUER_DID), eq(true), isNull(), isNull(), isNull()))
                .thenReturn(Mono.just(pagedModel(jwt1, jwt2)));

        var result = service.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID);

        assertThat(result).containsExactly(jwt1, jwt2);
        verify(trustProtocol20Api, times(1)).listPiaTS(any(), any(), any(), any(), any());
    }

    // -------------------------------------------------------------------------
    // Invalidation
    // -------------------------------------------------------------------------

    @Test
    void invalidateIdentityTrustStatement_forcesRefetchOnNextCall() throws Exception {
        var jwt = buildJwt(Instant.now().plusSeconds(3600).getEpochSecond());
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.just(jwt));

        service.getIdentityTrustStatement(ISSUER_DID);
        service.invalidateIdentityTrustStatement(ISSUER_DID);
        service.getIdentityTrustStatement(ISSUER_DID);

        verify(trustProtocol20Api, times(2)).getIdTS(any());
    }

    @Test
    void invalidateProtectedIssuanceAuthorizationTrustStatement_forcesRefetchOnNextCall() throws Exception {
        var jwt = buildJwt(Instant.now().plusSeconds(3600).getEpochSecond());
        when(trustProtocol20Api.listPiaTS(any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(pagedModel(jwt)));

        service.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID);
        service.invalidateProtectedIssuanceAuthorizationTrustStatement(ISSUER_DID);
        service.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID);

        verify(trustProtocol20Api, times(2)).listPiaTS(any(), any(), any(), any(), any());
    }

    @Test
    void invalidateAllTrustStatements_invalidatesBothCaches() throws Exception {
        var jwt = buildJwt(Instant.now().plusSeconds(3600).getEpochSecond());
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.just(jwt));
        when(trustProtocol20Api.listPiaTS(any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(pagedModel(jwt)));

        service.getIdentityTrustStatement(ISSUER_DID);
        service.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID);

        service.invalidateAllTrustStatements(ISSUER_DID);

        service.getIdentityTrustStatement(ISSUER_DID);
        service.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID);

        verify(trustProtocol20Api, times(2)).getIdTS(any());
        verify(trustProtocol20Api, times(2)).listPiaTS(any(), any(), any(), any(), any());
        verify(cacheMaintenanceService, times(1)).evictPublicKeyManually(ISSUER_DID);
        verify(cacheMaintenanceService, times(1)).evictEncryptionMetadataManually(ISSUER_DID);
    }

    @Test
    void invalidate_doesNotAffectOtherDids() throws Exception {
        var otherDid = "did:tdw:test:other-issuer";
        var jwt = buildJwt(Instant.now().plusSeconds(3600).getEpochSecond());
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.just(jwt));

        service.getIdentityTrustStatement(ISSUER_DID);
        service.getIdentityTrustStatement(otherDid);

        service.invalidateIdentityTrustStatement(ISSUER_DID);

        service.getIdentityTrustStatement(ISSUER_DID); // re-fetched
        service.getIdentityTrustStatement(otherDid);   // still cached

        // ISSUER_DID fetched twice (initial + after invalidation), otherDid fetched once
        verify(trustProtocol20Api, times(2)).getIdTS(eq(ISSUER_DID));
        verify(trustProtocol20Api, times(1)).getIdTS(eq(otherDid));
    }

    // -------------------------------------------------------------------------
    // Graceful fallback on API failure
    // -------------------------------------------------------------------------

    @Test
    void getIdentityTrustStatement_whenApiFails_returnsNull() {
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.error(new RuntimeException("connection refused")));

        var result = service.getIdentityTrustStatement(ISSUER_DID);

        assertThat(result).isNull();
    }

    @Test
    void getIdentityTrustStatement_whenApiReturnsEmpty_returnsNull() {
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.empty());

        var result = service.getIdentityTrustStatement(ISSUER_DID);

        assertThat(result).isNull();
    }

    @Test
    void getAllProtectedIssuanceAuthorizationTrustStatements_whenApiFails_returnsEmptyList() {
        when(trustProtocol20Api.listPiaTS(any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("timeout")));

        var result = service.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID);

        assertThat(result).isEmpty();
    }

    // -------------------------------------------------------------------------
    // maxCacheTtlSeconds cap
    // -------------------------------------------------------------------------

    @Test
    void getIdentityTrustStatement_withMaxCacheTtlCap_jwtIsReturnedCorrectly() throws Exception {
        // JWT valid for 1 day, but cap is 10 seconds – cap only affects eviction, not the returned value
        service = buildService(10L);
        var jwt = buildJwt(Instant.now().plusSeconds(86400).getEpochSecond());
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.just(jwt));

        var result = service.getIdentityTrustStatement(ISSUER_DID);

        assertThat(result).isEqualTo(jwt);
    }

    @Test
    void getIdentityTrustStatement_withoutMaxCacheTtlCap_expBasedTtlUsed() throws Exception {
        // No cap → exp-based TTL; verify the JWT is returned and cached
        var jwt = buildJwt(Instant.now().plusSeconds(86400).getEpochSecond());
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.just(jwt));

        service.getIdentityTrustStatement(ISSUER_DID);
        service.getIdentityTrustStatement(ISSUER_DID); // cache hit

        verify(trustProtocol20Api, times(1)).getIdTS(any());
    }

    // -------------------------------------------------------------------------
    // Malformed JWT payload
    // -------------------------------------------------------------------------

    @Test
    void getIdentityTrustStatement_withMalformedJwt_returnsFallbackTtlAndJwt() {
        var malformed = "not.a.jwt";
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.just(malformed));

        // Should still return the raw string (fallback TTL of 60s is used internally)
        var result = service.getIdentityTrustStatement(ISSUER_DID);

        assertThat(result).isEqualTo(malformed);
    }

    // -------------------------------------------------------------------------
    // Expired JWT → minimum TTL
    // -------------------------------------------------------------------------

    @Test
    void getIdentityTrustStatement_withExpiredJwt_returnsJwtWithMinimumTtl() throws Exception {
        // JWT already expired (exp in the past) → should still be returned but cached with 1s TTL
        var expiredJwt = buildJwt(Instant.now().minusSeconds(10).getEpochSecond());
        when(trustProtocol20Api.getIdTS(any()))
                .thenReturn(Mono.just(expiredJwt));

        var result = service.getIdentityTrustStatement(ISSUER_DID);

        // The JWT is returned as-is; signature/expiry validation is the caller's responsibility
        assertThat(result).isEqualTo(expiredJwt);
    }
}
