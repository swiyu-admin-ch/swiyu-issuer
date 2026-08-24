package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.TokenStatusListToken;
import ch.admin.bj.swiyu.issuer.service.JwsSignatureFacade;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link StatusListSigningService}.
 */
class StatusListSigningServiceTest {

    private ApplicationProperties applicationProperties;
    private StatusListProperties statusListProperties;
    private JwsSignatureFacade jwsSignatureFacade;
    private StatusListSigningService sut;

    @BeforeEach
    void setUp() {
        applicationProperties = mock(ApplicationProperties.class);
        statusListProperties = mock(StatusListProperties.class);
        jwsSignatureFacade = mock(JwsSignatureFacade.class);

        when(applicationProperties.getIssuerId()).thenReturn("did:example:issuer");
        when(statusListProperties.getVerificationMethod()).thenReturn("did:example:vm#1");

        sut = new StatusListSigningService(applicationProperties, statusListProperties, jwsSignatureFacade);
    }

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void buildSignedStatusListJwt_successfulSigning_returnsSignedJwt(JWSSigner signer) throws Exception {
        // Arrange
        var statusList = StatusList.builder()
                .uri("https://registry.example/status/uuid-1234")
                .configurationOverride(new ConfigurationOverride(null, "did:example:vm#override", null, null))
                .build();

        TokenStatusListToken token = new TokenStatusListToken(2, 8);

        // Use a real ES256 signer to exercise Nimbus signing flow
        when(jwsSignatureFacade.createSigner(statusListProperties, null, null)).thenReturn(signer);

        // Act
        SignedJWT signed = sut.buildSignedStatusListJwt(statusList, token);

        // Assert
        assertNotNull(signed);

        // Verify header values
        JWSHeader header = signed.getHeader();
        assertEquals("statuslist+jwt", header.getType().getType());
        assertEquals(SwissProfileVersions.VC_PROFILE_VERSION, header.getCustomParam(SwissProfileVersions.PROFILE_VERSION_PARAM));

        // Verify claims
        var claims = signed.getJWTClaimsSet();
        assertEquals(applicationProperties.getIssuerId(), claims.getIssuer());
        assertEquals(statusList.getUri(), claims.getSubject());
        assertEquals(statusListProperties.getStatusListCacheTime().toSeconds(), ((Number) claims.getClaim("ttl")).intValue());
        assertNotNull(claims.getClaim("status_list"));
        assertTrue(((Map<?, ?>) claims.getClaim("status_list")).containsKey("bits"));
        assertTrue(((Map<?, ?>) claims.getClaim("status_list")).containsKey("lst"));
    }

    @Test
    void buildSignedStatusListJwt_throwsConfigurationException_onKeyStrategyError() throws KeyStrategyException {
        // Arrange
        var statusList = StatusList.builder().uri("https://registry.example/status/1").build();
        TokenStatusListToken token = new TokenStatusListToken(1, 4);

        when(jwsSignatureFacade.createSigner(statusListProperties, null, null)).thenThrow(new KeyStrategyException("bad", null));

        // Act / Assert
        assertThrows(ConfigurationException.class, () -> sut.buildSignedStatusListJwt(statusList, token));
    }

    @Test
    void buildSignedStatusListJwt_throwsConfigurationException_onJoseException() throws Exception {
        // Arrange
        var statusList = StatusList.builder().uri("https://registry.example/status/2").build();
        TokenStatusListToken token = new TokenStatusListToken(1, 4);

        JWSSigner failingSigner = mock(JWSSigner.class);
        when(failingSigner.sign(any(), any())).thenThrow(new JOSEException("simulated signing failure"));
        when(jwsSignatureFacade.createSigner(statusListProperties, null, null)).thenReturn(failingSigner);

        // Act / Assert
        assertThrows(ConfigurationException.class, () -> sut.buildSignedStatusListJwt(statusList, token));
    }

    private static Stream<JWSSigner> createTestSigner() throws JOSEException {
        return Stream.of(
            new ECDSASigner(
                new ECKeyGenerator(Curve.P_256)
                    .keyID("test-key")
                    .algorithm(JWSAlgorithm.ES256)
                    .keyUse(KeyUse.SIGNATURE)
                    .generate()),
            new Ed25519Signer(
                new OctetKeyPairGenerator(Curve.Ed25519)
                    .keyID("test-key")
                    .algorithm(JWSAlgorithm.Ed25519)
                    .keyUse(KeyUse.SIGNATURE)
                    .generate())
            );
    }
}

