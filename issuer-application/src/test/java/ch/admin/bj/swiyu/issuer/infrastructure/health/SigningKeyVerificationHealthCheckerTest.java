package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.bj.swiyu.issuer.service.SignatureService;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for shared abstract signing key verification health checker logic.
 */
class SigningKeyVerificationHealthCheckerTest {

    private KeyResolver keyResolver;
    private SignatureService signatureService;
    private SdjwtProperties properties;

    // Concrete minimal subclass to expose performCheck
    private static class TestChecker extends AbstractSigningKeyVerificationHealthChecker<SdjwtProperties> {
        protected TestChecker(KeyResolver keyResolver, SignatureService signatureService, SdjwtProperties properties) {
            super(keyResolver, signatureService, properties);
        }
    }

    @BeforeEach
    void setup() throws JOSEException, KeyStrategyException, ParseException {
        keyResolver = Mockito.mock(KeyResolver.class);
        signatureService = Mockito.mock(SignatureService.class);
        properties = new SdjwtProperties();
        properties.setVerificationMethod("did:example:123#key-1");

        // Provide a mock JWK for DID resolution (public EC key)
        var ecKey = new ECKeyGenerator(Curve.P_256).keyID("test-key").generate();
        when(keyResolver.resolveKey("did:example:123")).thenReturn(JWK.parse(ecKey.toPublicJWK().toJSONString()));

        // Provide a signer that can sign ES256
        JWSSigner signer = new ECDSASigner(ecKey.toECPrivateKey());
        when(signatureService.createSigner(any(), any(), any())).thenReturn(signer);
    }

    @Test
    void performCheck_successfulVerification_setsUpStatus() {
        var checker = new TestChecker(keyResolver, signatureService, properties);
        Health.Builder builder = Health.up(); // initial state, will be overridden
        checker.performCheck(builder);
        var result = builder.build();
        assertEquals(Status.UP, result.getStatus());
        assertTrue(result.getDetails().containsKey("signingKeyVerificationMethod"));
        assertEquals("did:example:123#key-1", result.getDetails().get("signingKeyVerificationMethod"));
    }

    @Test
    void performCheck_failedDidResolution_setsDownStatus() {
        properties.setVerificationMethod("did:example:unknown#k1");
        when(keyResolver.resolveKey("did:example:unknown")).thenReturn(null); // simulate failure
        var checker = new TestChecker(keyResolver, signatureService, properties);
        Health.Builder builder = Health.up();
        checker.performCheck(builder);
        var result = builder.build();
        assertEquals(Status.DOWN, result.getStatus());
        assertTrue(result.getDetails().containsKey("failedDids"));
        assertEquals("did:example:unknown#k1", result.getDetails().get("failedDids"));
    }
}

