package ch.admin.bj.swiyu.issuer.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JwtVerificationUtil.
 * Covers EC/RSA verification, missing key, and unsupported key type.
 */
class JwtVerificationUtilTest {
    /**
     * Verifies a valid EC JWT is accepted and claims are correct.
     */
    @Test
    void verifyJwt_validECKey_success() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec1").generate();
        JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("ec1").build(),
                new JWTClaimsSet.Builder().claim("foo", "bar").build()
        );
        jwt.sign(new ECDSASigner(ecKey));
        Map<String, Object> claims = JwtVerificationUtil.verifyJwt(jwt.serialize(), jwkSet);
        assertEquals("bar", claims.get("foo"));
    }

    /**
     * Verifies a valid RSA JWT is accepted and claims are correct.
     */
    @Test
    void verifyJwt_validRSAKey_success() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("rsa1").generate();
        JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("rsa1").build(),
                new JWTClaimsSet.Builder().claim("baz", 42).build()
        );
        jwt.sign(new RSASSASigner(rsaKey));
        Map<String, Object> claims = JwtVerificationUtil.verifyJwt(jwt.serialize(), jwkSet);
        assertEquals(42L, claims.get("baz"));
    }

    /**
     * Verifies that missing key in JWKSet throws exception.
     */
    @Test
    void verifyJwt_missingKey_throws() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec3").generate();
        JWKSet jwkSet = new JWKSet(); // No keys
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("ec3").build(),
                new JWTClaimsSet.Builder().claim("fail", true).build()
        );
        jwt.sign(new ECDSASigner(ecKey));
        assertThrows(JOSEException.class, () -> JwtVerificationUtil.verifyJwt(jwt.serialize(), jwkSet));
    }

    /**
     * Verifies that unsupported key type throws exception.
     */
    @Test
    void buildVerifier_unsupportedKeyType_throws() {
        JWK octKey = new OctetSequenceKey.Builder(new byte[]{1,2,3}).keyID("oct1").build();
        assertThrows(JOSEException.class, () -> JwtVerificationUtil.buildVerifier(octKey.getKeyType(), octKey));
    }
}
