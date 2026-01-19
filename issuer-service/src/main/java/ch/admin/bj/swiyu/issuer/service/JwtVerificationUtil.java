package ch.admin.bj.swiyu.issuer.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;

import java.io.Serial;
import java.text.ParseException;
import java.util.Map;
import java.util.function.Function;
import java.util.HashMap;

/**
 * Utility for JWT signature verification and JWSVerifier creation.
 */
@UtilityClass
public class JwtVerificationUtil {
    /**
     * Registry for JWSVerifier factories by KeyType.
     * Add new key types here for extensibility.
     */
    private static final Map<KeyType, Function<JWK, JWSVerifier>> VERIFIER_FACTORIES = new HashMap<>();
    static {
        VERIFIER_FACTORIES.put(KeyType.EC, key -> {
            try {
                return new ECDSAVerifier(key.toECKey().toPublicJWK());
            } catch (JOSEException e) {
                throw new JwtVerifierFactoryException("Failed to create EC verifier", e);
            }
        });
        VERIFIER_FACTORIES.put(KeyType.RSA, key -> {
            try {
                return new RSASSAVerifier(key.toRSAKey().toPublicJWK());
            } catch (JOSEException e) {
                throw new JwtVerifierFactoryException("Failed to create RSA verifier", e);
            }
        });
    }

    /**
     * Verifies JWT signature and returns claims as a map.
     * @param jwtString JWT string
     * @param keySet JWKSet for key lookup
     * @return JWT claims as map
     * @throws JOSEException if verification fails
     * @throws ParseException if JWT is invalid
     */
    public Map<String, Object> verifyJwt(String jwtString, JWKSet keySet) throws JOSEException, ParseException {
        SignedJWT jwt = SignedJWT.parse(jwtString);
        JWSHeader header = jwt.getHeader();
        JWK key = keySet.getKeyByKeyId(header.getKeyID());
        if (key == null) {
            throw new JOSEException("Data Integrity of offer could not be verified. No matching key found");
        }
        JWSVerifier verifier = buildVerifier(key.getKeyType(), key);
        if (!jwt.verify(verifier)) {
            throw new JOSEException("JWT signature verification failed");
        }
        return jwt.getJWTClaimsSet().toJSONObject();
    }

    /**
     * Creates a JWSVerifier for supported key types using the registry.
     * @param kty KeyType
     * @param key JWK
     * @return JWSVerifier
     * @throws JOSEException if key type is unsupported
     */
    public JWSVerifier buildVerifier(KeyType kty, JWK key) throws JOSEException {
        Function<JWK, JWSVerifier> factory = VERIFIER_FACTORIES.get(kty);
        if (factory == null) {
            throw new JOSEException("Unsupported Key Type " + kty);
        }
        return factory.apply(key);
    }

    /**
     * Custom exception for verifier factory errors.
     */
    public static class JwtVerifierFactoryException extends RuntimeException {
        @Serial
        private static final long serialVersionUID = 1L;

        public JwtVerifierFactoryException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
