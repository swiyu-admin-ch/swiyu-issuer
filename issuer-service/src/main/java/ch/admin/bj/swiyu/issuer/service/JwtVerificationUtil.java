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

import java.text.ParseException;
import java.util.Map;

/**
 * Utility for JWT signature verification and JWSVerifier creation.
 */
@UtilityClass
public class JwtVerificationUtil {
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
            throw new JOSEException("No matching key found for JWT");
        }
        JWSVerifier verifier = buildVerifier(key.getKeyType(), key);
        if (!jwt.verify(verifier)) {
            throw new JOSEException("JWT signature verification failed");
        }
        return jwt.getJWTClaimsSet().toJSONObject();
    }

    /**
     * Creates a JWSVerifier for EC or RSA keys.
     * @param kty KeyType
     * @param key JWK
     * @return JWSVerifier
     * @throws JOSEException if key type is unsupported
     */
    JWSVerifier buildVerifier(KeyType kty, JWK key) throws JOSEException {
        if (KeyType.EC.equals(kty)) {
            return new ECDSAVerifier(key.toECKey().toPublicJWK());
        } else if (KeyType.RSA.equals(kty)) {
            return new RSASSAVerifier(key.toRSAKey().toPublicJWK());
        }
        throw new JOSEException("Unsupported Key Type " + kty);
    }
}
