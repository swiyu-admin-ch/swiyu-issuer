package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Instant;
import java.util.Date;
import java.util.List;

class AttestationJwtTest {
    /**
     * If only the issuer is checked for being trusted and the key id is used to resolve the public key, it is
     */
    @ParameterizedTest(name = "should reject JWT when attackerKeyID={0}, issuerDid={1}")
    @CsvSource({
            "did:example:12345#key-1, did:example:9876",
            "did:example:trusted-fake#key-1, did:example:trusted"
    })
    void whenDivergingIssuerAndKid_thenThrowIllegalArgumentException(String attackerKeyID, String issuerDid) throws JOSEException {
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID(attackerKeyID).keyUse(KeyUse.SIGNATURE).generate();
        var attestation = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("key-attestation+jwt"))
                .build(),
                new JWTClaimsSet.Builder()
                        .issuer(issuerDid)
                        .issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(5)))
                        .claim("attested_keys", List.of(signingKey.toPublicJWK().toJSONObject()))
                        .build());
        attestation.sign(new ECDSASigner(signingKey));
        var parsedJwt = attestation.serialize();
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(parsedJwt));
    }

    /**
     * If only the issuer is checked for being trusted and the key id is used to resolve the public key, it is
     */
    @ParameterizedTest(name = "should reject JWT when attackerKeyID={0}, issuerDid={1}")
    @CsvSource({
            "did:example:12345#key-1, did:example:9876",
            "did:example:trusted-fake#key-1, did:example:trusted"
    })
    void whenDivergingIssuerAndKidUsingKeyStorage_thenThrowIllegalArgumentException(String attackerKeyID, String issuerDid) throws JOSEException {
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID(attackerKeyID).keyUse(KeyUse.SIGNATURE).generate();
        var attestation = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("key-attestation+jwt"))
                .build(),
                new JWTClaimsSet.Builder()
                        .issuer(issuerDid)
                        .issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(5)))
                        .claim("attested_keys", List.of(signingKey.toPublicJWK().toJSONObject()))
                        .claim("key_storage", List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC.getValue()))
                        .build());
        attestation.sign(new ECDSASigner(signingKey));
        var parsedJwt = attestation.serialize();
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(parsedJwt));
    }
}