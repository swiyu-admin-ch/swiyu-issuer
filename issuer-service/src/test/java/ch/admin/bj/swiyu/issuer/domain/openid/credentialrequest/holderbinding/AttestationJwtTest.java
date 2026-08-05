package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AttestationJwtTest {

    @Test
    void parseJwt_withValidJwt_returnsAttestationJwt() throws JOSEException {
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID("did:example:issuer#key-1").keyUse(KeyUse.SIGNATURE).generate();
        var attestation = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("key-attestation+jwt"))
                .customParam("profile_version", SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                .build(),
                new JWTClaimsSet.Builder()
                        .issuer("did:example:issuer")
                        .issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(5*60)))
                        .claim("attested_keys", List.of(signingKey.toPublicJWK().toJSONObject()))
                        .claim("key_storage", List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC.getValue()))
                        .build());
        attestation.sign(new ECDSASigner(signingKey));
        var parsedJwt = attestation.serialize();

        Assertions.assertDoesNotThrow(() -> AttestationJwt.parseJwt(parsedJwt, true));
    }

    /**
     * If only the issuer is checked for being trusted and the key id is used to resolve the public key, it is
     */
    @ParameterizedTest(name = "should reject JWT when attackerKeyID={0}, issuerDid={1}")
    @CsvSource({
            "did:example:12345#key-1, did:example:9876",
            "did:example:trusted-fake#key-1, did:example:trusted"
    })
    void parseJwt_withDivergingIssuerAndKid_throwsIllegalArgumentException(String attackerKeyID, String issuerDid) throws JOSEException {
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID(attackerKeyID).keyUse(KeyUse.SIGNATURE).generate();
        var attestation = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("key-attestation+jwt"))
                .customParam("profile_version", "swiss-profile-issuance:1.0.0")
                .build(),
                new JWTClaimsSet.Builder()
                        .issuer(issuerDid)
                        .issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(5 * 60)))
                        .claim("attested_keys", List.of(signingKey.toPublicJWK().toJSONObject()))
                        .build());
        attestation.sign(new ECDSASigner(signingKey));
        var parsedJwt = attestation.serialize();
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(parsedJwt, true));
    }

    /**
     * If only the issuer is checked for being trusted and the key id is used to resolve the public key, it is
     */
    @ParameterizedTest(name = "should reject JWT when attackerKeyID={0}, issuerDid={1}")
    @CsvSource({
            "did:example:12345#key-1, did:example:9876",
            "did:example:trusted-fake#key-1, did:example:trusted"
    })
    void parseJwt_withDivergingIssuerAndKidUsingKeyStorage_throwsIllegalArgumentException(String attackerKeyID, String issuerDid) throws JOSEException {
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID(attackerKeyID).keyUse(KeyUse.SIGNATURE).generate();
        var attestation = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("key-attestation+jwt"))
                .customParam("profile_version", "swiss-profile-issuance:1.0.0")
                .build(),
                new JWTClaimsSet.Builder()
                        .issuer(issuerDid)
                        .issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(5 * 60)))
                        .claim("attested_keys", List.of(signingKey.toPublicJWK().toJSONObject()))
                        .claim("key_storage", List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC.getValue()))
                        .build());
        attestation.sign(new ECDSASigner(signingKey));
        var parsedJwt = attestation.serialize();
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(parsedJwt , true));
    }

    @Test
    void parseJwt_withMissingProfileVersionHeader_throwsIllegalArgumentException() throws JOSEException {
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID("did:example:issuer#key-1").keyUse(KeyUse.SIGNATURE).generate();
        var attestation = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("key-attestation+jwt"))
                // intentionally no profile_version
                .build(),
                new JWTClaimsSet.Builder()
                        .issuer("did:example:issuer")
                        .issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(5*60)))
                        .claim("attested_keys", List.of(signingKey.toPublicJWK().toJSONObject()))
                        .claim("key_storage", List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC.getValue()))
                        .build());
        attestation.sign(new ECDSASigner(signingKey));
        var parsedJwt = attestation.serialize();

        Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(parsedJwt, true));
    }

    @Test
    void parseJwt_withMissingTypeHeader_throwsIllegalArgumentException() throws JOSEException {
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID("did:example:issuer#key-1").keyUse(KeyUse.SIGNATURE).generate();
        var attestation = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .customParam("profile_version", SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                // intentionally no profile_version
                .build(),
                new JWTClaimsSet.Builder()
                        .issuer("did:example:issuer")
                        .issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(5*60)))
                        .claim("attested_keys", List.of(signingKey.toPublicJWK().toJSONObject()))
                        .claim("key_storage", List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC.getValue()))
                        .build());
        attestation.sign(new ECDSASigner(signingKey));
        var parsedJwt = attestation.serialize();

        Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(parsedJwt, true));
    }

    @Test
    void parseJwt_withInvalidTypeHeader_throwsIllegalArgumentException() throws JOSEException {
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID("did:example:issuer#key-1").keyUse(KeyUse.SIGNATURE).generate();
        var attestation = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("unsupported type"))
                .customParam("profile_version", SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                .build(),
                new JWTClaimsSet.Builder()
                        .issuer("did:example:issuer")
                        .issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(5*60)))
                        .claim("attested_keys", List.of(signingKey.toPublicJWK().toJSONObject()))
                        .claim("key_storage", List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC.getValue()))
                        .build());
        attestation.sign(new ECDSASigner(signingKey));
        var parsedJwt = attestation.serialize();

        Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(parsedJwt, true));
    }

    @Test
    void parseJwt_expiresNow_success() throws JOSEException {
        var jwt = buildJwt(new Date(), new Date(), new Date());
        Assertions.assertDoesNotThrow(() -> AttestationJwt.parseJwt(jwt, true));
    }

    @Test
    void parseJwt_withExpiredToken_throwsIllegalArgumentException() throws JOSEException {
        var jwt = buildJwt(new Date(), Date.from(Instant.now().plusSeconds(-5 * 60)), new Date());
        var ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(jwt, true));
        assertThat(ex.getMessage()).contains("Attestation is expired");
    }

    @Test
    void parseJwt_withTokenNotYetReady_throwsIllegalArgumentException() throws JOSEException {
        var jwt = buildJwt(new Date(), Date.from(Instant.now().plusSeconds(5 * 60)), Date.from(Instant.now().plusSeconds(5 * 60)));
        var ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(jwt, true));
        assertThat(ex.getMessage()).contains("Attestation not yet valid");
    }

    @Test
    void parseJwt_withTokenIssuedInFuture_throwsIllegalArgumentException() throws JOSEException {
        var jwt = buildJwt(Date.from(Instant.now().plusSeconds(5 * 60)), Date.from(Instant.now().plusSeconds(5 * 60)), new Date());
        var ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> AttestationJwt.parseJwt(jwt, true));
        assertThat(ex.getMessage()).contains("IssueTime is in the future");
    }

    /**
     * Security regression test: proof key matches the SECOND entry in attested_keys.
     * With the early-return bug from PR #268 this would have returned false, rejecting
     * a legitimate holder whose key happened not to be first in the list.
     */
    @Test
    @DisplayName("containsKey returns true when proof key is the second attested key (multi-key iteration)")
    void containsKey_proofKeyIsSecondAttestedKey_returnsTrue() throws JOSEException, ParseException {
        var issuerKey = new ECKeyGenerator(Curve.P_256).keyID("did:example:issuer#key-1").keyUse(KeyUse.SIGNATURE).generate();
        var firstAttestedKey = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate();
        var secondAttestedKey = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate();

        AttestationJwt attestation = buildAttestation(issuerKey, List.of(firstAttestedKey, secondAttestedKey));

        assertThat(attestation.containsKey(secondAttestedKey.toPublicJWK())).isTrue();
    }

    /**
     * Baseline: proof key matches the first attested key – must also return true.
     */
    @Test
    @DisplayName("containsKey returns true when proof key is the first attested key")
    void containsKey_proofKeyIsFirstAttestedKey_returnsTrue() throws JOSEException, ParseException {
        var issuerKey = new ECKeyGenerator(Curve.P_256).keyID("did:example:issuer#key-1").keyUse(KeyUse.SIGNATURE).generate();
        var firstAttestedKey = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate();
        var secondAttestedKey = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate();

        AttestationJwt attestation = buildAttestation(issuerKey, List.of(firstAttestedKey, secondAttestedKey));

        assertThat(attestation.containsKey(firstAttestedKey.toPublicJWK())).isTrue();
    }

    /**
     * Security regression test (EIDSEC-793): proof key is not in attested_keys at all –
     * the key-mismatch attack vector must be rejected regardless of list size.
     */
    @Test
    @DisplayName("containsKey returns false when proof key is absent from all attested keys")
    void containsKey_proofKeyNotInAttestedKeys_returnsFalse() throws JOSEException, ParseException {
        var issuerKey = new ECKeyGenerator(Curve.P_256).keyID("did:example:issuer#key-1").keyUse(KeyUse.SIGNATURE).generate();
        var firstAttestedKey = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate();
        var secondAttestedKey = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate();
        var attackerKey = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate();

        AttestationJwt attestation = buildAttestation(issuerKey, List.of(firstAttestedKey, secondAttestedKey));

        assertThat(attestation.containsKey(attackerKey.toPublicJWK())).isFalse();
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    /**
     * Builds a minimal but structurally valid {@link AttestationJwt} signed by {@code issuerKey}
     * and containing all {@code attestedKeys} in its {@code attested_keys} claim.
     */
    private AttestationJwt buildAttestation(ECKey issuerKey, List<ECKey> attestedKeys) throws JOSEException, ParseException {
        var attestedKeyObjects = attestedKeys.stream()
                .map(k -> k.toPublicJWK().toJSONObject())
                .toList();

        var signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(issuerKey.getKeyID())
                        .type(new JOSEObjectType("key-attestation+jwt"))
                        .build(),
                new JWTClaimsSet.Builder()
                        .issuer(issuerKey.getKeyID().split("#")[0])
                        .issueTime(new Date())
                        .expirationTime(Date.from(Instant.now().plusSeconds(120)))
                        .claim("attested_keys", attestedKeyObjects)
                        .claim("key_storage", List.of(AttackPotentialResistance.ISO_18045_HIGH.getValue()))
                        .build());
        signedJwt.sign(new ECDSASigner(issuerKey));

        return AttestationJwt.parseJwt(signedJwt.serialize(), false);
    }

    private String buildJwt(Date iat, Date exp, Date nbf) throws JOSEException {
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID("did:example:issuer#key-1").keyUse(KeyUse.SIGNATURE).generate();
        var attestation = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("key-attestation+jwt"))
                .customParam("profile_version", SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                .build(),
                new JWTClaimsSet.Builder()
                        .issuer("did:example:issuer")
                        .issueTime(iat)
                        .expirationTime(exp)
                        .notBeforeTime(nbf)
                        .claim("attested_keys", List.of(signingKey.toPublicJWK().toJSONObject()))
                        .claim("key_storage", List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC.getValue()))
                        .build());
        attestation.sign(new ECDSASigner(signingKey));
        return attestation.serialize();
    }
}