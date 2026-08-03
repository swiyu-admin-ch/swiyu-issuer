package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils.prepareSigner;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class ProofJwtTest {

    private static final List<String> SUPPORTED_ALGORITHMS = List.of("ES256", "Ed25519");
    private static IssuerSecret nonceSecret = IssuerSecret.builder().id(UUID.randomUUID()).build();

    @ParameterizedTest
    @MethodSource("createProofKey")
    void givenNoKey_whenHolderBindingValidate_thenThrow(JWK jwk) throws JOSEException {
        var signerSupport = prepareSigner(jwk);
        var nonce = getNonce();
        var aud = "http://issuer.com";
        var headerBuilder = new JWSHeader.Builder(signerSupport.alg())
                .type(new JOSEObjectType(ProofType.JWT.getClaimTyp()));
        JWSHeader header = headerBuilder
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("aud", aud)
                .issueTime(new Date())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signerSupport.signer());
        var proof = jwt.serialize();

        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120, nonceSecret);
        var offer = createTestOffer();

        var audience = "http://issuer.com";
        var algorithms = SUPPORTED_ALGORITHMS;
        var expirationTimestamp = offer.getOfferExpirationTimestamp();
        var exc = assertThrows(Oid4vcException.class,
                () -> proofJwt.isValidHolderBinding(audience, algorithms, expirationTimestamp));
        assertTrue(exc.getMessage().contains("No valid holder key binding was found in the proof header"));
    }

    @ParameterizedTest
    @MethodSource("createProofKey")
    void givenLegacyHolderKeyBinding_whenHolderBindingValidation_thenThrow(JWK jwk) throws JOSEException {
        var signerSupport = prepareSigner(jwk);
        var nonce = getNonce();
        var aud = "http://issuer.com";
        var headerBuilder = new JWSHeader.Builder(signerSupport.alg())
                .type(new JOSEObjectType(ProofType.JWT.getClaimTyp()));
        headerBuilder.keyID("did:jwk:notvalid");
        JWSHeader header = headerBuilder
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("aud", aud)
                .issueTime(new Date())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signerSupport.signer());
        var proof = jwt.serialize();

        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120, nonceSecret);

        String audience = "http://issuer.com";
        List<String> algorithms = SUPPORTED_ALGORITHMS;
        Long expirationTimestamp = Instant.now().plusSeconds(600).getEpochSecond();
        var exc = assertThrows(Oid4vcException.class,
                () -> proofJwt.isValidHolderBinding(audience, algorithms, expirationTimestamp));

        assertThat(exc.getMessage()).contains("No valid holder key binding was found in the proof header");
    }

    @ParameterizedTest
    @MethodSource("createProofKey")
    void givenValidKidAttributeRepresentation_whenHolderBindingValidate_thenValid_(JWK jwk) throws JOSEException {
        // Check holder proof
        var nonce = getNonce();
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp());
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120, nonceSecret);
        assertTrue(proofJwt.isValidHolderBinding("http://issuer.com", SUPPORTED_ALGORITHMS, Instant.now().plusSeconds(600).getEpochSecond()));
    }

    @ParameterizedTest
    @MethodSource("createProofKey")
    void givenValidJwkAttributeRepresentation_whenHolderBindingValidate_thenValid_(JWK jwk) throws JOSEException {
        // Check holder proof
        var nonce = getNonce();
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp());
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120, nonceSecret);
        assertTrue(proofJwt.isValidHolderBinding("http://issuer.com", SUPPORTED_ALGORITHMS, Instant.now().plusSeconds(600).getEpochSecond()));
    }

    @ParameterizedTest
    @MethodSource("createProofKey")
    void givenExpiredNonce_whenIsValidHolderBinding_thenThrowProofException(JWK jwk) throws JOSEException {
        var nonce = UUID.randomUUID() + "::" + Instant.now().minus(1, ChronoUnit.DAYS).toString() + "::notCheckedHash";
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp());
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120, nonceSecret);
        var exception = assertThrows(Oid4vcException.class, () -> proofJwt.isValidHolderBinding("http://issuer.com", SUPPORTED_ALGORITHMS, Instant.now().getEpochSecond()));
        assertEquals("Nonce is expired", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("createProofKey")
    void givenInvalidNonce_whenIsValidHolderBinding_thenThrowProofException(JWK jwk) throws JOSEException {
        var nonce = UUID.randomUUID() + "::" + "::notCheckedHash";
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp());
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120, nonceSecret);
        var exception = assertThrows(Oid4vcException.class, () -> proofJwt.isValidHolderBinding("http://issuer.com", SUPPORTED_ALGORITHMS, Instant.now().getEpochSecond()));
        assertEquals("Invalid nonce claim in proof JWT", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("createProofKey")
    void givenExpiredToken_whenIsValidHolderBinding_thenThrowProofException(JWK jwk) throws JOSEException {
        var nonce = getNonce();
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp());
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120, nonceSecret);
        var exception = assertThrows(Oid4vcException.class, () -> proofJwt.isValidHolderBinding("http://issuer.com", SUPPORTED_ALGORITHMS, Instant.now().minusSeconds(10).getEpochSecond()));
        assertEquals("Token is expired", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("createProofKey")
    void givenNoBinding_whenGetBinding_thenThrowIllegalStateException(JWK jwk) throws JOSEException {
        var nonce = getNonce();
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp());
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120, nonceSecret);
        var exception = assertThrows(IllegalStateException.class, () -> proofJwt.getBinding());
        assertEquals("Must first call isValidHolderBinding", exception.getMessage());
    }

    private CredentialOffer createTestOffer() {

        return CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(CredentialOfferStatusType.OFFERED)
                .metadataCredentialSupportedId(Collections.emptyList())
                .offerData(new HashMap<>() {{
                    put("data", "data");
                    put("otherStuff", "data");
                }})
                .preAuthorizedCode(UUID.randomUUID())
                .offerExpirationTimestamp(120L)
                .deferredOfferValiditySeconds(120)
                .credentialValidFrom(Instant.now())
                .build();
    }

    private static Stream<JWK> createProofKey() throws JOSEException {
        return Stream.of(new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .algorithm(JWSAlgorithm.ES256)
                .generate(),
        new OctetKeyPairGenerator(Curve.Ed25519)
            .keyUse(KeyUse.SIGNATURE)
            .keyID("Test-Key")
            .issueTime(new Date())
            .algorithm(JWSAlgorithm.Ed25519)
            .generate());
    }

    private @NotNull String getNonce() {
        return new SelfContainedNonce(nonceSecret).getNonce();
    }
}