package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class ProofJwtTest {

    private static ECKey jwk;

    @BeforeEach
    void setUp() throws JOSEException {
        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();
    }

    @Test
    void givenNoKey_whenHolderBindingValidate_thenThrow() throws JOSEException {
        var nonce = getNonce();
        var aud = "http://issuer.com";
        var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ProofType.JWT.getClaimTyp()));
        JWSHeader header = headerBuilder
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("aud", aud)
                .issueTime(new Date())
                .build();
        JWSSigner signer = new ECDSASigner(jwk);
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        var proof = jwt.serialize();

        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120);
        var offer = createTestOffer();

        var audience = "http://issuer.com";
        var algorithms = List.of("ES256");
        var expirationTimestamp = offer.getOfferExpirationTimestamp();
        var exc = assertThrows(Oid4vcException.class,
                () -> proofJwt.isValidHolderBinding(audience, algorithms, expirationTimestamp));
        assertTrue(exc.getMessage().contains("None of the supported binding method/s was found in the header"));
    }

    @Test
    void givenUnsupportedDidMethod_whenHolderBindingValidate_thenThrow() throws JOSEException {
        var nonce = getNonce();
        var aud = "http://issuer.com";
        var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ProofType.JWT.getClaimTyp()));
        headerBuilder.keyID("did:tdw:notvalid");
        JWSHeader header = headerBuilder
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("aud", aud)
                .issueTime(new Date())
                .build();
        JWSSigner signer = new ECDSASigner(jwk);
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        var proof = jwt.serialize();

        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120);

        String audience = "http://issuer.com";
        List<String> algorithms = List.of("ES256");
        Long expirationTimestamp = Instant.now().plusSeconds(600).getEpochSecond();
        var exc = assertThrows(Oid4vcException.class,
                () -> proofJwt.isValidHolderBinding(audience, algorithms, expirationTimestamp));

        assertTrue(exc.getMessage().contains("Did method provided in kid attribute did:tdw is not supported"));
    }

    @Test
    void givenInvalidJwtDidKeyRepresentation_whenHolderBindingValidate_thenThrow() throws JOSEException {
        var nonce = getNonce();
        var aud = "http://issuer.com";
        var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ProofType.JWT.getClaimTyp()));
        headerBuilder.keyID("did:jwk:notvalid");
        JWSHeader header = headerBuilder
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("aud", aud)
                .issueTime(new Date())
                .build();
        JWSSigner signer = new ECDSASigner(jwk);
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        var proof = jwt.serialize();

        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120);
        String audience = "http://issuer.com";
        List<String> algorithms = List.of("ES256");
        Long expirationTimestamp = Instant.now().plusSeconds(600).getEpochSecond();
        var exc = assertThrows(Oid4vcException.class,
                () -> proofJwt.isValidHolderBinding(audience, algorithms, expirationTimestamp));
        assertTrue(exc.getMessage().contains("could not be parsed to a JWK"));
    }

    @Test
    void givenValidKidAttributeRepresentation_whenHolderBindingValidate_thenValid_() throws JOSEException {
        // Check holder proof with didJwk
        var nonce = getNonce();
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp(), true);
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120);
        assertTrue(proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), Instant.now().plusSeconds(600).getEpochSecond()));
    }

    @Test
    void givenValidJwkAttributeRepresentation_whenHolderBindingValidate_thenValid_() throws JOSEException {
        // Check holder proof with didJwk
        var nonce = getNonce();
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp(), false);
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120);
        assertTrue(proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), Instant.now().plusSeconds(600).getEpochSecond()));
    }

    @Test
    void givenExpiredNonce_whenIsValidHolderBinding_thenThrowProofException() throws JOSEException {
        var nonce = UUID.randomUUID() + "::" + Instant.now().minus(1, ChronoUnit.DAYS).toString();
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp(), true);
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120);
        var exception = assertThrows(Oid4vcException.class, () -> proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), Instant.now().getEpochSecond()));
        assertEquals("Nonce is expired", exception.getMessage());
    }

    @Test
    void givenInvalidNonce_whenIsValidHolderBinding_thenThrowProofException() throws JOSEException {
        var nonce = UUID.randomUUID() + "::";
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp(), true);
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120);
        var exception = assertThrows(Oid4vcException.class, () -> proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), Instant.now().getEpochSecond()));
        assertEquals("Invalid nonce claim in proof JWT", exception.getMessage());
    }

    @Test
    void givenExpiredToken_whenIsValidHolderBinding_thenThrowProofException() throws JOSEException {
        var nonce = getNonce();
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp(), true);
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120);
        var exception = assertThrows(Oid4vcException.class, () -> proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), Instant.now().minusSeconds(10).getEpochSecond()));
        assertEquals("Token is expired", exception.getMessage());
    }

    @Test
    void givenNoBinding_whenGetBinding_thenThrowIllegalStateException() throws JOSEException {
        var nonce = getNonce();
        String proof = TestServiceUtils.createHolderProof(jwk, "http://issuer.com", nonce, ProofType.JWT.getClaimTyp(), true);
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof, 10, 120);
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

    private @NotNull String getNonce() {
        return UUID.randomUUID() + "::" + Instant.now().toString();
    }
}