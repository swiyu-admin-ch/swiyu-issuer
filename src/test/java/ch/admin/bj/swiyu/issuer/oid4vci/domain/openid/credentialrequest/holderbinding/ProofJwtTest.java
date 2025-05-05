package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestUtils;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ProofJwtTest {

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
        var nonce = UUID.randomUUID();
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

        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof);
        var offer = createTestOffer(nonce);
        var exc = assertThrows(Oid4vcException.class, () -> proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), offer.getNonce(), offer.getOfferExpirationTimestamp()));
        assertTrue(exc.getMessage().contains("None of the supported binding method/s was found in the header"));
    }

    @Test
    void givenUnsupportedDidMethod_whenHolderBindingValidate_thenThrow() throws JOSEException {
        var nonce = UUID.randomUUID();
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

        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof);
        var offer = createTestOffer(nonce);
        var exc = assertThrows(Oid4vcException.class, () -> proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), offer.getNonce(), offer.getTokenExpirationTimestamp()));
        assertTrue(exc.getMessage().contains("Did method provided in kid attribute did:tdw is not supported"));
    }

    @Test
    void givenInvalidJwtDidKeyRepresentation_whenHolderBindingValidate_thenThrow() throws JOSEException {
        var nonce = UUID.randomUUID();
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

        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof);
        var offer = createTestOffer(nonce);
        var exc = assertThrows(Oid4vcException.class, () -> proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), offer.getNonce(), offer.getTokenExpirationTimestamp()));
        assertTrue(exc.getMessage().contains("could not be parsed to a JWK"));
    }

    @Test
    void givenValidKidAttributeRepresentation_whenHolderBindingValidate_thenValid_() throws JOSEException {
        // Check holder proof with didJwk
        var nonce = UUID.randomUUID();
        String proof = TestUtils.createHolderProof(jwk, "http://issuer.com", nonce.toString(), ProofType.JWT.getClaimTyp(), true);
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof);
        var offer = createTestOffer(nonce);
        assertTrue(proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), offer.getNonce(), offer.getTokenExpirationTimestamp()));
    }

    @Test
    void givenValidJwkAttributeRepresentation_whenHolderBindingValidate_thenValid_() throws JOSEException {
        // Check holder proof with didJwk
        var nonce = UUID.randomUUID();
        String proof = TestUtils.createHolderProof(jwk, "http://issuer.com", nonce.toString(), ProofType.JWT.getClaimTyp(), false);
        ProofJwt proofJwt = new ProofJwt(ProofType.JWT, proof);
        var offer = createTestOffer(nonce);
        assertTrue(proofJwt.isValidHolderBinding("http://issuer.com", List.of("ES256"), offer.getNonce(), offer.getTokenExpirationTimestamp()));
    }

    private CredentialOffer createTestOffer(UUID nonce) {
        return new CredentialOffer(
                UUID.randomUUID(),
                CredentialStatusType.OFFERED,
                Collections.emptyList(),
                new HashMap<String, Object>() {{
                    put("data", "data");
                    put("otherStuff", "data");
                }},
                new HashMap<>(),
                UUID.randomUUID(),
                null,
                null,
                Instant.now().plusSeconds(600).getEpochSecond(),
                nonce,
                UUID.randomUUID(),
                120L,
                Instant.now(),
                Instant.now(),
                null
        );
    }
}