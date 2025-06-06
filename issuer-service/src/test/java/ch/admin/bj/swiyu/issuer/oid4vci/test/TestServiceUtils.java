/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.test;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.DidJwk;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class TestServiceUtils {
//    public static Map<String, Object> fetchOAuthToken(MockMvc mock, String preAuthCode) throws Exception {
//        var response = mock.perform(post("/api/v1/token")
//                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
//                        .param("pre-authorized_code", preAuthCode))
//                .andExpect(status().isOk())
//                .andExpect(content().string(containsString("expires_in")))
//                .andExpect(content().string(containsString("access_token")))
//                .andExpect(content().string(containsString("BEARER")))
//                .andReturn();
//        return new ObjectMapper().readValue(response.getResponse().getContentAsString(), HashMap.class);
//    }

//    public static ResultActions requestCredential(MockMvc mock, String token, String credentialRequestString) throws Exception {
//        return mock.perform(post("/api/v1/credential")
//                .header("Authorization", String.format("BEARER %s", token))
//                .contentType("application/json")
//                .content(credentialRequestString)
//        );
//    }

    public static String createHolderProof(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString, boolean useDidJwk) throws JOSEException {
        return createHolderProof(holderPrivateKey, issuerUri, nonce, proofTypeString, useDidJwk, new Date());
    }
    public static String createAttestedHolderProof(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString, boolean useDidJwk, AttackPotentialResistance attestationLevel, String attestationIssuerDid) throws JOSEException {
        return createHolderproofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, useDidJwk, new Date(), attestationLevel, attestationIssuerDid);
    }
    public static String createHolderProof(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString, boolean useDidJwk, Date issueTime) throws JOSEException {
        return createHolderproofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, useDidJwk, issueTime, null, null);
    }

    @NotNull
    private static String createHolderproofJWT(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString, boolean useDidJwk, Date issueTime, @Nullable AttackPotentialResistance attestationLevel, @Nullable String attestationIssuerDid) throws JOSEException {
        JWSSigner signer = new ECDSASigner(holderPrivateKey);

        var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(proofTypeString));
        if (useDidJwk) {
            headerBuilder.keyID(DidJwk.createFromJsonString(holderPrivateKey.toPublicJWK().toJSONString()).getDidJwk());
        } else {
            headerBuilder.jwk(holderPrivateKey.toPublicJWK());
        }
        // Add attestation if required
        if (attestationLevel != null) {
            var attestation = createKeyAttestation(attestationLevel, holderPrivateKey.toPublicJWK(), attestationIssuerDid == null ? "did:test:test-attestation-builder": attestationIssuerDid);
            attestation.sign(signer);
            headerBuilder.customParam("key_attestation", attestation.serialize());
        }
        JWSHeader header = headerBuilder
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("aud", issuerUri)
                .issueTime(issueTime)
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt.serialize();
    }

    private static SignedJWT createKeyAttestation(AttackPotentialResistance attestationLevel, ECKey publicJWK, String attestationIssuerDid) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("key-attestation+jwt"))
                .keyID(attestationIssuerDid+"#key-1")
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(attestationIssuerDid)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("key_storage", List.of(attestationLevel.getValue()))
                .claim("attested_keys", List.of(publicJWK.toJSONObject()))
                .build();
        return new SignedJWT(header, claims);
    }

//    public static String getCredential(MockMvc mock, Object token, String credentialRequestString) throws Exception {
//        var response = requestCredential(mock, (String) token, credentialRequestString)
//                .andExpect(status().isOk())
//                .andExpect(content().string(containsString("credential")))
//                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
//                .andReturn();
//
//        return JsonParser.parseString(response.getResponse().getContentAsString()).getAsJsonObject().get("credential").getAsString();
//    }
//
//    public static JsonObject requestFailingCredential(MockMvc mock, Object token, String credentialRequestString) throws Exception {
//        var response = requestCredential(mock, (String) token, credentialRequestString)
//                .andExpect(status().is4xxClientError())
//                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
//                .andReturn();
//
//        return JsonParser.parseString(response.getResponse().getContentAsString()).getAsJsonObject();
//    }

//    public static void verifyVC(SdjwtProperties sdjwtProperties, String vc, Map<String, String> credentialSubjectData) throws Exception {
//
//        var keyPair = ECKey.parseFromPEMEncodedObjects(sdjwtProperties.getPrivateKey());
//        var publicJWK = keyPair.toPublicJWK();
//        var sdJwtTokenParts = vc.split("~");
//        var jwt = sdJwtTokenParts[0];
//        var disclosures = List.of(sdJwtTokenParts).subList(1, sdJwtTokenParts.length);
//
//        // vc must end with "~" as it has no holder binding
//        assert (vc.endsWith("~"));
//
//        assertTrue(verifyToken(jwt, publicJWK.toJSONString()));
//
//        List<Disclosure> disclosureList = disclosures.stream().map(Disclosure::parse).toList();
//
//        assertEquals(credentialSubjectData.size(), disclosureList.size());
//
//        disclosureList.forEach(disclosure -> {
//            assertNotNull(disclosure.getClaimName());
//            assertEquals(credentialSubjectData.get(disclosure.getClaimName()), disclosure.getClaimValue());
//        });
//    }

//    public static boolean verifyToken(String token, String publicKeyJwk) {
//        try {
//            SignedJWT signedJWT = SignedJWT.parse(token);
//
//            // Parse the public key JWK
//            JWK jwk = JWK.parse(publicKeyJwk);
//
//            // Create a JWSVerifier with the public key
//            JWSVerifier verifier = new ECDSAVerifier(jwk.toECKey());
//
//            // Verify the signature
//            return signedJWT.verify(verifier);
//        } catch (ParseException | JOSEException e) {
//            return false;
//        }
//    }

}
