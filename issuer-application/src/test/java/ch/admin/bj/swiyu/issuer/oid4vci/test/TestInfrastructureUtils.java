package ch.admin.bj.swiyu.issuer.oid4vci.test;

import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import com.authlete.sd.Disclosure;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.Assertions;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.*;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TestInfrastructureUtils {
    public static Map<String, Object> fetchOAuthToken(MockMvc mock, String preAuthCode) throws Exception {
        return fetchOAuthTokenDpop(mock, preAuthCode, null, null);
    }

    /**
     * Fetches OAuth 2.0 token with optional DPoP
     *
     * @param mock            MockMvc to perform call with
     * @param preAuthCode     existing pre-AuthCode to fetch OAuth token with
     * @param holderPublicKey (optional) used to build DPoP-Proof
     * @param externalUrl     (required if providing holderPublicKey) used to set DPoP checked http URI
     * @return OAuthToken response
     * @throws Exception on request/signing/parsing errors
     */
    public static Map<String, Object> fetchOAuthTokenDpop(MockMvc mock, String preAuthCode, @Nullable JWK holderPublicKey, @Nullable String externalUrl) throws Exception {
        var requestBuilder = post("/oid4vci/api/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .param("pre-authorized_code", preAuthCode);
        if (holderPublicKey != null) {
            requestBuilder.header("DPoP", createDPoP(mock, "POST", externalUrl + "/oid4vci/api/token", null, holderPublicKey));
        }
        var response = mock.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("expires_in")))
                .andExpect(content().string(containsString("access_token")))
                .andExpect(content().string(containsString("BEARER")))
                .andReturn();
        @SuppressWarnings("unchecked")
        Map<String, Object> tokenResponse = new ObjectMapper().readValue(response.getResponse().getContentAsString(), HashMap.class);
        return tokenResponse;
    }

    /**
     * @param mock        MockMvc to perform call with
     * @param httpMethod  Method the call the dpop will be used for will be using
     * @param httpUri     absolute URI to the location the call the dpop will be used for will be going to
     * @param accessToken access token which has been associated with the dpopKey used as Bearer token in the call
     * @param dpopKey     Key which is bound with the OAuth2.0 session
     * @return Serialized DPoP JWT
     * @throws Exception
     */
    public static String createDPoP(MockMvc mock, String httpMethod, String httpUri, String accessToken, JWK dpopKey) throws Exception {
        // Fetch fresh nonce
        var nonce = mock.perform(post("/oid4vci/api/nonce"))
                .andExpect(status().isOk())
                .andReturn().getResponse()
                .getHeader("DPoP-Nonce");
        assertNotNull(nonce);
        var claimSetBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .claim("htm", httpMethod)
                .claim("htu", httpUri)
                .claim("nonce", nonce);
        if (StringUtils.isNotEmpty(accessToken)) {
            claimSetBuilder.claim("ath", Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes(StandardCharsets.UTF_8))));
        }
        var signedJwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(dpopKey.toPublicJWK())
                .type(new JOSEObjectType("dpop+jwt"))
                .customParam(SwissProfileVersions.PROFILE_VERSION_PARAM, SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                .build(),
                claimSetBuilder.build());
        signedJwt.sign(new ECDSASigner(dpopKey.toECKey()));
        return signedJwt.serialize();
    }

    public static JWK getDPoPKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
                .keyID("HolderDPoPKey")
                .keyUse(KeyUse.SIGNATURE)
                .generate().toECKey();
    }

    public static ResultActions requestCredential(MockMvc mock, String token, String credentialRequestString) throws Exception {
        return mock.perform(post("/oid4vci/api/credential")
                .header("Authorization", String.format("BEARER %s", token))
                .contentType("application/json")
                .content(credentialRequestString)
        );
    }

    public static String getCredential(MockMvc mock, Object token, String credentialRequestString) throws Exception {
        var response = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("credential")))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        return JsonParser.parseString(response.getResponse().getContentAsString()).getAsJsonObject().get("credential").getAsString();
    }

    public static JsonObject requestFailingCredential(MockMvc mock, Object token, String credentialRequestString) throws Exception {
        var response = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().is4xxClientError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        return JsonParser.parseString(response.getResponse().getContentAsString()).getAsJsonObject();
    }

    public static void verifyVC(SdjwtProperties sdjwtProperties, String vc, Map<String, String> credentialSubjectData) throws Exception {

        var keyPair = ECKey.parseFromPEMEncodedObjects(sdjwtProperties.getPrivateKey());
        var publicJWK = keyPair.toPublicJWK();
        var sdJwtTokenParts = vc.split("~");
        var jwt = sdJwtTokenParts[0];
        var disclosures = List.of(sdJwtTokenParts).subList(1, sdJwtTokenParts.length);

        // vc must end with "~" as it has no holder binding
        assert (vc.endsWith("~"));

        assertTrue(verifyToken(jwt, publicJWK.toJSONString()));

        List<Disclosure> disclosureList = disclosures.stream().map(Disclosure::parse).toList();

        assertEquals(credentialSubjectData.size(), disclosureList.size());

        disclosureList.forEach(disclosure -> {
            assertNotNull(disclosure.getClaimName());
            assertEquals(credentialSubjectData.get(disclosure.getClaimName()), disclosure.getClaimValue());
        });
    }

    public static boolean verifyToken(String token, String publicKeyJwk) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Parse the public key JWK
            JWK jwk = JWK.parse(publicKeyJwk);

            // Create a JWSVerifier with the public key
            JWSVerifier verifier = new ECDSAVerifier(jwk.toECKey());

            // Verify the signature
            return signedJWT.verify(verifier);
        } catch (ParseException | JOSEException e) {
            return false;
        }
    }

    public static CredentialFetchData prepareAttestedVC(MockMvc mock, UUID preAuthCode, AttackPotentialResistance resistance, String attestationIssuerDid, ECKey jwk, String issuerId) throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, preAuthCode.toString());
        var token = tokenResponse.get("access_token");
        Assertions.assertThat(token).isNotNull();
        Assertions.assertThat(tokenResponse).containsKey("c_nonce");
        String proof = TestServiceUtils.createAttestedHolderProof(
                jwk,
                issuerId,
                tokenResponse.get("c_nonce").toString(),
                ProofType.JWT.getClaimTyp(),
                false,
                resistance,
                attestationIssuerDid);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);

        return new CredentialFetchData(token, credentialRequestString);
    }

    public record CredentialFetchData(Object token, String credentialRequestString) {
    }
}