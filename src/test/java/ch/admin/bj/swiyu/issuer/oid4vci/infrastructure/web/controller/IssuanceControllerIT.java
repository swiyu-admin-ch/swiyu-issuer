/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.infrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestUtils;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import lombok.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestUtils.requestCredential;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IssuanceControllerIT {

    private static final UUID offerId = UUID.fromString("deadbeef-dead-dead-dead-deaddeafbeef");
    private static final UUID unboundOfferId = UUID.fromString("00000000-0000-0000-0000-000000000000");
    private static final UUID allValuesOfferId = UUID.randomUUID();
    private static ECKey jwk;
    private final UUID validPreAuthCode = UUID.randomUUID();
    private final UUID allValuesPreAuthCode = UUID.randomUUID();
    private final UUID unboundPreAuthCode = UUID.randomUUID();
    private final Instant validFrom = Instant.now();
    private final Instant validUntil = Instant.now().plus(30, ChronoUnit.DAYS);
    @Autowired
    private MockMvc mock;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private SdjwtProperties sdjwtProperties;
    @Autowired
    private ApplicationProperties applicationProperties;

    @BeforeEach
    void setUp() throws JOSEException {
        var statusList = createStatusList();
        statusListRepository.saveAndFlush(statusList);
        saveStatusListLinkedOffer(createTestOffer(offerId, validPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt"), statusList);
        saveStatusListLinkedOffer(createTestOffer(allValuesOfferId, allValuesPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt", validFrom, validUntil, null), statusList);
        saveStatusListLinkedOffer(createUnboundCredentialOffer(unboundOfferId, unboundPreAuthCode, CredentialStatusType.OFFERED), statusList);
        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();
    }

    @AfterEach
    void tearDown() {
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        statusListRepository.deleteAll();
    }

    @Test
    void testGetOpenIdConfiguraion_thenSuccess() throws Exception {
        mock.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("token_endpoint")))
                .andExpect(content().string(not(containsString("${external-url}"))));
    }

    @Test
    void testGetIssuerMetadata_thenSuccess() throws Exception {
        mock.perform(get("/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("${external-url}"))))
                .andExpect(content().string(containsString("credential_endpoint")))
                .andExpect(content().string(not(containsString("${stage}"))))
                .andExpect(content().string(containsString("local-Example Credential")))
                .andExpect(content().string(containsString("local-university_example_sd_jwt")));
    }

    @Test
    void testCredentialFlow_thenSuccess() throws Exception {
        String vc = getBoundVc();

        TestUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    @Test
    void testCredentialFlowSendIncorrectNonce_thenError() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), UUID.randomUUID().toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);

        requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_PROOF"))
                .andExpect(jsonPath("$.error_description").value("Nonce claim does not match the server-provided c_nonce value"))
                .andReturn();
    }

    @Test
    void testWrongProofType_thenBadRequest() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), "wrong type", true);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        JsonObject credentialResponse = TestUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals("INVALID_PROOF", credentialResponse.get("error").getAsString());
    }

    @Test
    void testHolderBindingProof_GivenIssuedAtWindowInFuture_thenBadRequest() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true, Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        JsonObject credentialResponse = TestUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals("INVALID_PROOF", credentialResponse.get("error").getAsString());
    }

    @Test
    void testHolderBindingProof_GivenIssuedAtWindowInPast_thenBadRequest() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true, Date.from(Instant.now().minus(1, ChronoUnit.HOURS)));
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        JsonObject credentialResponse = TestUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals("INVALID_PROOF", credentialResponse.get("error").getAsString());
    }

    @Test
    void testMissingProof_thenBadRequest() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String credentialRequestString = "{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\"}}";
        JsonObject credentialResponse = TestUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals("UNPROCESSABLE_ENTITY", credentialResponse.get("status").getAsString());
    }

    @Test
    void testWithMissingProof_thenBadRequest() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String credentialRequestString = "{ \"format\": \"vc+sd-jwt\" }";
        requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_PROOF"));
    }

    @Test
    void testUnboundCredentialFlow_thenSuccess() throws Exception {
        var vc = getUnboundVc();
        TestUtils.verifyVC(sdjwtProperties, vc, getUnboundCredentialSubjectData());
    }

    @Test
    void testInvalidPreAuthCode_thenBadRequest() throws Exception {
        var grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

        mock.perform(post("/api/v1/token")
                        .param("grant_type", grantType)
                        .param("pre-authorized_code", "aaaaaaaa-dead-dead-dead-deaddeafdead"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("INVALID_GRANT")));

        // check that correct preauthcode is used
        mock.perform(post("/api/v1/token")
                        .param("grant_type", grantType)
                        .param("pre-authorized_code", offerId.toString()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("INVALID_GRANT")));
    }

    @Test
    void testInvalidGrantType_thenBadRequest() throws Exception {
        // With Valid preauth code
        mock.perform(post("/api/v1/token")
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:test-authorized_code")
                        .param("pre-authorized_code", "deadbeef-dead-dead-dead-deaddeafbeef"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("INVALID_REQUEST")));

        // With Invalid preauth code
        mock.perform(post("/api/v1/token")
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:test-authorized_code")
                        .param("pre-authorized_code", "aaaaaaaa-dead-dead-dead-deaddeafdead"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("INVALID_REQUEST")));
    }

    @Test
    void testCredentialRequestEncryptionRSA() throws Exception {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("transportEncKeyRSA")
                .generate();

        encryptedCredentialRequestFlow(
                JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A128CBC_HS256,
                new RSADecrypter(rsaJWK.toRSAPrivateKey()),
                rsaJWK.toPublicJWK().toJSONString());
    }

    @Test
    void testCredentialRequestEncryptionEC() throws Exception {

        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("transportEncKeyEC")
                .generate();

        encryptedCredentialRequestFlow(
                JWEAlgorithm.ECDH_ES_A128KW,
                EncryptionMethod.A128CBC_HS256,
                new ECDHDecrypter(ecJWK.toECPrivateKey()),
                ecJWK.toPublicJWK().toJSONString());
    }

    void encryptedCredentialRequestFlow(JWEAlgorithm alg, EncryptionMethod enc, JWEDecrypter decrypter, String jwkJson) throws Exception {
        var responseEncryptionJson = String.format("""
                {
                    "alg": "%s",
                    "enc": "%s",
                    "jwk": %s
                }
                """, alg.getName(), enc.getName(), jwkJson);

        var jwe = fetchEncryptedCredentialFlow(responseEncryptionJson);
        jwe.decrypt(decrypter);
        var credentialResponseJson = jwe.getPayload().toString();
        JsonObject credentialResponse = JsonParser.parseString(
                        credentialResponseJson)
                .getAsJsonObject();
        String vc = credentialResponse.get("credential").getAsString();

        TestUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    @Test
    void testSdJwtOffer_thenSuccess() throws Exception {

        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var format = "vc+sd-jwt";
        var credentialRequestString = getCredentialRequestString(tokenResponse, format);

        var response = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credential").isNotEmpty())
                .andExpect(jsonPath("$.format").value("vc+sd-jwt"))
                .andReturn();

        assertNotNull(response);
        var credentialResponse = JsonParser.parseString(
                        response.getResponse().getContentAsString())
                .getAsJsonObject();
        var sdjwtVc = credentialResponse.get("credential").getAsString();
        var jwt = SignedJWT.parse(sdjwtVc.split("~")[0]);
        var claims = jwt.getPayload().toJSONObject();
        assertTrue(claims.containsKey("cnf"));
        var holderbindingJwk = JWK.parse((Map<String, Object>) claims.get("cnf"));
        assertEquals(holderbindingJwk.toECKey().getX(), jwk.toECKey().getX());

        var statusListType = (String) ((Map<String, Object>) ((Map<String, Object>) claims.get("status")).get("status_list")).get("type");
        assertEquals("SwissTokenStatusList-1.0", statusListType);
        requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest());
    }

    @Test
    void testOfferWrongFormat_thenFailure() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var invalidFormat = "ldp_vc";
        var credentialRequestString = getCredentialRequestString(tokenResponse, invalidFormat);

        requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.status").value("UNPROCESSABLE_ENTITY"))
                .andExpect(jsonPath("$.detail").value("format: Only vc+sd-jwt format is supported"));
    }

    /**
     * Test for evaluating if vct and vct#integrity is set.
     */
    @Test
    void testVcTypeIssuing_thenSuccess() throws Exception {
        // Get VC where vct#integrity is set. Claim should be there and filled
        var boundVc = SignedJWT.parse(getBoundVc());
        assertNotNull(boundVc.getJWTClaimsSet().getClaims().get("vct#integrity"));

        // Get VC where vct#integrity is not set. Claim should not exist
        var unboundVc = SignedJWT.parse(getUnboundVc());
        assertNull(unboundVc.getJWTClaimsSet().getClaims().get("vc#integrity"));

    }

    private static Map<String, String> getUnboundCredentialSubjectData() {
        Map<String, String> credentialSubjectData = new HashMap<>();
        credentialSubjectData.put("animal", "Tux");
        return credentialSubjectData;
    }

    private static CredentialOffer createUnboundCredentialOffer(UUID offerID, UUID preAuthCode, CredentialStatusType status) {
        var offerData = new HashMap<String, Object>();
        offerData.put("data", new GsonBuilder().create().toJson(getUnboundCredentialSubjectData()));
        return new CredentialOffer(
                offerID,
                status,
                List.of("unbound_example_sd_jwt"),
                offerData,
                new HashMap<>(),
                UUID.randomUUID(),
                null,
                null,
                Instant.now().plusSeconds(600).getEpochSecond(),
                UUID.randomUUID(),
                preAuthCode,
                Instant.now().plusSeconds(120).getEpochSecond(),
                null,
                null,
                null,
                null
        );
    }

    private String getBoundVc() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        return TestUtils.getCredential(mock, token, credentialRequestString);
    }

    private String getUnboundVc() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, unboundPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String credentialRequestString = "{ \"format\": \"vc+sd-jwt\" }";

        return TestUtils.getCredential(mock, token, credentialRequestString);
    }

    private String getCredentialRequestString(Map<String, Object> tokenResponse, String format) throws JOSEException {
        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), false);
        return String.format("{ \"format\": \"%s\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", format, proof);
    }

    @NonNull
    private JWEObject fetchEncryptedCredentialFlow(String responseEncryptionJson) throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}, \"credential_response_encryption\": %s}", proof, responseEncryptionJson);
        var response = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/jwt"))
                .andReturn();

        return JWEObject.parse(response.getResponse().getContentAsString());
    }

    private void saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList) {
        credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList));
        statusList.incrementNextFreeIndex();
        statusListRepository.saveAndFlush(statusList);
    }
}