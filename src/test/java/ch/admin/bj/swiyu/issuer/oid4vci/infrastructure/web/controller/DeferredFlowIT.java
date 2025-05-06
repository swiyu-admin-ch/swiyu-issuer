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
import com.google.gson.JsonParser;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallbackWithoutResult;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestUtils.requestCredential;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class DeferredFlowIT {

    private static ECKey jwk;
    private final UUID deferredPreAuthCode = UUID.randomUUID();
    private final UUID notDeferredPreAuthCode = UUID.randomUUID();
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
    @Autowired
    private TransactionTemplate transactionTemplate;

    @BeforeEach
    void setUp() throws JOSEException {
        var statusList = createStatusList();
        statusListRepository.save(statusList);

        var deferredOffer = createTestOffer(deferredPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt", validFrom, validUntil, getCredentialMetadata(true));
        saveStatusListLinkedOffer(deferredOffer, statusList);
        var notDeferredOffer = createTestOffer(notDeferredPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt", validFrom, validUntil, getCredentialMetadata(false));
        saveStatusListLinkedOffer(notDeferredOffer, statusList);

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
    void testBoundDeferredFlow_thenSuccess() throws Exception {

        var tokenResponse = TestUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");

        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");

        // Mock issuer management interaction
        setCredentialToReady(token);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);

        var credentialResponse = mock.perform(post("/api/v1/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andReturn();

        var vc = JsonParser.parseString(credentialResponse.getResponse().getContentAsString()).getAsJsonObject().get("credential").getAsString();
        TestUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    @Test
    void testBoundDeferredFlow_thenIssuancePendingException() throws Exception {

        var tokenResponse = TestUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");

        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        // to get token now should end up in a bad request
        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);
        mock.perform(post("/api/v1/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("ISSUANCE_PENDING"))
                .andReturn();
    }

    @Test
    void testBoundDeferredFlowWithInvalidTransactionId_thenInvalidCredentialRequestException() throws Exception {

        var tokenResponse = TestUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");

        String transactionId = "00000000-0000-0000-0000-000000000000";
        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);
        mock.perform(post("/api/v1/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIAL_REQUEST"))
                .andReturn();
    }

    @Test
    void testWrongBearer_thenInvalidCredentialRequestException() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");
        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        setCredentialToReady(token);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);

        mock.perform(post("/api/v1/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", UUID.randomUUID()))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_TOKEN"))
                .andExpect(jsonPath("$.error_description").value("Invalid accessToken"))
                .andReturn();
    }

    @Test
    void testWrongTransactionIdToken_thenInvalidCredentialRequestException() throws Exception {

        var tokenResponse = TestUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");
        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = getCredentialRequestString(proof);

        // wrong token
        var otherTokenResponse = TestUtils.fetchOAuthToken(mock, notDeferredPreAuthCode.toString());
        var otherToken = otherTokenResponse.get("access_token");

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        setCredentialToReady(token);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);

        mock.perform(post("/api/v1/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", otherToken))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIAL_REQUEST"))
                .andExpect(jsonPath("$.error_description").value("Invalid transactional id"))
                .andReturn();
    }

    @Test
    void testBoundDeferredFlowWithAlreadyIssuedCredential_thenInvalidCredentialRequestException() throws Exception {

        var tokenResponse = TestUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");

        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");

        // Mock issuer management interaction
        setCredentialToReady(token);

        String deferredCredentialRequestString = String.format("{ \"transaction_id\": \"%s\"}}", transactionId);

        var credentialResponse = getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        var vc = JsonParser.parseString(credentialResponse.getResponse().getContentAsString()).getAsJsonObject().get("credential").getAsString();
        TestUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());

        getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIAL_REQUEST"))
                .andReturn();
    }

    private static String getCredentialRequestString(String proof) {
        return String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
    }

    private void saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList) {
        credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList));
        statusList.incrementNextFreeIndex();
    }

    private static String getDeferredCredentialRequestString(String transactionId) {
        return String.format("{ \"transaction_id\": \"%s\"}", transactionId);
    }

    private ResultActions getDeferredCallResultActions(Object token, String deferredCredentialRequestString) throws Exception {
        return mock.perform(post("/api/v1/deferred_credential")
                .header("Authorization", String.format("BEARER %s", token))
                .contentType("application/json")
                .content(deferredCredentialRequestString));
    }

    private void setCredentialToReady(String token) {
        transactionTemplate.execute(new TransactionCallbackWithoutResult() {
            @Override
            protected void doInTransactionWithoutResult(TransactionStatus status) {
                var credentialOffer = credentialOfferRepository.findByAccessToken(UUID.fromString(token)).get();
                credentialOffer.setCredentialStatus(CredentialStatusType.READY);
                credentialOfferRepository.save(credentialOffer);
            }
        });
    }

    private static Map<String, Object> getCredentialMetadata(Boolean deferred) {
        return Map.of("vct#integrity", "sha256-SVHLfKfcZcBrw+d9EL/1EXxvGCdkQ7tMGvZmd0ysMck=", "deferred", deferred);
    }

}