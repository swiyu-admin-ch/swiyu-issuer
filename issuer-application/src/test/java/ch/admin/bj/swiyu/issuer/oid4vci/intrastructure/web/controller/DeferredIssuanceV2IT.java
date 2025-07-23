package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredDataDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class DeferredIssuanceV2IT {

    private final UUID validPreAuthCode = UUID.randomUUID();
    private ECKey jwk;
    @Autowired
    private MockMvc mock;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private ApplicationProperties applicationProperties;
    @Autowired
    private ObjectMapper objectMapper;
    private CredentialOffer offer;

    private static String getDeferredCredentialRequestString(String transactionId) {
        return String.format("{ \"transaction_id\": \"%s\"}", transactionId);
    }

    @BeforeEach
    void setUp() throws JOSEException {
        var testStatusList = saveStatusList(createStatusList());
        Map<String, Object> deferredMetadata = Map.of("deferred", true);

        offer = createTestOffer(validPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt", deferredMetadata);
        saveStatusListLinkedOffer(offer, testStatusList);
        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();
    }

    @Test
    void testDeferredOffer_withProof_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "university_example_sd_jwt");

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(jsonPath("$.interval").isNotEmpty())
                .andReturn();

        // check status from business issuer perspective
        mock.perform(patch("/management/api/credentials/%s/status?credentialStatus=%s".formatted(offer.getId(), CredentialStatusTypeDto.READY.name()))
                        .contentType("application/vnd.api.v2+json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(deferredCredentialResponse.getResponse().getContentAsString(), DeferredDataDto.class);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(deferredDataDto.transactionId().toString());

        mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential").isNotEmpty())
                .andExpect(jsonPath("$.format").value("vc+sd-jwt"))
                .andReturn();
    }

    private String getCredentialRequestString(Map<String, Object> tokenResponse, String configurationId) throws JOSEException {
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), false);
        return String.format("{\"credential_configuration_id\": \"%s\", \"proofs\": {\"jwt\": [\"%s\"]}}", configurationId, proof);
    }

    private void saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList) {
        credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList));
        statusList.incrementNextFreeIndex();
    }

    private StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }

    private ResultActions requestCredential(MockMvc mock, String token, String credentialRequestString) throws Exception {
        return mock.perform(post("/oid4vci/api/credential")
                .header("Authorization", String.format("BEARER %s", token))
                .contentType("application/vnd.api.v2+json")
                .content(credentialRequestString)
        );
    }

}