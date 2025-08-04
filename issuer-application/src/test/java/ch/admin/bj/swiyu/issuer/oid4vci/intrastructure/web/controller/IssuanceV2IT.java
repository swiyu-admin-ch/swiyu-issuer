package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class IssuanceV2IT {

    private final UUID validPreAuthCode = UUID.randomUUID();
    private final UUID preAuthCode = UUID.randomUUID();
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
    private SdjwtProperties sdjwtProperties;

    @BeforeEach
    void setUp() throws JOSEException {
        var testStatusList = saveStatusList(createStatusList());
        var offer = createTestOffer(validPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt");
        saveStatusListLinkedOffer(offer, testStatusList);
        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();

        var unboundOffer = createTestOffer(preAuthCode, CredentialStatusType.OFFERED, "unbound_example_sd_jwt");
        saveStatusListLinkedOffer(unboundOffer, testStatusList);
        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();
    }

    @Test
    void testSdJwtOffer_withProof_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "university_example_sd_jwt");

        requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();
    }

    @Test
    void testSdJwtOffer_withoutProof_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, preAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = String.format("{\"credential_configuration_id\": \"%s\"}", "unbound_example_sd_jwt");

        // assumption if no proofs provided then only 1 credential is issued
        requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();
    }

    @Test
    void testSdJwtOffer_withResponseEncryption_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("transportEncKeyEC")
                .generate();

        var responseEncryptionJson = String.format("""
                {
                    "alg": "%s",
                    "enc": "%s",
                    "jwk": %s
                }
                """, JWEAlgorithm.ECDH_ES_A128KW.getName(), EncryptionMethod.A128CBC_HS256.getName(), ecJWK.toPublicJWK().toJSONString());

        // credential_response_encryption
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), false);
        var credentialRequestString = String.format("{\"credential_configuration_id\": \"%s\", \"credential_response_encryption\": %s, \"proofs\": {\"jwt\": [\"%s\"]}}", "university_example_sd_jwt", responseEncryptionJson, proof);

        var response = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/jwt"))
                .andExpect(jsonPath("$").isNotEmpty())
                .andReturn();

        var jwe = JWEObject.parse(response.getResponse().getContentAsString());
        jwe.decrypt(new ECDHDecrypter(ecJWK.toECPrivateKey()));
        var jweContent = jwe.getPayload().toString();
        JsonObject credentialResponse = JsonParser.parseString(jweContent).getAsJsonObject();
        JsonArray credentials = credentialResponse.get("credentials").getAsJsonArray();
        JsonObject credential = credentials.get(0).getAsJsonObject();
        var vc = credential.get("credential").getAsString();

        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
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
                .contentType("application/json")
                .header("SWIYU-API-Version", "2")
                .content(credentialRequestString)
        );
    }
}