package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
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
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class IssuanceV2IT {

    private final UUID validPreAuthCode = UUID.randomUUID();
    private final UUID validUnboundPreAuthCode = UUID.randomUUID();
    private StatusList testStatusList;
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
    @MockitoSpyBean
    private IssuerMetadataTechnical issuerMetadataTechnical;

    @BeforeEach
    void setUp() throws JOSEException {
        testStatusList = saveStatusList(createStatusList());
        CredentialOffer offer = createTestOffer(validPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt");
        saveStatusListLinkedOffer(offer, testStatusList);
        jwk = createPrivateKeyV2("Test-Key");

        var unboundOffer = createTestOffer(validUnboundPreAuthCode, CredentialStatusType.OFFERED, "unbound_example_sd_jwt");
        saveStatusListLinkedOffer(unboundOffer, testStatusList);
    }

    @Test
    void testSdJwtOffer_withProof_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, List.of(jwk), applicationProperties);

        var response = requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();

        var credentials = extractCredentialsV2(response);

        assertEquals(1, credentials.size());
        var credential = credentials.get(0).getAsJsonObject();
        var credentialString = credential.get("credential").getAsString();
        testHolderBindingV2(credentialString, jwk);
    }

    @Test
    void testSdJwtOffer_withMetadata_thenSuccess() throws Exception {

        var validPreAuthCodeWithMetadata = UUID.randomUUID();
        var vctIntegrity = "vct#integrity";
        var vctMetadataUri = "vct_metadata_uri";
        var vctMetadataUriIntegrity = "vct_metadata_uri#integrity";

        var metadata = new CredentialOfferMetadata(false, vctIntegrity, vctMetadataUri, vctMetadataUriIntegrity);
        var getValidPreAuthCodeWithMetadataOffer = createTestOffer(validPreAuthCodeWithMetadata, CredentialStatusType.OFFERED, "university_example_sd_jwt", metadata);
        saveStatusListLinkedOffer(getValidPreAuthCodeWithMetadataOffer, testStatusList);

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCodeWithMetadata.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, List.of(jwk), applicationProperties);

        var response = requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        var credentials = extractCredentialsV2(response);

        assertEquals(1, credentials.size());
        var credential = credentials.get(0).getAsJsonObject();
        var credentialString = credential.get("credential").getAsString();
        var claims = getVcClaims(credentialString);

        assertEquals(vctIntegrity, claims.get(vctIntegrity).getAsString());
        assertEquals(vctMetadataUri, claims.get(vctMetadataUri).getAsString());
        assertEquals(vctMetadataUriIntegrity, claims.get(vctMetadataUriIntegrity).getAsString());
    }

    @Test
    void testSdJwtOffer_withoutProof_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validUnboundPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = String.format("{\"credential_configuration_id\": \"%s\"}",
                "unbound_example_sd_jwt");

        // assumption if no proofs provided then only 1 credential is issued
        var response = requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();

        var credentials = extractCredentialsV2(response);

        // without proof only 1 credential is issued
        assertEquals(1, credentials.size());
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
                        """, JWEAlgorithm.ECDH_ES_A128KW.getName(), EncryptionMethod.A128CBC_HS256.getName(),
                ecJWK.toPublicJWK().toJSONString());

        // credential_response_encryption
        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), false);
        var credentialRequestString = String.format(
                "{\"credential_configuration_id\": \"%s\", \"credential_response_encryption\": %s, \"proofs\": {\"jwt\": [\"%s\"]}}",
                "university_example_sd_jwt", responseEncryptionJson, proof);

        var response = requestCredentialV2(mock, (String) token, credentialRequestString)
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

    @Test
    void testSdJwtOffer_withMultipleProof_thenSuccess() throws Exception {

        var numberOfProofs = 3;

        List<ECKey> holderPrivateKeys = createHolderPrivateKeysV2(numberOfProofs);

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, holderPrivateKeys, applicationProperties);

        var response = requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();

        var credentials = extractCredentialsV2(response);

        assertEquals(numberOfProofs, credentials.size());

        for (int j = 0; j < numberOfProofs; j++) {
            var credential = credentials.get(j).getAsJsonObject();
            var credentialString = credential.get("credential").getAsString();
            testHolderBindingV2(credentialString, holderPrivateKeys.get(j));
        }
    }

    @Test
    void testSdJwtOffer_exceedsBatchSize_thenException() throws Exception {

        var numberOfProofs = 4;

        List<ECKey> holderPrivateKeys = createHolderPrivateKeysV2(numberOfProofs);

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, holderPrivateKeys, applicationProperties);

        requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andReturn();
    }

    @Test
    void testSdJwtOffer_noBatchIssuanceAllowed_thenException() throws Exception {

        doReturn(null).when(issuerMetadataTechnical).getBatchCredentialIssuance();

        var numberOfProofs = 2;

        List<ECKey> holderPrivateKeys = createHolderPrivateKeysV2(numberOfProofs);

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, holderPrivateKeys, applicationProperties);

        requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andReturn();
    }

    private void saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList) {
        credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList));
        statusList.incrementNextFreeIndex();
    }

    private StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }
}