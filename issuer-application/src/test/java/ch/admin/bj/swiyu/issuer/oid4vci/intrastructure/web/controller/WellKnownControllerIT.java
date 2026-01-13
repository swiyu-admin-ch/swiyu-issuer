package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller.CredentialOfferTestHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import io.fabric8.kubernetes.client.utils.OpenIDConnectionUtils;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class WellKnownControllerIT {
    @Autowired
    private MockMvc mock;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private SdjwtProperties sdjwtProperties;

    protected CredentialOfferTestHelper testHelper;

    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;

    @BeforeEach
    void setupTest() {
        var statusRegistryUUID = UUID.randomUUID();
        var statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
                .formatted(statusRegistryUUID);
        testHelper = new CredentialOfferTestHelper(mock, credentialOfferRepository, credentialOfferStatusRepository, statusListRepository, credentialManagementRepository,
                statusRegistryUrl);
    }

    @Test
    void testGetOpenIdConfiguration_thenSuccess() throws Exception {
        mock.perform(get("/oid4vci/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("token_endpoint")))
                .andExpect(content().string(not(containsString("${external-url}"))));
    }

    @Test
    void testGetOauthAuthorizationServer_thenSuccess() throws Exception {
        mock.perform(get("/oid4vci/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("token_endpoint")))
                .andExpect(content().string(not(containsString("${external-url}"))));
    }

    @Test
    void testGetIssuerMetadata_thenSuccess() throws Exception {
        mock.perform(get("/oid4vci/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("${external-url}"))))
                .andExpect(content().string(containsString("credential_endpoint")))
                .andExpect(content().string(not(containsString("${stage}")))) // stage placeholder should be replace
                .andExpect(content().string(containsString("local-Example Credential"))) // Replaced placeholder examples
                .andExpect(content().string(containsString("local-university_example_sd_jwt")))
                .andExpect(content().string(containsString("\"vct_metadata_uri\""))) // vct metadata indirection should not be filtered out if used
                .andExpect(content().string(containsString("\"vct_metadata_uri#integrity\""))) // integrity for vct metadata indirection should not be filtered out if used
                .andExpect(content().string(Matchers.not(containsString("issuanceBatchSize")))); // Util Field should not be displayed metadata
    }

    @Test
    void testGetIssuerSignedMetadataSubject_thenSuccess() throws Exception {
        var url = testHelper.createBasicOfferJsonAndGetTenantID();
        var issuerPublicKey = assertDoesNotThrow(() -> JWK.parseFromPEMEncodedObjects(sdjwtProperties.getPrivateKey()).toECKey().toECPublicKey());
        var issuerSignatureVerifier = assertDoesNotThrow(() -> new ECDSAVerifier(issuerPublicKey));

        // openid-credential-issuer
        var issuerMetadataResponse = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-credential-issuer".formatted(url))
                        .accept("application/jwt"))
                .andExpect(status().isOk())
                .andReturn());

        var issuerMetadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(issuerMetadataResponse.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");

        assertDoesNotThrow(() -> issuerMetadataJwt.verify(issuerSignatureVerifier), "Signed Metadata must have a valid signature");
        var issuerMetadata = assertDoesNotThrow(() -> objectMapper.readValue(issuerMetadataJwt.getPayload().toString(),
                IssuerMetadata.class));

        var sub = issuerMetadataJwt.getPayload().toJSONObject().get("sub").toString();
        assertEquals(issuerMetadata.getCredentialIssuer(), sub);

        // openid-configuration
        var metadataResponse = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-credential-issuer".formatted(url))
                        .accept("application/jwt"))
                .andExpect(status().isOk())
                .andReturn());

        var metadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(metadataResponse.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");

        assertDoesNotThrow(() -> issuerMetadataJwt.verify(issuerSignatureVerifier), "Signed Metadata must have a valid signature");
        var metadata = assertDoesNotThrow(() -> objectMapper.readValue(metadataJwt.getPayload().toString(),
                OpenIdConfigurationDto.class));

        sub = metadataJwt.getPayload().toJSONObject().get("sub").toString();
        assertEquals(metadata.issuer(), sub);
    }

    @Test
    void testGetIssuerMetadata_PreferSigned() throws Exception {
        var issuerPublicKey = assertDoesNotThrow(() -> JWK.parseFromPEMEncodedObjects(sdjwtProperties.getPrivateKey()).toECKey().toECPublicKey());
        var issuerSignatureVerifier = assertDoesNotThrow(() -> new ECDSAVerifier(issuerPublicKey));

        // when json and jwt are allowed, prefer jwt
        var url = testHelper.createBasicOfferJsonAndGetTenantID();
        var issuerMetadataResponse = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-credential-issuer".formatted(url))
                        .accept("application/json,application/jwt"))
                .andExpect(status().isOk())
                .andReturn());

        var issuerMetadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(issuerMetadataResponse.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");
        assertDoesNotThrow(() -> issuerMetadataJwt.verify(issuerSignatureVerifier), "Signed Metadata must have a valid signature");

        var metadataResponse = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-configuration".formatted(url))
                        .accept("application/json,application/jwt"))
                .andExpect(status().isOk())
                .andReturn());

        var metadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(metadataResponse.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");
        assertDoesNotThrow(() -> metadataJwt.verify(issuerSignatureVerifier), "Signed Metadata must have a valid signature");
    }
}