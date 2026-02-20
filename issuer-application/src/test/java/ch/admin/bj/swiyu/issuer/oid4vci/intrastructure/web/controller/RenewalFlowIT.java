package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller.StatusListTestHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mockserver.MockServerContainer;
import org.testcontainers.utility.DockerImageName;
import reactor.core.publisher.Mono;

import java.util.UUID;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class RenewalFlowIT {

    public static final String TEST_BUSINESS_ISSUER_CREDENTIAL_RENEWAL_ENDPOINT = "/test/credential-renewal/endpoint";
    @Container
    static MockServerContainer mockServerContainer = new MockServerContainer(
            DockerImageName.parse("mockserver/mockserver:5.15.0")
    );

    static MockServerClient mockServerClient;
    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @MockitoSpyBean
    ApplicationProperties applicationProperties;
    @Autowired
    IssuerMetadata issuerMetadata;
    @Autowired
    SwiyuProperties swiyuProperties;
    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;
    @Mock
    private ApiClient mockApiClient;
    private StatusListTestHelper statusListTestHelper;
    private String payload;
    private OAuthTokenDto oauthTokenResponse;
    private ECKey dpopKey;

    @BeforeAll
    static void initialization() {
        mockServerClient =
                new MockServerClient(
                        mockServerContainer.getHost(),
                        mockServerContainer.getServerPort()
                );
    }

    @BeforeEach
    void setUp() throws Exception {
        mockServerClient.reset();
        statusListTestHelper = new StatusListTestHelper(mockMvc, objectMapper);
        final StatusListEntryCreationDto statusListEntry = statusListTestHelper.buildStatusListEntry();
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(Mono.just(statusListEntry));
        when(statusBusinessApi.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.empty());
        when(statusBusinessApi.getApiClient()).thenReturn(mockApiClient);
        when(mockApiClient.getBasePath()).thenReturn(statusListEntry.getStatusRegistryUrl());

        final StatusListDto statusListDto = assertDoesNotThrow(() -> statusListTestHelper.createStatusList(
                StatusListTypeDto.TOKEN_STATUS_LIST,
                1000,
                // Space for 1000 entries; length / batch size is how many VCs we can store in the status list
                null,
                2,
                // 2 Bits for having the states issue, revoke and suspend (and one unused state)
                null,
                null,
                null,
                null));
        // We will need the status list uri as identifier to indicate which status list will be used a VC we create
        var statusListUri = statusListDto.getStatusRegistryUrl();

        payload = "{\"metadata_credential_supported_id\": [\"university_example_sd_jwt\"],\"credential_subject_data\": {\"name\" : \"name\", \"type\": \"type\"}, \"status_lists\": [\"%s\"]}"
                .formatted(statusListUri);

        assertDoesNotThrow(this::createCredential);

        when(applicationProperties.isRenewalFlowEnabled()).thenReturn(true);
        when(applicationProperties.getBusinessIssuerRenewalApiEndpoint())
                .thenReturn(mockServerContainer.getEndpoint() + TEST_BUSINESS_ISSUER_CREDENTIAL_RENEWAL_ENDPOINT);
    }

    @Test
    void testRenewalSuccess() throws Exception {

        mockServerClient
                .when(
                        new HttpRequest()
                                .withMethod("POST")
                                .withPath(TEST_BUSINESS_ISSUER_CREDENTIAL_RENEWAL_ENDPOINT)
                )
                .respond(
                        HttpResponse.response()
                                .withStatusCode(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(payload)
                );

        // renew token
        var tokenResponse = refreshTokenWithDpop(oauthTokenResponse.getRefreshToken(), dpopKey);

        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(privindex -> assertDoesNotThrow(() -> createPrivateKeyV2("Test-Key-%s".formatted(privindex))))
                .toList();

        var credentialRequestString = getCredentialRequestStringV2(mockMvc, holderKeys, applicationProperties);

        // set to issued
        requestCredentialV2WithDpop(mockMvc, tokenResponse.getAccessToken(), credentialRequestString, issuerMetadata, dpopKey)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andReturn();
    }

    @Test
    void testRenewalInvalidAccessToken_thenException() throws Exception {

        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(privindex -> assertDoesNotThrow(() -> createPrivateKeyV2("Test-Key-%s".formatted(privindex))))
                .toList();

        var credentialRequestString = getCredentialRequestStringV2(mockMvc, holderKeys, applicationProperties);

        // set to issued
        requestCredentialV2WithDpop(mockMvc, UUID.randomUUID().toString(), credentialRequestString, issuerMetadata, dpopKey)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/json"))
                .andReturn();
    }

    @Test
    void testRenewalInvalidRefreshToken_thenException() throws Exception {

        mockMvc.perform(post("/oid4vci/api/token")
                        .header("DPoP", createDpop(
                                mockMvc,
                                issuerMetadata.getNonceEndpoint(),
                                "POST",
                                "http://localhost:8080/oid4vci/api/token",
                                null,
                                dpopKey
                        ))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", UUID.randomUUID().toString()))
                .andExpect(status().isBadRequest());
    }

    /**
     * This test mocks the business issuer being not able to process the request due to various issues
     *
     * @param statusCode status the business issuer responds with
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "420", // renewal quota exceeded
            "451", // cannot renew due to legal reasons
            "409", // SID detects a conflict
            "404", // Management ID not found
            "500", // Internal Error Business Issuer
            "503" // Peripheral systems not available
    })
    void testRenewalExternalFailures(String statusCode) {

        var expectedStatus = Integer.parseInt(statusCode);
        mockServerClient
                .when(
                        new HttpRequest()
                                .withMethod("POST")
                                .withPath(TEST_BUSINESS_ISSUER_CREDENTIAL_RENEWAL_ENDPOINT)
                )
                .respond(
                        HttpResponse.response()
                                .withStatusCode(expectedStatus)
                                .withHeader("Content-Type", "application/json")
                );

        // renew token
        var tokenResponse = assertDoesNotThrow(() -> refreshTokenWithDpop(oauthTokenResponse.getRefreshToken(), dpopKey));

        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(privindex -> assertDoesNotThrow(() -> createPrivateKeyV2("Test-Key-%s".formatted(privindex))))
                .toList();


        var credentialRequestString = assertDoesNotThrow(() -> getCredentialRequestStringV2(mockMvc, holderKeys, applicationProperties));

        // set to issued
        var credentialResponse = assertDoesNotThrow(() -> requestCredentialV2WithDpop(mockMvc, tokenResponse.getAccessToken(), credentialRequestString, issuerMetadata, dpopKey)
                .andExpect(status().is(expectedStatus))
                .andExpect(content().contentType("application/json"))
                .andReturn());

    }

    private JsonObject createCredential() throws Exception {

        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(privindex -> assertDoesNotThrow(() -> createPrivateKeyV2("Test-Key-%s".formatted(privindex))))
                .toList();

        MvcResult result = mockMvc
                .perform(post("/management/api/credentials").contentType("application/json").content(payload))
                .andExpect(status().isOk())
                .andReturn();

        var managementJsonObject = JsonParser.parseString(result.getResponse().getContentAsString()).getAsJsonObject();

        var preAuthCode = IssuanceV2TestUtils.getPreAuthCodeFromDeeplink(managementJsonObject.get("offer_deeplink").getAsString());

        dpopKey = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256)
                .keyID("HolderDPoPKey")
                .keyUse(KeyUse.SIGNATURE)
                .generate());

        oauthTokenResponse = requestTokenWithDpop(preAuthCode, dpopKey);

        var credentialRequestString = getCredentialRequestStringV2(mockMvc, holderKeys, applicationProperties);

        // set to issued
        requestCredentialV2WithDpop(mockMvc, oauthTokenResponse.getAccessToken(), credentialRequestString, issuerMetadata, dpopKey)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andReturn();

        return managementJsonObject;
    }

    private OAuthTokenDto requestTokenWithDpop(String preAuthCode, ECKey dpopKey) throws Exception {
        MvcResult tokenResult = mockMvc.perform(post("/oid4vci/api/token")
                        .header("DPoP", createDpop(
                                mockMvc,
                                issuerMetadata.getNonceEndpoint(),
                                "POST",
                                "http://localhost:8080/oid4vci/api/token",
                                null,
                                dpopKey
                        ))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                        .param("pre-authorized_code", preAuthCode))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readValue(tokenResult.getResponse().getContentAsString(), OAuthTokenDto.class);
    }

    private OAuthTokenDto refreshTokenWithDpop(String refreshToken, ECKey dpopKey) throws Exception {
        MvcResult tokenResult = mockMvc.perform(post("/oid4vci/api/token")
                        .header("DPoP", createDpop(
                                mockMvc,
                                issuerMetadata.getNonceEndpoint(),
                                "POST",
                                "http://localhost:8080/oid4vci/api/token",
                                null,
                                dpopKey
                        ))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readValue(tokenResult.getResponse().getContentAsString(), OAuthTokenDto.class);
    }
}