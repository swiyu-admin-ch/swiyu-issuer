package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller.StatusListTestHelper;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.mockito.Mockito;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mockserver.MockServerContainer;
import org.testcontainers.utility.DockerImageName;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceTestUtils.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.getMinimalPayloadForUniversityCredential;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression test for EIDOMNI-1216: an OID4VCI renewal and an operator-triggered
 * status change (revoke) racing on the same {@link CredentialManagement} aggregate.
 * <p>
 * Without a lock on the revoke path, the revoke transaction could read the aggregate
 * before the concurrently committed renewal's new child offer was attached, derive its
 * status-list updates from that stale snapshot, and commit REVOKED without ever
 * touching the renewed offer's status-list index - leaving the renewed credential
 * VALID despite the aggregate being reported REVOKED.
 * <p>
 * Not annotated {@code @Transactional}: the two HTTP calls below must run in genuinely
 * independent database transactions on separate threads for the pessimistic lock to
 * actually contend, so cleanup is done manually in {@link #tearDown()} instead.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Execution(ExecutionMode.SAME_THREAD)
class RenewalRevocationRaceConditionIT {

    private static final String TEST_BUSINESS_ISSUER_CREDENTIAL_RENEWAL_ENDPOINT = "/test/credential-renewal/endpoint";

    @Container
    static MockServerContainer mockServerContainer = new MockServerContainer(
            DockerImageName.parse("mockserver/mockserver:5.15.0"));

    static MockServerClient mockServerClient;

    private final ApiClient mockApiClient = Mockito.mock(ApiClient.class);

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
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private TransactionTemplate transactionTemplate;

    private String payload;
    private OAuthTokenDto oauthTokenResponse;
    private ECKey dpopKey;
    private String managementId;

    @BeforeAll
    static void initialization() {
        mockServerClient = new MockServerClient(
                mockServerContainer.getHost(),
                mockServerContainer.getServerPort());
    }

    @BeforeEach
    void setUp() throws Exception {
        Mockito.reset(applicationProperties);
        mockServerClient.reset();

        var statusListTestHelper = new StatusListTestHelper(mockMvc, objectMapper);
        final StatusListEntryCreationDto statusListEntry = statusListTestHelper.buildStatusListEntry();
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(Mono.just(statusListEntry));
        when(statusBusinessApi.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.empty());
        when(statusBusinessApi.getApiClient()).thenReturn(mockApiClient);
        when(mockApiClient.getBasePath()).thenReturn(statusListEntry.getStatusRegistryUrl());

        final StatusListDto statusListDto = assertDoesNotThrow(() -> statusListTestHelper.createStatusList(
                1000, null, 2, null, null, null, null));

        payload = getMinimalPayloadForUniversityCredential(statusListDto.getStatusRegistryUrl());

        assertDoesNotThrow(this::createCredential);

        doReturn(120).when(applicationProperties).getNonceLifetimeSeconds();
        doReturn(true).when(applicationProperties).isRenewalFlowEnabled();
        doReturn(mockServerContainer.getEndpoint() + TEST_BUSINESS_ISSUER_CREDENTIAL_RENEWAL_ENDPOINT)
                .when(applicationProperties).getBusinessIssuerRenewalApiEndpoint();
    }

    @AfterEach
    void tearDown() {
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        credentialManagementRepository.deleteAll();
        statusListRepository.deleteAll();
    }

    @Test
    void givenRenewalHoldsManagementLock_whenRevokeRunsConcurrently_thenRenewedCredentialIsAlsoRevoked() throws Exception {
        // The business-issuer call is where CredentialRenewalService#handleRenewalFlow spends most of
        // its time while still holding the pessimistic write lock on the management row acquired via
        // the access-token lookup. Delaying the mocked response widens that window so the concurrent
        // revoke request reliably contends with it instead of racing purely on local CPU timing.
        mockServerClient
                .when(new HttpRequest()
                        .withMethod("POST")
                        .withPath(TEST_BUSINESS_ISSUER_CREDENTIAL_RENEWAL_ENDPOINT))
                .respond(HttpResponse.response()
                        .withStatusCode(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(payload)
                        .withDelay(TimeUnit.SECONDS, 2));

        var executor = Executors.newFixedThreadPool(2);
        try {
            Future<Integer> renewalStatus = executor.submit(() -> {
                var tokenResponse = refreshTokenWithDpop(oauthTokenResponse.getRefreshToken(), dpopKey);
                var credentialRequestString = createCredentialRequestStringWithNewKeys();
                return requestCredentialWithDpop(mockMvc, tokenResponse.getAccessToken(), credentialRequestString,
                        issuerMetadata, dpopKey)
                        .andReturn().getResponse().getStatus();
            });

            // Head start so the renewal request has already entered its transaction and acquired the
            // row lock - and is now blocked on the delayed business-issuer call - before the revoke
            // request is fired from the second thread.
            Thread.sleep(500);

            Future<Integer> revokeStatus = executor.submit(() ->
                    updateStatus(mockMvc, managementId, UpdateCredentialStatusRequestTypeDto.REVOKED)
                            .andReturn().getResponse().getStatus());

            assertThat(renewalStatus.get(10, TimeUnit.SECONDS)).isEqualTo(200);
            assertThat(revokeStatus.get(10, TimeUnit.SECONDS)).isEqualTo(200);
        } finally {
            executor.shutdown();
        }

        var offerIds = transactionTemplate.execute(status ->
                credentialManagementRepository.findById(UUID.fromString(managementId))
                        .orElseThrow()
                        .getCredentialOffers().stream()
                        .map(CredentialOffer::getId)
                        .toList());

        assertThat(offerIds)
                .as("Renewal must have attached a second child offer to the management")
                .hasSize(2);

        var offerStatuses = credentialOfferStatusRepository.findByOfferIdIn(offerIds);
        assertThat(offerStatuses).isNotEmpty();

        for (var statusListId : offerStatuses.stream()
                .map(entry -> entry.getId().getStatusListId())
                .collect(Collectors.toSet())) {
            var statusList = statusListRepository.findById(statusListId).orElseThrow();
            var tokenStatusList = TokenStatusListToken.loadTokenStatusListToken(
                    (Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped(), 204800);

            offerStatuses.stream()
                    .filter(entry -> entry.getId().getStatusListId().equals(statusListId))
                    .forEach(entry -> assertThat(tokenStatusList.getStatus(entry.getId().getIndex()))
                            .as("Offer %s, index %d must be revoked, not left VALID by the renewal that overlapped the revoke",
                                    entry.getId().getOfferId(), entry.getId().getIndex())
                            .isEqualTo(TokenStatusListBit.REVOKE.getValue()));
        }

        var mgmt = credentialManagementRepository.findById(UUID.fromString(managementId)).orElseThrow();
        assertThat(mgmt.getCredentialManagementStatus()).isEqualTo(CredentialStatusManagementType.REVOKED);
    }

    private JsonObject createCredential() throws Exception {
        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(privindex -> assertDoesNotThrow(() -> createPrivateKey("Test-Key-%s".formatted(privindex))))
                .toList();

        MvcResult result = TestInfrastructureUtils.createCredentialOffer(mockMvc, payload)
                .andExpect(status().isOk())
                .andReturn();

        var managementJsonObject = getManagementJsonObject(result);
        managementId = managementJsonObject.get("management_id").getAsString();

        var preAuthCode = getPreAuthCodeFromDeeplink(managementJsonObject.get("offer_deeplink").getAsString());

        dpopKey = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256)
                .keyID("HolderDPoPKey")
                .keyUse(KeyUse.SIGNATURE)
                .generate());

        oauthTokenResponse = requestTokenWithDpop(preAuthCode, dpopKey);

        var credentialRequestString = getCredentialRequestString(mockMvc, holderKeys, applicationProperties, "university_example_sd_jwt");

        requestCredentialWithDpop(mockMvc, oauthTokenResponse.getAccessToken(), credentialRequestString,
                issuerMetadata, dpopKey)
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
                                dpopKey))
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
                                dpopKey))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readValue(tokenResult.getResponse().getContentAsString(), OAuthTokenDto.class);
    }

    private String createCredentialRequestStringWithNewKeys() throws Exception {
        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(privindex -> assertDoesNotThrow(() -> createPrivateKey("Test-Key-%s".formatted(privindex))))
                .toList();
        return getCredentialRequestString(mockMvc, holderKeys, applicationProperties, "university_example_sd_jwt");
    }

    private JsonObject getManagementJsonObject(MvcResult result) throws Exception {
        return JsonParser.parseString(result.getResponse().getContentAsString()).getAsJsonObject();
    }
}
