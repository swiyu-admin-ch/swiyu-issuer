package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@AutoConfigureMockMvc
@Testcontainers
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@ActiveProfiles("test")
@Execution(ExecutionMode.SAME_THREAD)
class CredentialOfferStatusMultiThreadedIT {

    private final UUID statusListUUID = UUID.randomUUID();
    private final String statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
            .formatted(statusListUUID);

    @Autowired
    protected SwiyuProperties swiyuProperties;
    @Autowired
    protected MockMvc mvc;
    @Autowired
    private IssuerMetadata issuerMetadata;
    @Autowired
    private ApplicationProperties applicationProperties;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;

    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;
    @Mock
    private ApiClient mockApiClient;

    private CredentialOfferTestHelper testHelper;

    @BeforeEach
    void setupTest() throws Exception {
        testHelper = new CredentialOfferTestHelper(mvc, credentialOfferRepository, credentialOfferStatusRepository, statusListRepository, credentialManagementRepository,
                statusRegistryUrl);

        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusListUUID);
        statusListEntryCreationDto.setStatusRegistryUrl(statusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(Mono.just(statusListEntryCreationDto));
        when(statusBusinessApi.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.empty());
        when(statusBusinessApi.getApiClient()).thenReturn(mockApiClient);
        when(mockApiClient.getBasePath()).thenReturn(statusRegistryUrl);

        // Mock removing access to registry
        // Add status list
        mvc.perform(post("/management/api/status-list")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(
                                "{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": 30000,\"config\": {\"bits\": 2}}"))
                .andExpect(status().isOk());
    }

    @AfterEach
    void tearDown() {
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        statusListRepository.deleteAll();
    }


    @Test
    void testCreateOfferMultiThreaded_thenSuccess() {
        // create some offers in a multithreaded manner
        // When increasing this too much spring boot will throw 'Failed to read request'
        // in a non-deterministic way...
        var results = IntStream.range(0, 1000).parallel().mapToObj(i -> {
            try {
                return testHelper.createStatusListLinkedOfferAndGetUUID();
            } catch (Exception e) {
                System.out.println(e.toString());
                throw new RuntimeException(e);
            }
        }).toList();
        // Get unique indexed on status list
        var indexSet = credentialManagementRepository.findAllById(results).stream()
                .map(mgmt -> mgmt.getCredentialOffers().stream().map(offer -> {
                    Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository.findByOfferId(offer.getId());
                    return byOfferStatusId.stream().findFirst().get().getId().getIndex();
                }))
                .collect(Collectors.toSet());
        Assertions.assertThat(indexSet).as("Should be the same size if no status was used multiple times")
                .hasSameSizeAs(results);
    }

    @Test
    void testUpdateOfferStatus_thenSuccess() throws Exception {
        var offerIds = IntStream.range(0, 2).parallel().mapToObj(i -> {
            try {

                var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                        .boxed()
                        .map(privindex -> assertDoesNotThrow(() -> createPrivateKeyV2("Test-Key-%s".formatted(privindex))))
                        .toList();
                String payload = "{\"metadata_credential_supported_id\": [\"university_example_sd_jwt\"],\"credential_subject_data\": {\"name\" : \"name\", \"type\": \"type\"}, \"status_lists\": [\"%s\"]}"
                        .formatted(statusRegistryUrl);

                MvcResult result = mvc
                        .perform(post("/management/api/credentials").contentType("application/json").content(payload))
                        .andExpect(status().isOk())
                        .andReturn();

                var managementJsonObject = JsonParser.parseString(result.getResponse().getContentAsString()).getAsJsonObject();

                var offer = extractCredentialOfferFromResponse(managementJsonObject);

                var preAuthCode = offer.get("grants").getAsJsonObject().get("urn:ietf:params:oauth:grant-type:pre-authorized_code").getAsJsonObject().get("pre-authorized_code").getAsString();

                var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mvc, preAuthCode);
                var token = tokenResponse.get("access_token");
                var credentialRequestString = getCredentialRequestStringV2(mvc, holderKeys, applicationProperties);

                // set to issued
                requestCredentialV2(mvc, (String) token, credentialRequestString)
                        .andExpect(status().isOk())
                        .andExpect(content().contentType("application/json"))
                        .andReturn();

                return UUID.fromString(managementJsonObject.get("offer_id").getAsString());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).toList();

        // Get all offers and the status list we are using
        var offers = offerIds.stream().map(credentialOfferRepository::findById).map(Optional::get).toList();
        CredentialOffer offer = offers.getFirst();
        Set<CredentialOfferStatus> credentialOfferStatuses = credentialOfferStatusRepository.findByOfferId(offer.getId());
        var statusListId = credentialOfferStatuses.stream().findFirst().get().getId().getStatusListId();
        var statusListIndexes = offers.stream()
                .map(credentialOffer -> credentialOfferStatusRepository.findByOfferId(credentialOffer.getId()))
                .flatMap(Set::stream)
                .map(CredentialOfferStatus::getId)
                .map(CredentialOfferStatusKey::getIndex)
                .collect(Collectors.toSet());
        // Check initialization
        assertTrue(offerIds.stream().map(credentialOfferRepository::findById).allMatch(credentialOffer -> credentialOffer.get().getCredentialStatus() == CredentialOfferStatusType.ISSUED));
        var initialStatusListToken = testHelper.loadTokenStatusListToken(2, statusListRepository.findById(statusListId).get().getStatusZipped());
        assertTrue(statusListIndexes.stream().allMatch(idx -> initialStatusListToken.getStatus(idx) == TokenStatusListBit.VALID.getValue()));
        // Update Status to Suspended
        var mgmtIds = offers.stream().map(credentialOffer -> credentialOffer.getCredentialManagement().getId()).toList();
        runSequential(mgmtIds, CredentialStatusTypeDto.SUSPENDED);
        assertTrue(mgmtIds.stream().map(credentialManagementRepository::findById).allMatch(credentialOffer -> credentialOffer.get().getCredentialManagementStatus() == CredentialStatusManagementType.SUSPENDED));
        // Reset Status
        runSequential(mgmtIds, CredentialStatusTypeDto.ISSUED);
        assertTrue(mgmtIds.stream().map(credentialManagementRepository::findById).allMatch(credentialOffer -> credentialOffer.get().getCredentialManagementStatus() == CredentialStatusManagementType.ISSUED));
        offerIds.forEach(o -> testHelper.assertOfferStateConsistent(o, CredentialOfferStatusType.ISSUED));
        var restoredStatusListToken = testHelper.loadTokenStatusListToken(2, statusListRepository.findById(statusListId).get().getStatusZipped());
        assertEquals(initialStatusListToken.getStatusListData(), restoredStatusListToken.getStatusListData(), "Bitstring should be same again");
    }

    private void runSequential(List<UUID> mgmtIds, CredentialStatusTypeDto credentialStatusTypeDto) {
        mgmtIds.forEach(offerId -> {
            try {
                mvc.perform(patch(testHelper.getUpdateUrl(offerId, credentialStatusTypeDto)))
                        .andExpect(status().is(200));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    private JsonObject extractCredentialOfferFromResponse(JsonObject dto) throws Exception {

        var decodedDeeplink = URLDecoder.decode(dto.get("offer_deeplink").getAsString(), StandardCharsets.UTF_8);

        var credentialOfferString = decodedDeeplink.replace("swiyu://?credential_offer=", "");

        return JsonParser.parseString(credentialOfferString).getAsJsonObject();
    }
}