/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.HashSet;
import java.util.UUID;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest()
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
//@Transactional selecting indexes view does not work with transactional
class CredentialOfferStatusIT {

    private static final int STATUS_LIST_MAX_LENGTH = 9;
    @Autowired
    protected SwiyuProperties swiyuProperties;
    @Autowired
    protected MockMvc mvc;
    protected CredentialOfferTestHelper testHelper;
    private String statusRegistryUrl;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;
    @Mock
    private ApiClient mockApiClient;
    private UUID managementId;
    @Autowired
    private IssuerMetadata issuerMetadata;
    @Autowired
    private ApplicationProperties applicationProperties;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;

    @BeforeEach
    void setupTest() throws Exception {
        var statusRegistryUUID = UUID.randomUUID();
        statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
                .formatted(statusRegistryUUID);
        testHelper = new CredentialOfferTestHelper(mvc, credentialOfferRepository, credentialOfferStatusRepository, statusListRepository, credentialManagementRepository,
                statusRegistryUrl);
        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusRegistryUUID);
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
                                "{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": %s,\"config\": {\"bits\": 2}}".formatted(STATUS_LIST_MAX_LENGTH)))
                .andExpect(status().isOk());
        // Add Test Offer
        managementId = testHelper.createBasicOfferJsonAndGetUUID();
    }

    @Test
    void testGetOfferStatus_thenSuccess() throws Exception {

        CredentialStatusTypeDto expectedStatus = CredentialStatusTypeDto.OFFERED;

        mvc.perform(get(testHelper.getStatusUrl(managementId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(expectedStatus.toString()));
    }

    @Transactional
    @ParameterizedTest
    @ValueSource(strings = {"READY", "CANCELLED"})
    void testUpdateWithSameStatus_thenOk(String value) throws Exception {
        managementId = testHelper.createStatusListLinkedOfferAndGetUUID();

        var mgmt = credentialManagementRepository.findById(managementId).orElseThrow();
        var offerId = mgmt.getCredentialOffers().stream()
                .findFirst()
                .orElseThrow()
                .getId();

        testHelper.changeOfferStatus(offerId, CredentialOfferStatusType.valueOf(value));

        mvc.perform(patch(testHelper.getUpdateUrl(managementId, CredentialStatusTypeDto.valueOf(value))))
                .andExpect(status().isOk());

        mvc.perform(get(testHelper.getStatusUrl(managementId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.valueOf(value).toString()));
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered1_thenBadRequest() throws Exception {

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.ISSUED;

        mvc.perform(patch(testHelper.getUpdateUrl(managementId, newStatus)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testCreateOfferWhenExceedStatusListMaximum_thenBadRequest() throws Exception {
        var managementObjects = new HashSet<UUID>();
        var offerSpace = STATUS_LIST_MAX_LENGTH / issuerMetadata.getIssuanceBatchSize();
        for (var i = 0; i < offerSpace; i++) {
            managementObjects.add(UUID.fromString(createCredential().get("offer_id").getAsString()));
        }
        assertThat(managementObjects).hasSize(offerSpace);
        var offers = managementObjects.stream().map(credentialOfferStatusRepository::findByOfferId).flatMap(Collection::stream).toList();
        var usedStatusLists = offers.stream().map(CredentialOfferStatus::getId).map(CredentialOfferStatusKey::getStatusListId).distinct().toList();
        assertThat(usedStatusLists).as("Only one status list should have been used").hasSize(1);
        assertThat(credentialOfferStatusRepository.countByStatusListId(usedStatusLists.getFirst())).as("All entries should be filled").isEqualTo(STATUS_LIST_MAX_LENGTH);
        String payload = "{\"metadata_credential_supported_id\": [\"test\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\",\"lastName\" : \"lastName\"}, \"status_lists\": [\"%s\"]}"
                .formatted(statusRegistryUrl);
        mvc
                .perform(post(CredentialOfferTestHelper.BASE_URL).contentType("application/json").content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail")
                        .value(
                                Matchers.allOf(
                                        Matchers.containsString(statusRegistryUrl),
                                        Matchers.containsString("No status indexes remain in status list"))));

    }

    private JsonObject createCredential() throws Exception {
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

        var token = IssuanceV2TestUtils.getAccessTokenFromDeeplink(mvc, managementJsonObject.get("offer_deeplink").getAsString());

        var credentialRequestString = getCredentialRequestStringV2(mvc, holderKeys, applicationProperties);

        // set to issued
        requestCredentialV2(mvc, token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andReturn();

        return managementJsonObject;
    }

    @Nested
    @DisplayName("Test deferred flow")
    class Deferred {
        @Test
        void testUpdateOfferStatusWithDeferred_thenBadRequest() throws Exception {

            CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.READY;

            mvc.perform(patch(testHelper.getUpdateUrl(managementId, newStatus)))
                    .andExpect(status().isBadRequest());
        }

        @Transactional
        @Test
        void testUpdateOfferStatusWithReadyWhenDeferred_thenOk() throws Exception {

            CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.READY;

            // Set the status to DEFERRED as this is done by the oid4vci
            var mgmt = credentialManagementRepository.findById(managementId).orElseThrow();
            mgmt.getCredentialOffers().stream().findFirst().ifPresent(offer -> {
                offer.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.DEFERRED);
                credentialOfferRepository.save(offer);
            });

            mvc.perform(patch(testHelper.getUpdateUrl(managementId, newStatus)))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Test invalid status inputs")
    class InvalidStatusInputs {

        @ParameterizedTest
        @ValueSource(strings = {"IN_PROGRESS", "DEFERRED", "ISSUED"})
        void testUpdateOfferStatusWhenPreIssuedWhitSuspended_thenBadRequest(String value) throws Exception {
            var originalState = CredentialStatusTypeDto.OFFERED.toString();
            var newValue = CredentialStatusTypeDto.valueOf(value);
            var vcId = testHelper.createBasicOfferJsonAndGetUUID();

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newValue)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getStatusUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }

        @Transactional
        @Test
        void testUpdateOfferStatusWithOfferedWhenInProgress_thenBadRequest() throws Exception {
            var originalState = CredentialStatusTypeDto.IN_PROGRESS.toString();
            managementId = testHelper.createBasicOfferJsonAndGetUUID();

            var mgmt = credentialManagementRepository.findById(managementId).orElseThrow();
            mgmt.getCredentialOffers().stream().findFirst().ifPresent(offer -> {
                offer.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.valueOf(originalState));
                credentialOfferRepository.save(offer);
            });

            mvc.perform(patch(testHelper.getUpdateUrl(managementId, CredentialStatusTypeDto.OFFERED)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getStatusUrl(managementId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }

        @Transactional
        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "CANCELLED", "DEFERRED", "EXPIRED"})
        void testUpdateOfferWithIssuedWhenPreIssued_thenBadRequest(String originalState) throws Exception {

            var newValue = CredentialStatusTypeDto.ISSUED;
            managementId = testHelper.createBasicOfferJsonAndGetUUID();
            var mgmt = credentialManagementRepository.findById(managementId).orElseThrow();
            mgmt.getCredentialOffers().stream().findFirst().ifPresent(offer -> {
                offer.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.valueOf(originalState));
                credentialOfferRepository.save(offer);
            });

            mvc.perform(patch(testHelper.getUpdateUrl(managementId, newValue)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getStatusUrl(managementId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }
    }

    @Nested
    @DisplayName("Test suspension of offers")
    class Suspended {
        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.SUSPENDED;

        @Transactional
        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "CANCELLED", "IN_PROGRESS", "DEFERRED", "READY", "EXPIRED", "CANCELLED"})
        void testUpdateOfferStatusWhenPreIssuedWhitSuspended_thenBadRequest(String value) throws Exception {
            managementId = testHelper.createWithOfferStatus(CredentialOfferStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(managementId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getStatusUrl(managementId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @Transactional
        @ParameterizedTest
        @ValueSource(strings = {"EXPIRED", "CANCELLED"})
        void testUpdateOfferStatusToIssuedWhenFinal_thenReject(String value) throws Exception {

            managementId = testHelper.createStatusListLinkedOfferAndGetUUID();

            var mgmt = credentialManagementRepository.findById(managementId).orElseThrow();
            mgmt.getCredentialOffers().stream().findFirst().ifPresent(offer -> {
                offer.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.valueOf(value));
                credentialOfferRepository.save(offer);
            });

            mvc.perform(patch(testHelper.getUpdateUrl(managementId, CredentialStatusTypeDto.ISSUED)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Test revocation of offers")
    class Revoked {
        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.REVOKED;

        @Transactional
        @ParameterizedTest
        @ValueSource(strings = {"EXPIRED", "CANCELLED"})
        void testUpdateOfferStatusWhenTerminalState_thenBadRequest(String value) throws Exception {
            managementId = testHelper.createWithOfferStatus(CredentialOfferStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(managementId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getStatusUrl(managementId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }
    }

    @Nested
    @DisplayName("Test cancellation of offers")
    class Cancelled {

        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.CANCELLED;

        @Transactional
        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "IN_PROGRESS", "DEFERRED", "READY", "CANCELLED"})
        void testCancelWhenPreIssued_thenOk(String value) throws Exception {

            managementId = testHelper.createWithOfferStatus(CredentialOfferStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(managementId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));

            mvc.perform(get(testHelper.getStatusUrl(managementId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));
        }

        @Transactional
        @Test
        void testUpdateOfferStatusWithCancelledWhenExpired_thenBadRequest() throws Exception {
            var originalState = CredentialStatusTypeDto.EXPIRED;
            managementId = testHelper.createWithOfferStatus(CredentialOfferStatusType.EXPIRED);

            mvc.perform(patch(testHelper.getUpdateUrl(managementId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getStatusUrl(managementId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState.toString()));
        }
    }
}