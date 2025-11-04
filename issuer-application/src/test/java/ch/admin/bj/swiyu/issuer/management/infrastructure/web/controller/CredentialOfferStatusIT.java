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
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
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
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
    private UUID id;
    @Autowired
    private IssuerMetadata issuerMetadata;

    @BeforeEach
    void setupTest() throws Exception {
        var statusRegistryUUID = UUID.randomUUID();
        statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
                .formatted(statusRegistryUUID);
        testHelper = new CredentialOfferTestHelper(mvc, credentialOfferRepository, credentialOfferStatusRepository, statusListRepository,
                statusRegistryUrl);
        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusRegistryUUID);
        statusListEntryCreationDto.setStatusRegistryUrl(statusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(statusListEntryCreationDto);
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
        id = testHelper.createBasicOfferJsonAndGetUUID();
    }

    @Test
    void testGetOfferStatus_thenSuccess() throws Exception {

        CredentialStatusTypeDto expectedStatus = CredentialStatusTypeDto.OFFERED;

        mvc.perform(get(testHelper.getUrl(id)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(expectedStatus.toString()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"READY", "CANCELLED", "SUSPENDED", "REVOKED"})
    void testUpdateWithSameStatus_thenOk(String value) throws Exception {
        var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
        testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

        mvc.perform(patch(testHelper.getUpdateUrl(vcId, CredentialStatusTypeDto.valueOf(value))))
                .andExpect(status().isOk());

        mvc.perform(get(testHelper.getUrl(vcId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.valueOf(value).toString()));
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered1_thenBadRequest() throws Exception {

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.ISSUED;

        mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenIssued_thenSuccess() throws Exception {

        assertThat(STATUS_LIST_MAX_LENGTH).as("This test requires more than 9 indexes").isGreaterThanOrEqualTo(9);
        Set<Integer> unusedIndexes = new HashSet<>(IntStream.range(0, STATUS_LIST_MAX_LENGTH).boxed().collect(Collectors.toSet()));
        // Add Revoked VCS
        UUID vcRevokedId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.REVOKED);
        var offer = credentialOfferRepository.findById(vcRevokedId).get();
        Set<CredentialOfferStatus> revokedOfferStatus = credentialOfferStatusRepository.findByOfferId(offer.getId());
        assertThat(revokedOfferStatus)
                .as("Expecting test configuration to provide batch size of 3")
                .hasSize(3);
        var offerIds = revokedOfferStatus.stream()
                .map(CredentialOfferStatus::getId)
                .map(CredentialOfferStatusKey::getOfferId)
                .distinct()
                .toList();
        assertThat(offerIds)
                .as("All status entries should be of the same offer")
                .hasSize(1);
        unusedIndexes.removeAll(revokedOfferStatus.stream().map(CredentialOfferStatus::getId).map(CredentialOfferStatusKey::getIndex).collect(Collectors.toSet()));
        assertEquals(CredentialStatusType.REVOKED, offer.getCredentialStatus());
        var statusListId = assertDoesNotThrow(() -> revokedOfferStatus.stream().findFirst().orElseThrow().getId().getStatusListId());
        var statusList = assertDoesNotThrow(() -> statusListRepository.findById(statusListId).orElseThrow());
        var tokenStatusList = testHelper.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped());
        for (var offerStatus : revokedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been revoked").isEqualTo(1);
        }
        for (Integer index : unusedIndexes) {
            assertThat(tokenStatusList.getStatus(index)).as("Index has not been used and not revoked").isEqualTo(0);
        }

        UUID vcSuspendedId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.SUSPENDED);
        offer = assertDoesNotThrow(() -> credentialOfferRepository.findById(vcSuspendedId).orElseThrow());
        assertEquals(CredentialStatusType.SUSPENDED, offer.getCredentialStatus());
        var suspendedOfferStatus = credentialOfferStatusRepository.findByOfferId(offer.getId());
        var suspendedIndexes = suspendedOfferStatus.stream()
                .map(CredentialOfferStatus::getId)
                .map(CredentialOfferStatusKey::getIndex)
                .collect(Collectors.toSet());
        unusedIndexes.removeAll(suspendedIndexes);

        statusList = assertDoesNotThrow(() -> statusListRepository.findById(statusListId).orElseThrow());
        tokenStatusList = testHelper.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
                statusList.getStatusZipped());

        for (var offerStatus : suspendedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been suspended").isEqualTo(2);
        }
        for (var offerStatus : revokedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been still revoked").isEqualTo(1);
        }
        for (Integer index : unusedIndexes) {
            assertThat(tokenStatusList.getStatus(index)).as("Index is still unused / valid").isZero();
        }

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.ISSUED;
        mvc.perform(patch(testHelper.getUpdateUrl(vcSuspendedId, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(newStatus.toString()));
        offer = assertDoesNotThrow(() -> credentialOfferRepository.findById(vcSuspendedId).orElseThrow());
        assertEquals(CredentialStatusType.ISSUED, offer.getCredentialStatus());
        var issuedOfferStatus = credentialOfferStatusRepository.findByOfferId(offer.getId());
        var unsuspendedIndexes = issuedOfferStatus.stream()
                .map(CredentialOfferStatus::getId)
                .map(CredentialOfferStatusKey::getIndex)
                .collect(Collectors.toSet());
        assertThat(suspendedIndexes)
                .as("Suspendend and unsuspended should be the same indexes")
                .containsExactlyInAnyOrderElementsOf(unsuspendedIndexes);


        statusList = assertDoesNotThrow(() -> statusListRepository.findById(statusListId).orElseThrow());
        tokenStatusList = testHelper.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
                statusList.getStatusZipped());
        for (var offerStatus : issuedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been unsuspended").isZero();
        }
        for (var offerStatus : revokedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been still revoked").isEqualTo(1);
        }
        for (Integer index : unusedIndexes) {
            assertThat(tokenStatusList.getStatus(index)).as("Index is still unused / valid").isZero();
        }
    }

    @Test
    void testCreateOfferWhenExceedStatusListMaximum_thenBadRequest() throws Exception {
        var managementObjects = new HashSet<UUID>();
        var offerSpace = STATUS_LIST_MAX_LENGTH / issuerMetadata.getIssuanceBatchSize();
        for (var i = 0; i < offerSpace; i++) {
            managementObjects.add(testHelper.createStatusListLinkedOfferAndGetUUID());
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

    @Nested
    @DisplayName("Test deferred flow")
    class CredentialFlow {
    }

    @Nested
    @DisplayName("Test deferred flow")
    class Deferred {
        @Test
        void testUpdateOfferStatusWithDeferred_thenBadRequest() throws Exception {

            CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.READY;

            mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void testUpdateOfferStatusWithReadyWhenDeferred_thenOk() throws Exception {

            CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.READY;

            // Set the status to DEFERRED as this is done by the oid4vci
            var offer = credentialOfferRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException(String.format("Credential %s not found", id)));

            offer.changeStatus(CredentialStatusType.DEFERRED);

            credentialOfferRepository.save(offer);

            mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
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

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }

        @Test
        void testUpdateOfferStatusWithOfferedWhenInProgress_thenBadRequest() throws Exception {
            var originalState = CredentialStatusTypeDto.IN_PROGRESS.toString();
            var vcId = testHelper.createBasicOfferJsonAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(originalState));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, CredentialStatusTypeDto.OFFERED)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "CANCELLED", "IN_PROGRESS", "DEFERRED", "READY", "EXPIRED"})
        void testUpdateOfferWithIssuedWhenPreIssued_thenBadRequest(String originalState) throws Exception {

            var newValue = CredentialStatusTypeDto.ISSUED;
            var vcId = testHelper.createBasicOfferJsonAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(originalState));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newValue)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }
    }

    @Nested
    @DisplayName("Test suspension of offers")
    class Suspended {
        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.SUSPENDED;

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "CANCELLED", "IN_PROGRESS", "DEFERRED", "READY", "EXPIRED", "CANCELLED"})
        void testUpdateOfferStatusWhenPreIssuedWhitSuspended_thenBadRequest(String value) throws Exception {
            var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"REVOKED"})
        void testUpdateOfferStatusWhenTerminalWhitSuspended_thenBadRequest(String value) throws Exception {
            var vcId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"ISSUED", "SUSPENDED"})
        void testUpdateOfferStatusWhenSuspended_thenSuccess(String value) throws Exception {

            var vcId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.SUSPENDED.toString()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"REVOKED", "EXPIRED", "CANCELLED"})
        void testUpdateOfferStatusToIssuedWhenFinal_thenReject(String value) throws Exception {

            var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, CredentialStatusTypeDto.ISSUED)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Test revocation of offers")
    class Revoked {
        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.REVOKED;

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "IN_PROGRESS", "DEFERRED", "READY"})
        void testUpdateOfferStatusWhenPreIssuedWithRevoked_thenIsOk(String value) throws Exception {
            var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
            testHelper.changeOfferStatus(id, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"EXPIRED", "CANCELLED"})
        void testUpdateOfferStatusWhenTerminalState_thenBadRequest(String value) throws Exception {
            var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"SUSPENDED", "ISSUED", "REVOKED"})
        void testUpdateOfferStatusWhenPossibleState_thenIsOk(String value) throws Exception {
            var vcId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk());
        }

        /**
         * Should fail because no way of revocation is available
         */
        @Test
        void testUpdateOfferStatusWithRevokedWhenIssuedWithoutStatusList_thenBadRequest() throws Exception {

            testHelper.updateStatusForEntity(id, CredentialStatusType.ISSUED);

            mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void testUpdateOfferStatusWithRevokedWhenRevoked_thenOk() throws Exception {

            mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Test cancellation of offers")
    class Cancelled {

        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.CANCELLED;

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "IN_PROGRESS", "DEFERRED", "READY", "CANCELLED", "REVOKED"})
        void testCancelWhenPreIssued_thenOk(String value) throws Exception {
            var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
            testHelper.changeOfferStatus(id, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"REVOKED", "SUSPENDED", "ISSUED"})
        void testCancelWhenPostIssued_thenBadRequest(String value) throws Exception {
            var originalState = CredentialStatusTypeDto.valueOf(value);
            var vcId = testHelper.createIssueAndSetStateOfVc(originalState);
            testHelper.updateStatusForEntity(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState.toString()));
        }

        @Test
        void testUpdateOfferStatusWithCancelledWhenExpired_thenBadRequest() throws Exception {
            var originalState = CredentialStatusTypeDto.EXPIRED;
            var vcId = testHelper.createBasicOfferJsonAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(originalState.toString()));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState.toString()));
        }
    }
}