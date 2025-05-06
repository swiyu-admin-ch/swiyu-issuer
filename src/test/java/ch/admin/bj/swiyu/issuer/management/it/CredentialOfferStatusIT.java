/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.it;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import org.apache.commons.lang3.RandomStringUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
class CredentialOfferStatusIT {

    private static final String BASE_URL = "/api/v1/credentials";
    private final UUID statusListUUID = UUID.randomUUID();
    private final String statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
            .formatted(statusListUUID);

    @Autowired
    protected SwiyuProperties swiyuProperties;

    @Autowired
    protected MockMvc mvc;

    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;

    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;

    private UUID id;

    private static String getUrl(UUID id) {
        return String.format("%s/%s/status", BASE_URL, id);
    }

    @BeforeEach
    void setupTest() throws Exception {
        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusListUUID);
        statusListEntryCreationDto.setStatusRegistryUrl(statusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(statusListEntryCreationDto);

        // Mock removing access to registry
        // Add status list
        mvc.perform(post("/api/v1/status-list")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(
                                "{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": 255,\"config\": {\"bits\": 2}}"))
                .andExpect(status().isOk());
        // Add Test Offer
        id = this.createBasicOfferJsonAndGetUUID();
    }

    @AfterEach
    void tearDown() {
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        statusListRepository.deleteAll();
    }

    @Test
    void testGetOfferStatus_thenSuccess() throws Exception {

        CredentialStatusTypeDto expectedStatus = CredentialStatusTypeDto.OFFERED;

        mvc.perform(get(getUrl(id)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(expectedStatus.toString()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"READY", "CANCELLED", "SUSPENDED", "REVOKED"})
    void testUpdateWithSameStatus_thenOk(String value) throws Exception {
        var vcId = createStatusListLinkedOfferAndGetUUID();
        changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

        mvc.perform(patch(getUpdateUrl(vcId, CredentialStatusTypeDto.valueOf(value))))
                .andExpect(status().isOk());

        mvc.perform(get(getUrl(vcId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.valueOf(value).toString()));
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered1_thenBadRequest() throws Exception {

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.ISSUED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
        // todo check!! message
    }

    private TokenStatusListToken loadTokenStatusListToken(int bits, String lst) throws IOException {
        return TokenStatusListToken.loadTokenStatusListToken(bits, lst, 204800);
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenIssued_thenSuccess() throws Exception {
        UUID vcRevokedId = createIssueAndSetStateOfVc(CredentialStatusTypeDto.REVOKED);

        var offer = credentialOfferRepository.findById(vcRevokedId).get();
        Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        assertEquals(CredentialStatusType.REVOKED, offer.getCredentialStatus());
        assertEquals(1, byOfferStatusId.size());
        var offerStatus = byOfferStatusId.stream().findFirst().get();
        assertEquals(0, offerStatus.getIndex(), "Should be the very first index");
        var statusList = statusListRepository.findById(offerStatus.getId().getStatusListId()).get();
        assertEquals(1, statusList.getNextFreeIndex(), "Should NOT have advanced the counter");
        var tokenStatusList = loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be revoked");
        assertEquals(0, tokenStatusList.getStatus(1), "Should not be revoked");

        UUID vcSuspendedId = createIssueAndSetStateOfVc(CredentialStatusTypeDto.SUSPENDED);
        offer = credentialOfferRepository.findById(vcSuspendedId).get();
        assertEquals(CredentialStatusType.SUSPENDED, offer.getCredentialStatus());
        byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        offerStatus = byOfferStatusId.stream().findFirst().get();
        assertEquals(1, offerStatus.getIndex(), "Should be the the second entry");
        statusList = statusListRepository.findById(offerStatus.getId().getStatusListId()).get();
        assertEquals(2, statusList.getNextFreeIndex(), "Should have advanced the counter");
        tokenStatusList = loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
                statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be still revoked");
        assertEquals(2, tokenStatusList.getStatus(1), "Should be suspended");
        assertEquals(0, tokenStatusList.getStatus(2), "Should not be revoked");

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.ISSUED;
        mvc.perform(patch(getUpdateUrl(vcSuspendedId, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(newStatus.toString()));
        offer = credentialOfferRepository.findById(vcSuspendedId).get();
        assertEquals(CredentialStatusType.ISSUED, offer.getCredentialStatus());
        byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        offerStatus = byOfferStatusId.stream().findFirst().get();
        statusList = statusListRepository.findById(offerStatus.getId().getStatusListId()).get();
        tokenStatusList = loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
                statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be still revoked");
        assertEquals(0, tokenStatusList.getStatus(1), "Should not be suspended any more");
    }

    /**
     * Creates an offer with a linked status list, set the state to issued and then
     * revokes it
     */
    private UUID createIssueAndSetStateOfVc(CredentialStatusTypeDto newStatus) throws Exception {
        UUID vcId = createStatusListLinkedOfferAndGetUUID();

        this.updateStatusForEntity(vcId, CredentialStatusType.ISSUED);

        mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(newStatus.toString()));

        return vcId;
    }

    private String getUpdateUrl(UUID id, CredentialStatusTypeDto credentialStatus) {
        return String.format("%s?credentialStatus=%s", getUrl(id), credentialStatus);
    }

    private UUID createBasicOfferJsonAndGetUUID() throws Exception {
        String minPayloadWithEmptySubject = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}}",
                RandomStringUtils.random(10));

        MvcResult result = mvc
                .perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andReturn();

        return UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.management_id"));
    }

    private UUID createStatusListLinkedOfferAndGetUUID() throws Exception {
        String minPayloadWithEmptySubject = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(RandomStringUtils.random(10), statusRegistryUrl);

        MvcResult result = mvc
                .perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andReturn();
        try {
            return UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.management_id"));
        } catch (PathNotFoundException e) {
            throw new RuntimeException(String.format("Failed to create an offer with code %d and response %s",
                    result.getResponse().getStatus(), result.getResponse().getContentAsString()), e);
        }
    }

    CredentialOffer updateStatusForEntity(UUID id, CredentialStatusType status) {
        CredentialOffer credentialOffer = credentialOfferRepository.findById(id).get();
        credentialOffer.changeStatus(status);
        return credentialOfferRepository.save(credentialOffer);
    }

    @Test
    void testCreateOfferMultiThreaded_thenSuccess() throws Exception {
        // create some offers in a multithreaded manner
        // When increasing this too much spring boot will throw 'Failed to read request'
        // in a non-deterministic way...
        var results = IntStream.range(0, 20).parallel().mapToObj(i -> {
            try {
                return createStatusListLinkedOfferAndGetUUID();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).toList();
        // Get unique indexed on status list
        var indexSet = credentialOfferRepository.findAllById(results).stream()
                .map(offer -> {
                            Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
                            return byOfferStatusId.stream().findFirst().get().getIndex();
                        }
                )
                .collect(Collectors.toSet());
        Assertions.assertThat(indexSet).as("Should be the same size if no status was used multiple times")
                .hasSameSizeAs(results);
    }

    @Test
    void testUpdateOfferStatusMultiThreaded_thenSuccess() throws Exception {
        // create some offers in a multithreaded manner
        // When increasing this too much spring boot will throw 'Failed to read request'
        // in a non-deterministic way...
        var offerIds = IntStream.range(0, 20).parallel().mapToObj(i -> {
            try {
                return createStatusListLinkedOfferAndGetUUID();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).toList();
        // Set offers to issued
        offerIds.forEach(offerId -> {
            updateStatusForEntity(offerId, CredentialStatusType.ISSUED);
        });
        // Get all offers and the status list we are using
        var offers = offerIds.stream().map(credentialOfferRepository::findById).map(Optional::get).toList();
        CredentialOffer offer = offers.getFirst();
        Set<CredentialOfferStatus> credentialOfferStatuses = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        var statusListId = credentialOfferStatuses.stream().findFirst().get().getId().getStatusListId();
        var statusListIndexes = offers.stream()
                .map(credentialOffer -> credentialOfferStatusRepository.findByOfferStatusId(credentialOffer.getId()))
                .flatMap(Set::stream).map(CredentialOfferStatus::getIndex).collect(Collectors.toSet());
        // Check initialization
        assertTrue(offerIds.stream().map(credentialOfferRepository::findById).allMatch(credentialOffer -> credentialOffer.get().getCredentialStatus() == CredentialStatusType.ISSUED));
        var initialStatusListToken = loadTokenStatusListToken(2, statusListRepository.findById(statusListId).get().getStatusZipped());
        assertTrue(statusListIndexes.stream().allMatch(idx -> initialStatusListToken.getStatus(idx) == TokenStatusListBit.VALID.getValue()));
        // Update Status to Suspended
        offerIds.stream().parallel().forEach(offerId -> {
            try {
                mvc.perform(patch(getUpdateUrl(offerId, CredentialStatusTypeDto.SUSPENDED)))
                        .andExpect(status().is(200));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertTrue(offerIds.stream().map(credentialOfferRepository::findById).allMatch(credentialOffer -> credentialOffer.get().getCredentialStatus() == CredentialStatusType.SUSPENDED));
        offerIds.forEach(this::assertOfferStateConsistent);
        // Reset Status
        offerIds.stream().parallel().forEach(offerId -> {
            try {
                mvc.perform(patch(getUpdateUrl(offerId, CredentialStatusTypeDto.ISSUED)))
                        .andExpect(status().is(200));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertTrue(offerIds.stream().map(credentialOfferRepository::findById).allMatch(credentialOffer -> credentialOffer.get().getCredentialStatus() == CredentialStatusType.ISSUED));
        offerIds.forEach(this::assertOfferStateConsistent);
        var restoredStatusListToken = loadTokenStatusListToken(2, statusListRepository.findById(statusListId).get().getStatusZipped());
        assertEquals(initialStatusListToken.getStatusListData(), restoredStatusListToken.getStatusListData(), "Bitstring should be same again");
    }

    /**
     * Helper function that checks if the status of an offer is the same as shown in the bitstring of the status list
     *
     * @param offerId UUID of the CredentialOffer to be checked
     */
    private void assertOfferStateConsistent(UUID offerId) {
        var offer = credentialOfferRepository.findById(offerId).get();
        Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        var state = offer.getCredentialStatus();
        var statusList = statusListRepository.findById(byOfferStatusId.stream().findFirst().get().getId().getStatusListId()).get();
        byOfferStatusId.forEach(status -> {
            try {
                var tokenState = loadTokenStatusListToken(2, statusList.getStatusZipped()).getStatus(status.getIndex());
                var expectedState = switch (state) {
                    case OFFERED, CANCELLED, IN_PROGRESS, EXPIRED, DEFERRED, READY, ISSUED:
                        yield TokenStatusListBit.VALID.getValue();
                    case SUSPENDED:
                        yield TokenStatusListBit.SUSPEND.getValue();
                    case REVOKED:
                        yield TokenStatusListBit.REVOKE.getValue();
                };
                assertEquals(expectedState, tokenState, String.format("offer %s , idx %d", offerId, tokenState));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    // Helper function to mock the oid4vci and management processes
    private void changeOfferStatus(UUID offerId, CredentialStatusType status) {
        var offer = credentialOfferRepository.findById(offerId).get();
        offer.changeStatus(status);
        credentialOfferRepository.save(offer);
    }

    private void changeOfferStatus(CredentialStatusType status) {
        var offer = credentialOfferRepository.findById(id).get();
        offer.changeStatus(status);
        credentialOfferRepository.save(offer);
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

            mvc.perform(patch(getUpdateUrl(id, newStatus)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void testUpdateOfferStatusWithReadyWhenDeferred_thenOk() throws Exception {

            CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.READY;

            // Set the status to DEFERRED as this is done by the oid4vci
            var offer = credentialOfferRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException(String.format("Credential %s not found", id)));

            offer.changeStatus(CredentialStatusType.DEFERRED);

            credentialOfferRepository.save(offer);

            mvc.perform(patch(getUpdateUrl(id, newStatus)))
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
            var vcId = createBasicOfferJsonAndGetUUID();

            mvc.perform(patch(getUpdateUrl(vcId, newValue)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }

        @Test
        void testUpdateOfferStatusWithOfferedWhenInProgress_thenBadRequest() throws Exception {
            var originalState = CredentialStatusTypeDto.IN_PROGRESS.toString();
            var vcId = createBasicOfferJsonAndGetUUID();
            changeOfferStatus(vcId, CredentialStatusType.valueOf(originalState));

            mvc.perform(patch(getUpdateUrl(vcId, CredentialStatusTypeDto.OFFERED)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "CANCELLED", "IN_PROGRESS", "DEFERRED", "READY", "EXPIRED"})
        void testUpdateOfferWithIssuedWhenPreIssued_thenBadRequest(String originalState) throws Exception {

            var newValue = CredentialStatusTypeDto.ISSUED;
            var vcId = createBasicOfferJsonAndGetUUID();
            changeOfferStatus(vcId, CredentialStatusType.valueOf(originalState));

            mvc.perform(patch(getUpdateUrl(vcId, newValue)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(getUrl(vcId)))
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
            var vcId = createStatusListLinkedOfferAndGetUUID();
            changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"REVOKED"})
        void testUpdateOfferStatusWhenTerminalWhitSuspended_thenBadRequest(String value) throws Exception {
            var vcId = createIssueAndSetStateOfVc(CredentialStatusTypeDto.valueOf(value));

            mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"ISSUED", "SUSPENDED"})
        void testUpdateOfferStatusWhenSuspended_thenSuccess(String value) throws Exception {

            var vcId = createIssueAndSetStateOfVc(CredentialStatusTypeDto.valueOf(value));

            mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.SUSPENDED.toString()));
        }
    }

    @Nested
    @DisplayName("Test revocation of offers")
    class Revoked {
        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.REVOKED;

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "IN_PROGRESS", "DEFERRED", "READY"})
        void testUpdateOfferStatusWhenPreIssuedWithRevoked_thenIsOk(String value) throws Exception {
            var vcId = createStatusListLinkedOfferAndGetUUID();
            changeOfferStatus(CredentialStatusType.valueOf(value));

            mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));

            mvc.perform(get(getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"EXPIRED", "CANCELLED"})
        void testUpdateOfferStatusWhenTerminalState_thenBadRequest(String value) throws Exception {
            var vcId = createStatusListLinkedOfferAndGetUUID();
            changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"SUSPENDED", "ISSUED", "REVOKED"})
        void testUpdateOfferStatusWhenPossibleState_thenIsOk(String value) throws Exception {
            var vcId = createIssueAndSetStateOfVc(CredentialStatusTypeDto.valueOf(value));

            mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk());
        }

        /**
         * Should fail because no way of revocation is available
         */
        @Test
        void testUpdateOfferStatusWithRevokedWhenIssuedWithoutStatusList_thenBadRequest() throws Exception {
            CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.REVOKED;

            updateStatusForEntity(id, CredentialStatusType.ISSUED);

            mvc.perform(patch(getUpdateUrl(id, newStatus)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void testUpdateOfferStatusWithRevokedWhenRevoked_thenOk() throws Exception {

            CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.REVOKED;

            mvc.perform(patch(getUpdateUrl(id, newStatus)))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Test cancellation of offers")
    class Cancelled {

        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.CANCELLED;

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "IN_PROGRESS", "DEFERRED", "READY", "CANCELLED"})
        void testCancelWhenPreIssued_thenOk(String value) throws Exception {
            var vcId = createStatusListLinkedOfferAndGetUUID();
            changeOfferStatus(CredentialStatusType.valueOf(value));

            mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));

            mvc.perform(get(getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"REVOKED", "SUSPENDED", "ISSUED"})
        void testCancelWhenPostIssued_thenBadRequest(String value) throws Exception {
            var originalState = CredentialStatusTypeDto.valueOf(value);
            var vcId = createIssueAndSetStateOfVc(originalState);
            updateStatusForEntity(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState.toString()));
        }

        @Test
        void testUpdateOfferStatusWithCancelledWhenExpired_thenBadRequest() throws Exception {
            var originalState = CredentialStatusTypeDto.EXPIRED;
            var vcId = createBasicOfferJsonAndGetUUID();
            changeOfferStatus(vcId, CredentialStatusType.valueOf(originalState.toString()));

            mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState.toString()));
        }
    }
}