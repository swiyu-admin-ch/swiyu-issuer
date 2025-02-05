/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.it;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.management.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.TokenStatusListToken;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import org.apache.commons.lang3.RandomStringUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
class CredentialOfferStatusIT {

    private static final String BASE_URL = "/credentials";
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

    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;

    private UUID id;

    private static String getUrl(UUID id) {
        return String.format("%s/%s/status", BASE_URL, id);
    }

    @BeforeEach
    void setupTest() throws Exception {
        credentialOfferRepository.deleteAll();
        statusListRepository.deleteAll();

        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusListUUID);
        statusListEntryCreationDto.setStatusRegistryUrl(statusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(statusListEntryCreationDto);

        // Mock removing access to registry
        // Add status list
        mvc.perform(post("/status-list")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(
                                "{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": 255,\"config\": {\"bits\": 2}}"))
                .andExpect(status().isOk());
        // Add Test Offer
        id = this.createBasicOfferJsonAndGetUUID();
    }

    @Test
    void testGetOfferStatus_thenSuccess() throws Exception {

        CredentialStatusTypeDto expectedStatus = CredentialStatusTypeDto.OFFERED;

        mvc.perform(get(getUrl(id)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(expectedStatus.toString()));
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered_thenOk() throws Exception {

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.OFFERED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isOk());
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered_thenBadRequest() throws Exception {

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.OFFERED;

        mvc.perform(patch(getUpdateUrl(id, CredentialStatusTypeDto.REVOKED)))
                .andExpect(status().isOk());

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenRevoked_thenOk() throws Exception {

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.OFFERED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isOk());
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered1_thenBadRequest() throws Exception {

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.ISSUED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
        // todo check!! message
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenIssued_thenSuccess() throws Exception {
        UUID vcRevokedId = createIssueAndSetStateOfVc(CredentialStatusTypeDto.REVOKED);

        var offer = credentialOfferRepository.findById(vcRevokedId).get();
        assertEquals(CredentialStatusType.REVOKED, offer.getCredentialStatus());
        assertEquals(1, offer.getOfferStatusSet().size());
        var offerStatus = offer.getOfferStatusSet().stream().findFirst().get();
        assertEquals(0, offerStatus.getIndex(), "Should be the very first index");
        var statusList = offerStatus.getStatusList();
        assertEquals(1, statusList.getNextFreeIndex(), "Should have advanced the counter");
        var tokenStatusList = TokenStatusListToken
                .loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be revoked");
        assertEquals(0, tokenStatusList.getStatus(1), "Should not be revoked");

        UUID vcSuspendedId = createIssueAndSetStateOfVc(CredentialStatusTypeDto.SUSPENDED);
        offer = credentialOfferRepository.findById(vcSuspendedId).get();
        assertEquals(CredentialStatusType.SUSPENDED, offer.getCredentialStatus());
        offerStatus = offer.getOfferStatusSet().stream().findFirst().get();
        assertEquals(1, offerStatus.getIndex(), "Should be the the second entry");
        statusList = offerStatus.getStatusList();
        assertEquals(2, statusList.getNextFreeIndex(), "Should have advanced the counter");
        tokenStatusList = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
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
        offerStatus = offer.getOfferStatusSet().stream().findFirst().get();
        statusList = offerStatus.getStatusList();
        tokenStatusList = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
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

    /**
     * Should fail because no way of revocation is available
     */
    @Test
    void testUpdateOfferStatusWithRevokedWhenIssuedWithoutStatusList_thenBadRequest() throws Exception {
        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.REVOKED;

        this.updateStatusForEntity(id, CredentialStatusType.ISSUED);

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenOffered_thenSuccess() throws Exception {
        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.CANCELLED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));

        mvc.perform(get(String.format("%s/%s", BASE_URL, id)))
                .andExpect(status().isOk());

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

    private CredentialOffer updateStatusForEntity(UUID id, CredentialStatusType status) {
        CredentialOffer credentialOffer = credentialOfferRepository.findById(id).get();
        credentialOffer.changeStatus(status);
        return credentialOfferRepository.save(credentialOffer);
    }

    @Test
    void testCreateOfferMultiThreaded_thenSuccess() throws Exception {
        // create some offers in a multithreaded manner
        // When increasing this too much spring boot will throw 'Failed to read request'
        // in a non-deterministic way...
        var results = IntStream.range(0, 5).parallel().mapToObj(i -> {
            try {
                return createStatusListLinkedOfferAndGetUUID();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).toList();
        // Get unique indexed on status list
        var indexSet = credentialOfferRepository.findAllById(results).stream()
                .map(offer -> offer.getOfferStatusSet().stream().findFirst().get().getIndex())
                .collect(Collectors.toSet());
        Assertions.assertThat(indexSet).as("Should be the same size if no status was used multiple times")
                .hasSameSizeAs(results);

    }
}
