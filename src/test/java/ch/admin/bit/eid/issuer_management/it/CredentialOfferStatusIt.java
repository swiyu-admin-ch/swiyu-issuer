package ch.admin.bit.eid.issuer_management.it;

import ch.admin.bit.eid.issuer_management.domain.CredentialOfferRepository;
import ch.admin.bit.eid.issuer_management.domain.StatusListRepository;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer;
import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.models.statuslist.TokenStatusListToken;
import ch.admin.bit.eid.issuer_management.services.TemporaryStatusListRestClientService;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("Offer status it")
class CredentialOfferStatusIt extends BaseIt {

    @Autowired
    private CredentialOfferRepository repo;

    @Autowired
    private StatusListRepository statusListRepository;

    @MockBean
    private TemporaryStatusListRestClientService temporaryStatusListRestClientService;

    private UUID id;

    @BeforeEach
    void setupTest() throws Exception {
        // Mock removing access to registry
        Mockito.doNothing().when(temporaryStatusListRestClientService).updateStatusList(ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(String.class));
        // Add status list
        mvc.perform(post("/status-list")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"uri\": \"https://status-data-service-d.apps.p-szb-ros-shrd-npr-01.cloud.admin.ch/api/v1/statuslist/874e5579-928e-42a4-8051-a3f9e9ead16f.jwt\",\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": 255,\"config\": {\"bits\": 2}}")
        ).andExpect(status().isOk());
        // Add Test Offer
        id = this.createBasicOfferJsonAndGetUUID();
    }

    @AfterEach
    void teardownTest() {
        repo.deleteAll();
        statusListRepository.deleteAll();
    }

    @Test
    void testGetOfferStatus_thenSuccess() throws Exception {

        CredentialStatusEnum expectedStatus = CredentialStatusEnum.OFFERED;

        mvc.perform(get(getUrl(id)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(expectedStatus.toString()));
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered_thenBadRequest() throws Exception {

        CredentialStatusEnum newStatus = CredentialStatusEnum.OFFERED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered1_thenBadRequest() throws Exception {

        CredentialStatusEnum newStatus = CredentialStatusEnum.ISSUED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
        // todo check!! message
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenIssued_thenSuccess() throws Exception {
        UUID vcRevokedId = createIssueAndSetStateOfVc(CredentialStatusEnum.REVOKED);

        var offer = repo.findById(vcRevokedId).get();
        assertEquals(CredentialStatusEnum.REVOKED, offer.getCredentialStatus());
        assertEquals(1, offer.getOfferStatusSet().size());
        var offerStatus = offer.getOfferStatusSet().stream().findFirst().get();
        assertEquals(0, offerStatus.getIndex(), "Should be the very first index");
        var statusList = offerStatus.getStatusList();
        assertEquals(1, statusList.getLastUsedIndex(), "Should have advanced the counter");
        var tokenStatusList = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be revoked");
        assertEquals(0, tokenStatusList.getStatus(1), "Should not be revoked");

        UUID vcSuspendedId = createIssueAndSetStateOfVc(CredentialStatusEnum.SUSPENDED);
        offer = repo.findById(vcSuspendedId).get();
        assertEquals(CredentialStatusEnum.SUSPENDED, offer.getCredentialStatus());
        offerStatus = offer.getOfferStatusSet().stream().findFirst().get();
        assertEquals(1, offerStatus.getIndex(), "Should be the the second entry");
        statusList = offerStatus.getStatusList();
        assertEquals(2, statusList.getLastUsedIndex(), "Should have advanced the counter");
        tokenStatusList = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be still revoked");
        assertEquals(2, tokenStatusList.getStatus(1), "Should be suspended");
        assertEquals(0, tokenStatusList.getStatus(2), "Should not be revoked");

        CredentialStatusEnum newStatus = CredentialStatusEnum.ISSUED;
        mvc.perform(patch(getUpdateUrl(vcSuspendedId, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(newStatus.toString()));
        offer = repo.findById(vcSuspendedId).get();
        assertEquals(CredentialStatusEnum.ISSUED, offer.getCredentialStatus());
        offerStatus = offer.getOfferStatusSet().stream().findFirst().get();
        statusList = offerStatus.getStatusList();
        tokenStatusList = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be still revoked");
        assertEquals(0, tokenStatusList.getStatus(1), "Should not be suspended any more");
    }

    /**
     * Creates an offer with a linked status list, set the state to issued and then revokes it
     */
    @NotNull
    private UUID createIssueAndSetStateOfVc(CredentialStatusEnum newStatus) throws Exception {
        UUID vcId = createStatusListLinkedOfferAndGetUUID();

        this.updateStatusForEntity(vcId, CredentialStatusEnum.ISSUED);


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
        CredentialStatusEnum newStatus = CredentialStatusEnum.REVOKED;

        this.updateStatusForEntity(id, CredentialStatusEnum.ISSUED);


        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
    }


    @Test
    void testUpdateOfferStatusWithRevokedWhenOffered_thenSuccess() throws Exception {
        CredentialStatusEnum newStatus = CredentialStatusEnum.REVOKED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.status").value(newStatus.toString()));


        mvc.perform(get(String.format("%s/%s", BASE_URL, id)))
                .andExpect(status().isOk());

    }

    private String getUpdateUrl(UUID id, CredentialStatusEnum credentialStatus) {
        return String.format("%s?credentialStatus=%s", getUrl(id), credentialStatus);
    }

    private UUID createBasicOfferJsonAndGetUUID() throws Exception {
        String minPayloadWithEmptySubject = String.format("{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}}", RandomStringUtils.random(10));

        MvcResult result = mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject)).andReturn();

        return UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.management_id"));
    }

    private UUID createStatusListLinkedOfferAndGetUUID() throws Exception {
        String minPayloadWithEmptySubject = String.format("{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"https://status-data-service-d.apps.p-szb-ros-shrd-npr-01.cloud.admin.ch/api/v1/statuslist/874e5579-928e-42a4-8051-a3f9e9ead16f.jwt\"]}", RandomStringUtils.random(10));

        MvcResult result = mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject)).andReturn();

        return UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.management_id"));
    }

    private CredentialOffer updateStatusForEntity(UUID id, CredentialStatusEnum status) {
        CredentialOffer credentialOffer = repo.findById(id).get();
        credentialOffer.setCredentialStatus(status);

        return repo.save(credentialOffer);
    }

    private static String getUrl(UUID id) {
        return String.format("%s/%s/status", BASE_URL, id);
    }
}
