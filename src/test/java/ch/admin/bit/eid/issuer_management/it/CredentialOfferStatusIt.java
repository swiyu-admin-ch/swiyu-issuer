package ch.admin.bit.eid.issuer_management.it;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.models.entities.CredentialOfferEntity;
import ch.admin.bit.eid.issuer_management.repositories.CredentialOfferRepository;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DisplayName("Offer status it")
class CredentialOfferStatusIt extends BaseIt  {

    @Autowired
    private CredentialOfferRepository repo;

    @Test
    void testGetOfferStatus_thenSuccess() throws Exception {
        UUID id = this.createBasicRequestJsonAndGetUUID();
        CredentialStatusEnum expectedStatus = CredentialStatusEnum.OFFERED;

        mvc.perform(get(getUrl(id)))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedStatus.getDisplayName()));
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered_thenBadRequest() throws Exception {
        UUID id = this.createBasicRequestJsonAndGetUUID();
        CredentialStatusEnum newStatus = CredentialStatusEnum.OFFERED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered1_thenBadRequest() throws Exception {
        UUID id = this.createBasicRequestJsonAndGetUUID();
        CredentialStatusEnum newStatus = CredentialStatusEnum.ISSUED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
        // todo check!! message
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenIssued_thenSuccess() throws Exception {
        UUID id = this.createBasicRequestJsonAndGetUUID();
        CredentialStatusEnum newStatus = CredentialStatusEnum.REVOKED;

        this.updateStatusForEntity(id, CredentialStatusEnum.ISSUED);

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(newStatus.getDisplayName()));
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenOffered_thenSuccess() throws Exception {
        UUID id = this.createBasicRequestJsonAndGetUUID();
        CredentialStatusEnum newStatus = CredentialStatusEnum.REVOKED;

        mvc.perform(patch(getUpdateUrl(id, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.status").value(newStatus.getDisplayName()));


        mvc.perform(get(String.format("%s/%s", BASE_URL, id)))
                // todo check
                .andExpect(status().isOk());
    }

    private String getUpdateUrl(UUID id, CredentialStatusEnum credentialStatus) {
        return String.format("%s?credentialStatus=%s", getUrl(id), credentialStatus);
    }

    private static String getUrl(UUID id) {
        return String.format("%s/%s/status", BASE_URL, id);
    }

    private UUID createBasicRequestJsonAndGetUUID() throws Exception {
        String minPayloadWithEmptySubject = String.format("{\"metadata_credential_supported_id\": \"%s\", \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}}", RandomStringUtils.random(10));

        MvcResult result = mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject)).andReturn();

        return UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.management_id"));
    }

    private CredentialOfferEntity updateStatusForEntity(UUID id, CredentialStatusEnum status) {
        CredentialOfferEntity credentialOffer = repo.findById(id).get();
        credentialOffer.setCredentialStatus(status);

        return repo.save(credentialOffer);
    }
}
