package ch.admin.bj.swiyu.issuer.management.it;

import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class CredentialOfferTestHelper {

    public static final String BASE_URL = "/management/api/v1/credentials";

    private final MockMvc mvc;
    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final StatusListRepository statusListRepository;
    
    private final String statusRegistryUrl;


    public CredentialOfferTestHelper(MockMvc mvc,
                                     CredentialOfferRepository credentialOfferRepository,
                                     CredentialOfferStatusRepository credentialOfferStatusRepository,
                                     StatusListRepository statusListRepository, String unsetStatusRegistryUrl) {
        this.mvc = mvc;
        this.credentialOfferRepository = credentialOfferRepository;
        this.credentialOfferStatusRepository = credentialOfferStatusRepository;
        this.statusListRepository = statusListRepository;
        statusRegistryUrl = unsetStatusRegistryUrl;
    }

    public UUID createBasicOfferJsonAndGetUUID() throws Exception {
        String minPayloadWithEmptySubject = "{\"metadata_credential_supported_id\": [\"test\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}}";

        MvcResult result = mvc
                .perform(post(BASE_URL).contentType("application/json").content(minPayloadWithEmptySubject))
                .andReturn();

        return UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.management_id"));
    }

    public UUID createStatusListLinkedOfferAndGetUUID() throws Exception {
        String payload = "{\"metadata_credential_supported_id\": [\"test\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(statusRegistryUrl);

        MvcResult result = mvc
                .perform(post(BASE_URL).contentType("application/json").content(payload))
                .andExpect(status().isOk())
                .andReturn();

        try {
            return UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.management_id"));
        } catch (PathNotFoundException e) {
            throw new RuntimeException(String.format("Failed to create an offer with code %d and response %s",
                    result.getResponse().getStatus(), result.getResponse().getContentAsString()), e);
        }
    }


    public CredentialOffer updateStatusForEntity(UUID id, CredentialStatusType status) {
        CredentialOffer credentialOffer = credentialOfferRepository.findById(id).orElseThrow();
        credentialOffer.changeStatus(status);
        return credentialOfferRepository.save(credentialOffer);
    }

    public void assertOfferStateConsistent(UUID offerId) {
        var offer = credentialOfferRepository.findById(offerId).orElseThrow();
        Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        var state = offer.getCredentialStatus();
        var statusList = statusListRepository.findById(byOfferStatusId.stream().findFirst().orElseThrow().getId().getStatusListId()).orElseThrow();
        byOfferStatusId.forEach(status -> {
            try {
                var tokenState = TokenStatusListToken.loadTokenStatusListToken(2, statusList.getStatusZipped(), 204800).getStatus(status.getIndex());
                var expectedState = switch (state) {
                    case OFFERED, CANCELLED, IN_PROGRESS, EXPIRED, DEFERRED, READY, ISSUED ->
                            TokenStatusListBit.VALID.getValue();
                    case SUSPENDED -> TokenStatusListBit.SUSPEND.getValue();
                    case REVOKED -> TokenStatusListBit.REVOKE.getValue();
                };
                if (expectedState != tokenState) {
                    throw new AssertionError(String.format("Offer %s, idx %d: expected %d but got %d", offerId, status.getIndex(), expectedState, tokenState));
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    TokenStatusListToken loadTokenStatusListToken(int bits, String lst) throws IOException {
        return TokenStatusListToken.loadTokenStatusListToken(bits, lst, 204800);
    }

    String getUpdateUrl(UUID id, CredentialStatusTypeDto credentialStatus) {
        return String.format("%s?credentialStatus=%s", getUrl(id), credentialStatus);
    }

    String getUrl(UUID id) {
        return String.format("%s/%s/status", BASE_URL, id);
    }


    // Helper function to mock the oid4vci and management processes
    void changeOfferStatus(UUID offerId, CredentialStatusType status) {
        var offer = credentialOfferRepository.findById(offerId).get();
        offer.changeStatus(status);
        credentialOfferRepository.save(offer);
    }

    /**
     * Creates an offer with a linked status list, set the state to issued and then
     * revokes it
     */
    UUID createIssueAndSetStateOfVc(CredentialStatusTypeDto newStatus) throws Exception {
        UUID vcId = createStatusListLinkedOfferAndGetUUID();

        this.updateStatusForEntity(vcId, CredentialStatusType.ISSUED);

        mvc.perform(patch(getUpdateUrl(vcId, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(newStatus.toString()));

        return vcId;
    }
}