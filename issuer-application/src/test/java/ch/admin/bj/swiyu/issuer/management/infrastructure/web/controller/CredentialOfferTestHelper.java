package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.CredentialStatusTypeDto;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import org.apache.http.client.utils.URLEncodedUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.getMinimalPayloadForCredentialSupportedIdTest;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class CredentialOfferTestHelper {

    public static final String BASE_URL = "/management/api/credentials";

    private final MockMvc mvc;
    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final StatusListRepository statusListRepository;
    private final CredentialManagementRepository credentialManagementRepository;

    private final String statusRegistryUrl;


    public CredentialOfferTestHelper(MockMvc mvc,
                                     CredentialOfferRepository credentialOfferRepository,
                                     CredentialOfferStatusRepository credentialOfferStatusRepository,
                                     StatusListRepository statusListRepository,
                                     CredentialManagementRepository credentialManagementRepository,
                                     String unsetStatusRegistryUrl) {
        this.mvc = mvc;
        this.credentialOfferRepository = credentialOfferRepository;
        this.credentialOfferStatusRepository = credentialOfferStatusRepository;
        this.statusListRepository = statusListRepository;
        this.credentialManagementRepository = credentialManagementRepository;
        statusRegistryUrl = unsetStatusRegistryUrl;
    }

    public UUID createBasicOfferJsonAndGetUUID() throws Exception {
        String minPayloadWithEmptySubject = getMinimalPayloadForCredentialSupportedIdTest();

        MvcResult result = mvc
                .perform(post(BASE_URL).contentType("application/json").content(minPayloadWithEmptySubject))
                .andReturn();

        return UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.management_id"));
    }

    public ResultActions createOffer(String payload) throws Exception {
        return mvc
                .perform(post(BASE_URL).contentType("application/json").content(payload));
    }

    public String createBasicOfferJsonAndGetTenantID() throws Exception {
        var objectMapper = new ObjectMapper();
        String minPayloadWithEmptySubject = getMinimalPayloadForCredentialSupportedIdTest();

        MvcResult result = mvc
                .perform(post(BASE_URL).contentType("application/json").content(minPayloadWithEmptySubject))
                .andReturn();

        var createCredentialOfferResponse = assertDoesNotThrow(() -> objectMapper.readValue(result.getResponse()
                .getContentAsString(), CredentialWithDeeplinkResponseDto.class));
        var deeplink = createCredentialOfferResponse.getOfferDeeplink();
        var parsedDeeplink = assertDoesNotThrow(() -> new URI(deeplink));
        var offerQuery = URLEncodedUtils.parse(parsedDeeplink, StandardCharsets.UTF_8);
        var credentialOffer = offerQuery.getFirst();
        var parsedOffer = assertDoesNotThrow(
                () -> objectMapper.readValue(credentialOffer.getValue(), Map.class));
        return assertDoesNotThrow(() -> new URI(parsedOffer.get("credential_issuer").toString()).getPath());
    }

    public UUID createStatusListLinkedOfferAndGetUUID() throws Exception {
        String payload = getMinimalPayloadForCredentialSupportedIdTest(null, null, statusRegistryUrl);

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

    public UUID createWithOfferStatus(CredentialOfferStatusType status) throws Exception {
        var managementId = createStatusListLinkedOfferAndGetUUID();

        var mgmt = credentialManagementRepository.findById(managementId).orElseThrow();
        mgmt.getCredentialOffers().stream().findFirst().ifPresent(offer -> {
            offer.setCredentialOfferStatusJustForTestUsage(status);
            credentialOfferRepository.save(offer);
        });

        return managementId;
    }

    public void assertOfferStateConsistent(UUID offerId, CredentialOfferStatusType statusType) {
        var offer = credentialOfferRepository.findById(offerId).orElseThrow();
        Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository.findByOfferId(offer.getId());
        var statusList = statusListRepository.findById(byOfferStatusId.stream().findFirst().orElseThrow().getId().getStatusListId()).orElseThrow();
        byOfferStatusId.forEach(status -> {
            try {
                var tokenState = TokenStatusListToken.loadTokenStatusListToken(2, statusList.getStatusZipped(), 204800).getStatus(status.getId().getIndex());
                var expectedState = switch (statusType) {
                    case INIT, OFFERED, CANCELLED, IN_PROGRESS, EXPIRED, DEFERRED, READY, ISSUED, REQUESTED ->
                            TokenStatusListBit.VALID.getValue();
                };
                if (expectedState != tokenState) {
                    throw new AssertionError(String.format("Offer %s, idx %d: expected %d but got %d", offerId, status.getId().getIndex(), expectedState, tokenState));
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public String getUpdateUrl(UUID id, CredentialStatusTypeDto credentialStatus) {
        return String.format("%s?credentialStatus=%s", getStatusUrl(id), credentialStatus);
    }

    TokenStatusListToken loadTokenStatusListToken(int bits, String lst) throws IOException {
        return TokenStatusListToken.loadTokenStatusListToken(bits, lst, 204800);
    }

    String getStatusUrl(UUID id) {
        return String.format("%s/%s/status", BASE_URL, id);
    }


    // Helper function to mock the oid4vci and management processes
    void changeOfferStatus(UUID offerId, CredentialOfferStatusType status) {
        var offer = credentialOfferRepository.findById(offerId).get();
        offer.setCredentialOfferStatusJustForTestUsage(status);
        credentialOfferRepository.save(offer);
    }
}