package ch.admin.bj.swiyu.issuer.api;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialInfoResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.UUID;

public record CredentialManagementDto(
        @JsonProperty("id")
        UUID id,
        @JsonProperty("status")
        CredentialStatusTypeDto credentialStatus,
        @JsonProperty("renewal_request_count")
        Integer renewalRequestCount,
        @JsonProperty("renewal_response_count")
        Integer renewalResponseCount,
        @JsonProperty("credential_offers")
        List<CredentialInfoResponseDto> credentialOffers
) {

}