package ch.admin.bj.swiyu.issuer.dto;

import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialInfoResponseDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.CredentialStatusTypeDto;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.UUID;


@JsonInclude(JsonInclude.Include.NON_NULL)
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
        List<CredentialInfoResponseDto> credentialOffers,
        @JsonProperty("dpop_key")
        String dpopKey
) {
}