package ch.admin.bj.swiyu.issuer.api.credentialoffer;

import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestDto;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record CredentialInfoResponseDto(
        @JsonProperty("status")
        CredentialStatusTypeDto credentialStatus,
        @JsonProperty("metadata_credential_supported_id")
        List<String> metadataCredentialSupportedId,
        @JsonProperty("credential_metadata")
        Map<String, Object> credentialMetadata,
        @JsonProperty("holder_jwk")
        String holderJWK,
        @JsonProperty("client_agent_info")
        ClientAgentInfoDto clientAgentInfo,
        @JsonProperty("offer_expiration_timestamp")
        long offerExpirationTimestamp,
        @JsonProperty("credential_valid_from")
        Instant credentialValidFrom,
        @JsonProperty("credential_valid_until")
        Instant credentialValidUntil,
        @JsonProperty("credential_request")
        CredentialRequestDto credentialRequest,
        @JsonProperty(value = "offer_deeplink")
        String offerDeeplink
) {
}