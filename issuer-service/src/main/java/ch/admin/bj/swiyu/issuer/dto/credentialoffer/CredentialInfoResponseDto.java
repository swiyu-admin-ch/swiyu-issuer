package ch.admin.bj.swiyu.issuer.dto.credentialoffer;

import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.CredentialStatusTypeDto;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "CredentialInfoResponse")
public record CredentialInfoResponseDto(
        @JsonProperty("status")
        CredentialStatusTypeDto credentialStatus,
        @JsonProperty("metadata_credential_supported_id")
        List<String> metadataCredentialSupportedId,
        @JsonProperty("credential_metadata")
        CredentialOfferMetadataDto credentialMetadata,
        @JsonProperty("holder_jwks")
        List<String> holderJWKs,
        @JsonProperty("key_attestations")
        List<String> keyAttestations,
        @JsonProperty("client_agent_info")
        ClientAgentInfoDto clientAgentInfo,
        @JsonProperty("offer_expiration_timestamp")
        long offerExpirationTimestamp,
        @JsonProperty("deferred_offer_expiration_seconds")
        int deferredOfferExpirationSeconds,
        @JsonProperty("credential_valid_from")
        Instant credentialValidFrom,
        @JsonProperty("credential_valid_until")
        Instant credentialValidUntil,
//        @JsonProperty("credential_request")
//        CredentialEndpointRequestDto credentialRequest,
        @JsonProperty(value = "offer_deeplink")
        String offerDeeplink,
        @JsonProperty(value = "vc_hash")
        List<String> vcHashes
) {
}