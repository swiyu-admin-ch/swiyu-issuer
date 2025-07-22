package ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialResponseEncryptionDto;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

// TODO check if CredentialResponseEncryptionDto still correct
// TODO "format": "dc+sd-jwt"
// TODO "remove offer deeplink"
// TODO check if comments make sense, or if they are too verbose

/**
 * @param credentialConfigurationId
 * @param proofs
 * @param credentialResponseEncryption spec: <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request">...</a>
 */
public record CredentialRequestDtoV2(
        /*
         *  String that uniquely identifies one of the keys in the name/value pairs stored in the credential_configurations_supported Credential Issuer metadata
         */
        @JsonProperty("credential_configuration_id")
        @NotBlank String credentialConfigurationId,

        /*
         * Object providing one or more proof of possessions of the cryptographic key material to which the issued Credential instances will be bound to. The proofs parameter contains exactly one parameter
         */
        @Valid ProofsDto proofs,

        @JsonProperty("credential_response_encryption")
        CredentialResponseEncryptionDto credentialResponseEncryption
) {
}