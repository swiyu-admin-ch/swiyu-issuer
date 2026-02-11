package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.Map;

@Schema(name = "CredentialEndpointRequest", description = "Request to the Credential Endpoint as defined in OID4VCI draft 13 specification")
@Deprecated(since = "OID4VCI 1.0")
public record CredentialEndpointRequestDto(
        @NotNull
        @Pattern(regexp = "^vc\\+sd-jwt$", message = "Only vc+sd-jwt format is supported")
        String format,

        @Schema(description = "Proof for holder binding. Can be in key:did or cnf format.")
        @CredentialRequestProofConstraint
        Map<String, Object> proof,

        /**
         * If this request element is not present, the corresponding credential response returned is not encrypted
         */
        @JsonProperty("credential_response_encryption")
        CredentialResponseEncryptionDto credentialResponseEncryption
) {
}