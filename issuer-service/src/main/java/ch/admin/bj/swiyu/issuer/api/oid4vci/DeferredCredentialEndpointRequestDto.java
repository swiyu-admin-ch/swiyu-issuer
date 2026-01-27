/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.api.oid4vci;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

@Schema(name = "DeferredCredentialEndpointRequest", description = "Request to the deferred credential endpoint.")
public record DeferredCredentialEndpointRequestDto(
        @NotNull
        @JsonProperty("transaction_id")
        @Schema(description = "Id received from the create credential request for the deferred flow.")
        UUID transactionId,
        
        @Nullable
        @JsonProperty("credential_response_encryption")
        @Schema(description = """
                Note that this object will be used for encrypting the response, regardless of what was sent in the initial Credential Request.
                If this parameter is missing, the credential_response_encryption sent in the credential request will be used.
                """)
        CredentialResponseEncryptionDto credentialResponseEncryption
) {
}