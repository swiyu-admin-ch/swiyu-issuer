/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

import java.util.Map;
import java.util.UUID;

@Schema(name = "DeferredCredentialRequest")
public record DeferredCredentialRequestDto(
        @NotNull
        @JsonProperty("transaction_id")
        @Schema(description = "Id received from the create credential request for the deferred flow.")
        UUID transactionId,

        @Schema(description = "Proof for holder binding. Can be in key:did or cnf format.")
        @CredentialRequestProofConstraint
        Map<String, Object> proof
) {
}