/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.util.List;

/**
 * proof_types_supported describes specifics of the key proof(s) that the Credential Issuer supports.
 * This identifier is also used by the Wallet in the Credential Request <br>
 * For more details see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2.3">OID4VCI Credential Issuer Metadata Parameters</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SupportedProofType {
    /**
     * array of case sensitive strings that identify the algorithms that the Issuer supports for this proof type.
     * The Wallet uses one of them to sign the proof. Algorithm names used are determined by the key proof type
     */
    @JsonProperty(value = "proof_signing_alg_values_supported")
    List<@Pattern(regexp = "^ES256$", message = "Only ES256 is supported for holder binding proofs") String> supportedSigningAlgorithms;

    /**
     * If the Credential Issuer does not require a key attestation, this parameter MUST NOT be present in the metadata.
     * If the key_attestations_required is present but empty, a key attestation is required,
     * but no requirement to its level is made.
     */
    @Nullable
    @JsonProperty(value = "key_attestations_required")
    KeyAttestationRequirement keyAttestationRequirement;

}
