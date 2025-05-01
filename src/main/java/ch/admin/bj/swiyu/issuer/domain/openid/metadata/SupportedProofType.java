/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class SupportedProofType {
    @JsonProperty(value = "proof_signing_alg_values_supported")
    List<@Pattern(regexp = "^ES256$", message = "Only ES256 is supported for holder binding proofs") String> supportedSigningAlgorithms;

}
