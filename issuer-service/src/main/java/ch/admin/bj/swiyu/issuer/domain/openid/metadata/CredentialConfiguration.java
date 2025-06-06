/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@Validated
public class CredentialConfiguration {
    @NotNull
    @Pattern(regexp = "^vc\\+sd-jwt$", message = "Only vc+sd-jwt format is supported")
    private String format;

    /**
     * SD-JWT specific field <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A.3.2">see specs</a>
     * Optional
     */
    @NotNull
    private String vct;

    /**
     * SD-JWT specific field <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A.3.2">see specs</a>
     * Optional
     */
    @JsonProperty("claims")
    private HashMap<String, Object> claims;

    /**
     * Field for VC not SD-JWT (VC Signed as JWT or JSON-LD)
     * Optional
     */
    @JsonProperty("credential_definition")
    @Null(message = "Credential definition is not allowed for the vc+sd-jwt format which is the only one supported")
    private CredentialDefinition credentialDefinition;

    /**
     * Target representation of the holder public key material in the issued credential.
     * The following is our current understanding of the purpose of the attribute:
     * E.g. when specifying ["did:jwk","jwk"] this means that the binding public key provided by the
     * holder is taken and put in the credentials one time as did:jwk and additionally as jwk.
     * Mapping/converting of the original public key is applied where needed. Currently only did:jwk is supported.
     */
    @JsonProperty("cryptographic_binding_methods_supported")
    @Valid
    private List<@Pattern(regexp = "^(did:)?jwk$", message = "Only jwk and did:jwk are supported")String> cryptographicBindingMethodsSupported;

    /**
     * Case-sensitive strings that identify the algorithms that the Issuer uses to sign the issued Credential
     */
    @JsonProperty("credential_signing_alg_values_supported")
    @Valid
    private List<@Pattern(regexp = "^ES256$") String> credentialSigningAlgorithmsSupported;

    /**
     * Define what kind of proof the holder is allowed to provide for the credential
     */
    @JsonProperty("proof_types_supported")
    @Size(max = 1)
    @Valid
    private Map<@Pattern(regexp = "^jwt$", message = "Only jwt holder binding proofs are supported") String, SupportedProofType> proofTypesSupported;


    @PostConstruct
    public void postConstruct() {
        if(!proofTypesSupported.isEmpty() && cryptographicBindingMethodsSupported.isEmpty()) {
            throw new IllegalArgumentException("If proof types are supported, cryptographic binding methods must be specified as well");
        }
    }
}
