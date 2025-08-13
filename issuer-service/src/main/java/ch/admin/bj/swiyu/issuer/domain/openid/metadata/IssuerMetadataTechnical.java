/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

/**
 * The issuer metadata represented here are the fields used for technical decisions in creating the VC.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@Validated
public class IssuerMetadataTechnical {

    @JsonProperty("credential_issuer")
    @NotNull
    private String credentialIssuer;

    /**
     * Information for the holder where to get the credential.
     * Must be present or the holder will not be able to fetch the credential
     */
    @JsonProperty("credential_endpoint")
    @NotNull
    @Pattern(regexp = "^.+/credential$", message = "Credential endpoint for this issuer is /credential")
    private String credentialEndpoint;

    @JsonProperty("credential_configurations_supported")
    @NotNull
    @Size(min = 1, message = "At least one credential configuration has to be be provided")
    @Valid
    private Map<String, CredentialConfiguration> credentialConfigurationSupported;

    @JsonProperty("credential_response_encryption")
    @Valid
    private IssuerCredentialResponseEncryption responseEncryption;

    @JsonProperty("batch_credential_issuance")
    private BatchCredentialIssuance batchCredentialIssuance;

    @JsonProperty("version")
    @NotNull
    @Pattern(regexp = "^1\\.0$", message = "Only version 1.0 is supported")
    private String version;

    public @NotNull CredentialConfiguration getCredentialConfigurationById(String credentialConfigurationSupportedId) {
        CredentialConfiguration credentialConfiguration = credentialConfigurationSupported.get(credentialConfigurationSupportedId);
        if (credentialConfiguration == null) {
            throw new Oid4vcException(CredentialRequestError.INVALID_CREDENTIAL_REQUEST, "Requested Credential is not offered (anymore).");
        }
        return credentialConfiguration;
    }
}