/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;

/**
 * The issuer metadata represented here are the fields used for technical decisions in creating the VC.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@Validated
@Schema(name="IssuerMetadata", description = """
        The OID4VCI Credential Issuer Metadata contains information on the Credential Issuer's technical capabilities,
        supported Credentials, and (internationalized) display information.
        """)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IssuerMetadata {

    @JsonProperty("credential_issuer")
    @NotNull
    @Schema(description = "The Credential Issuer's identifier")
    private String credentialIssuer;

    @JsonProperty("authorization_servers")
    private List<String> authorizationServers;

    @JsonProperty("credential_endpoint")
    @NotNull
    @Pattern(regexp = "^.+/credential$", message = "Credential endpoint for this issuer is /credential")
    @Schema(description = """
            Information for the holder where to get the credential.
            """)
    private String credentialEndpoint;

    @JsonProperty("deferred_credential_endpoint")
    private String deferredCredentialEndpoint;

    @JsonProperty("notification_endpoint")
    private String notificationEndpoint;

    @JsonProperty("credential_configurations_supported")
    @NotNull
    @Size(min = 1, message = "At least one credential configuration has to be be provided")
    @Valid
    private Map<String, CredentialConfiguration> credentialConfigurationSupported;

    @JsonProperty("credential_request_encryption")
    @Schema(description = "Object containing information about whether the Credential Issuer supports encryption of the Credential Request on top of TLS.")
    @Nullable
    @Valid
    private IssuerCredentialRequestEncryption requestEncryption;

    @JsonProperty("credential_response_encryption")
    @Schema(description = "Object containing information about whether the Credential Issuer supports encryption of the Credential Response on top of TLS.")
    @Nullable
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