/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.api.credentialoffer;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(name = "CredentialOffer", example = "credential_offer = {" +
        "\"credential_issuer\": external_url, " +
        "\"credential_configuration_ids\": metadata_credential_supported_ids, " +
        "\"grants\": {\"urn:ietf:params:oauth:grant-type:pre-authorized_code\": " +
        "{\"pre-authorized_code\": pre_auth_code, \"user_pin_required\": pin_required}}, " +
        "\"version\": \"1.0\"}")
public class CredentialOfferDto {

    @JsonProperty("credential_issuer")
    private String credentialIssuer;

    @JsonProperty("credential_configuration_ids")
    private List<String> credentials;

    private Map<String, Object> grants;

    private String version;
}
