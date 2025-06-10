/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.api.oid4vci;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object for the Oauth Access Token Request
 * JsonProperty is not working with the necessary media type application/x-www-form-urlencoded but are kept for documentation
 *
 * @param grant_type
 * @param preauthorized_code
 */
@Schema(name = "OauthAccessTokenRequest")
public record OauthAccessTokenRequestDto(
        @NotBlank
        @JsonProperty("grant_type")
        @Schema(description = "The type of grant being requested. Must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code'.", defaultValue = "urn:ietf:params:oauth:grant-type:pre-authorized_code")
        String grant_type,

        @NotBlank
        @JsonProperty("pre-authorized_code")
        String preauthorized_code
) {
}