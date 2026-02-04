/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object for the Oauth Access Token Request
 * JsonProperty is not working with the necessary media type application/x-www-form-urlencoded but are kept for documentation
 *
 * @param grant_type
 * @param preauthorized_code
 */
@Schema(name = "OauthAccessTokenRequest")
public record OAuthAccessTokenRequestDto(
        @NotBlank
        @JsonProperty("grant_type")
        @Schema(description = "The type of grant being requested. Must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code' or 'refresh_token.", defaultValue = "urn:ietf:params:oauth:grant-type:pre-authorized_code")
        String grant_type,

        @Nullable
        @JsonProperty("pre-authorized_code")
        String preauthorized_code,

        @Nullable
        @JsonProperty("refresh_token")
        String refresh_token


) {
}