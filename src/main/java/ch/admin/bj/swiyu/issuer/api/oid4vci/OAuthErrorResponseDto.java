/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.api.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

/**
 * <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.2">OAUTH RFC</a>
 */
@Schema(name = "OAuthErrorResponse")
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OAuthErrorResponseDto(@JsonProperty("error") @NotNull OAuthErrorDto error,
                                    @JsonProperty("error_description") String error_description) {
}
