/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.api.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "OpenIdConfiguration")
@Builder(toBuilder = true)
public record OpenIdConfigurationDto(String issuer, String token_endpoint,
                                     @Nullable List<String> dpop_signing_alg_values_supported) {

}
