/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.api.type_metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;

/**
 * specs can be found here: <a href="https://github.com/e-id-admin/open-source-community/blob/ceb40a4a03761e3c369a83042a3a67ced2af0635/tech-roadmap/rfcs/oca/spec.md#sd-jwt-vc">...</a>
 */
public record TypeMetadataDisplayRenderingOcaDto(
        @NotEmpty
        String uri,
        @JsonProperty("uri#integrity")
        String uriIntegrity
) {
}