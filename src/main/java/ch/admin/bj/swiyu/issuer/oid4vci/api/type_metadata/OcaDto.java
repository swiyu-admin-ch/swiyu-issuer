/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.api.type_metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

/**
 * see <a href="https://github.com/e-id-admin/open-source-community/blob/ceb40a4a03761e3c369a83042a3a67ced2af0635/tech-roadmap/rfcs/oca/spec.md#oca-bundle-as-json-file">...</a>
 */
public record OcaDto(
        /* capture_bases Array containing one or more Capture Base objects.
         * There MUST only be one root Capture Base.
         */
        @NotEmpty
        @JsonProperty("capture_bases")
        List<Object> captureBases,

        /*
         * overlays Array containing one or more Overlay objects.
         */
        @NotEmpty
        @JsonProperty("overlays")
        List<Object> overlays
) {
}