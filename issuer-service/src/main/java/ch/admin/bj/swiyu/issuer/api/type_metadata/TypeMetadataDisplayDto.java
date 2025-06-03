/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.api.type_metadata;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;

/**
 * specs can be found here: <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html#name-display-metadata">...</a>
 */
@Schema(name = "TypeMetadataDisplay")
public record TypeMetadataDisplayDto(
        // A language tag as defined in RFC5646
        @NotEmpty String lang,
        // Name for the type for end users.
        @NotEmpty String name,
        @Valid
        TypeMetadataDisplayRenderingDto rendering
) {
}