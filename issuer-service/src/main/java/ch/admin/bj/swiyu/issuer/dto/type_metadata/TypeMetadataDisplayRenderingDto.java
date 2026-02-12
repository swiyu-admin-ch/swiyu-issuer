package ch.admin.bj.swiyu.issuer.dto.type_metadata;

import jakarta.validation.Valid;

/**
 * Spec can be found here: <a href="https://github.com/e-id-admin/open-source-community/blob/ceb40a4a03761e3c369a83042a3a67ced2af0635/tech-roadmap/rfcs/oca/spec.md#sd-jwt-vc">...</a>
 */
public record TypeMetadataDisplayRenderingDto(
        @Valid
        TypeMetadataDisplayRenderingOcaDto oca
) {
}