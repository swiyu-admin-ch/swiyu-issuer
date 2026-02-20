package ch.admin.bj.swiyu.issuer.dto.type_metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.List;

/**
 * see <a href="https://github.com/e-id-admin/open-source-community/blob/ceb40a4a03761e3c369a83042a3a67ced2af0635/tech-roadmap/rfcs/oca/spec.md#oca-bundle-as-json-file">...</a>
 */
public record OcaDto(

        @NotNull(message = "'profile_version' must be set")
        @JsonProperty("profile_version")
        @Pattern(regexp = "^swiss-profile-vc:1.0.0$", message = "Profile version must be 'swiss-profile-vc:1.0.0'")
        String profileVersion,

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