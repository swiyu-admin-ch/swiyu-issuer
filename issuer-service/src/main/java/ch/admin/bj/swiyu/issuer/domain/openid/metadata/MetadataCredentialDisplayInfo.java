package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;

public class MetadataCredentialDisplayInfo extends MetadataDisplayInfo {
    @Nullable
    @JsonProperty(value = "logo")
    @Schema(description = "Object with information about the logo of the Credential.")
    private MetadataLogo logo;

    @Nullable
    @JsonProperty(value = "description")
    private String description;

    @Nullable
    @JsonProperty(value = "background_color")
    @Schema(description = """
            String value of a background color of the Credential represented as numerical color values defined
            in CSS Color Module Level 3""")
    private String backgroundColor;

    @Nullable
    @JsonProperty(value = "background_image")
    @Schema(description = """
            Object with information about the background image of the Credential. At least the following parameter
            """)
    private MetadataImage backgroundImage;

    @Nullable
    @JsonProperty(value = "text_color")
    private String textColor;
}
