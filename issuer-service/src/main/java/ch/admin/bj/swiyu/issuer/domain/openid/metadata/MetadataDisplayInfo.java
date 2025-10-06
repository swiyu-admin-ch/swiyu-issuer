package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MetadataDisplayInfo {
    @Nullable
    @JsonProperty(value = "locale")
    @Schema(description = """
            String value that identifies the language of this object represented as a language tag taken
            from values defined in BCP47 [RFC5646]. There MUST be only one object for each language identifier.
            """, example = "de-CH")
    private String locale;
    @Nullable
    @JsonProperty(value = "name")
    private String name;
}
