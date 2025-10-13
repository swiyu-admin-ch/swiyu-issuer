package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;

/**
 * Display Object with localized name and logo including alt-text
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MetadataIssuerDisplayInfo extends MetadataDisplayInfo {
    @Nullable
    @JsonProperty(value = "logo")
    @Schema(description = "Object with information about the logo of the Credential Issuer.")
    private MetadataLogo logo;
}
