package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;
import lombok.Data;

import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Deprecated(since = "OID4VCI 1.0")
public class CredentialClaim {
    /**
     * Optional, if set to true the claim is mandatory in the presentation
     */
    private boolean mandatory;
    /**
     * Optional, if set should be one of:
     * <ul>
     * <li>string</li>
     * <li>number</li>
     * <li><a href="https://www.iana.org/assignments/media-types/media-types.xhtml#image">iana data type</a></li>
     * </ul>
     */
    @JsonProperty("value_type")
    private String valueType;

    @Nullable
    @JsonProperty("display")
    private List<MetadataDisplayInfo> display;

}
