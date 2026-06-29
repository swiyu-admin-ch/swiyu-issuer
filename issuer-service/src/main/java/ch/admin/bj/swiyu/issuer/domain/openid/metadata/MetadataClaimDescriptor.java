package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Schema(description = """
        A claims description object as used in the Credential Issuer metadata is an object used to describe
        how a certain claim in the Credential is displayed to the End-User.
        """)
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MetadataClaimDescriptor {
    /**
     * A non-empty array representing a claims path pointer
     */
    @NotEmpty
    @JsonProperty(value = "path")
    @ValidPathElements
    private List<Object> path;

    /**
     * Optional boolean when true the issuer will always check in the offer create validation and then will be part of the issued credential
     */
    @JsonProperty(value = "mandatory", defaultValue = "false")
    private boolean mandatory;

    /**
     * A non-empty, optional array of objects, defining display properties of a claim for a certain language
     */
    @Nullable
    @Size(min = 1)
    @JsonProperty(value = "display")
    private List<MetadataDisplayInfo> display;
}