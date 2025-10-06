package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
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
    @JsonProperty(value = "path")
    @NotNull
    private String path;

    @JsonProperty(value = "mandatory", defaultValue = "false")
    private boolean mandatory;

    @JsonProperty(value = "display")
    @Nullable
    private List<MetadataDisplayInfo> display;
}
