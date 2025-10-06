package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MetadataImage {
    @NotNull
    @JsonProperty(value = "uri")
    @Schema(description = """
            tring value that contains a URI where the Wallet can obtain the logo of the Credential Issuer.
            The Wallet needs to determine the scheme, since the URI value could use the https: scheme, the data: scheme, etc.""")
    private String uri;
}
