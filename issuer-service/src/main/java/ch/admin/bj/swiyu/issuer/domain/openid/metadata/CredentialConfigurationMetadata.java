package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import lombok.Data;

import java.util.List;

@Schema(description = """
        Object containing information relevant to the usage and display of issued Credentials.
        Credential Format-specific mechanisms can overwrite the information in this object to convey
        Credential metadata. Format-specific mechanisms, such as SD-JWT VC display metadata are always
        preferred by the Wallet over the information in this object, which serves as the default fallback.
        """)
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialConfigurationMetadata {
    @Nullable
    @JsonProperty("display")
    private List<MetadataCredentialDisplayInfo> display;

    @Nullable
    @JsonProperty("claims")
    private List<MetadataClaimDescriptor> claimDescriptor;
}
