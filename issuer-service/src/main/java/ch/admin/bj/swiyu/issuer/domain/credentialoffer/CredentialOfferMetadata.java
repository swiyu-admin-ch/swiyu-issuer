package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import org.apache.commons.lang3.StringUtils;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialOfferMetadata(
        Boolean deferred,
        @JsonProperty("vct_metadata_uri")
        String vctMetadataUri,
        @JsonProperty("vct_metadata_uri#integrity")
        String vctMetadataUriIntegrity
) {

    public String getVctMetadataUriOrDefault(String defaultValue) {
        return StringUtils.getIfBlank(vctMetadataUri, () -> defaultValue);
    }

    public String getVctMetadataUriIntegrityOrDefault(String defaultValue) {
        return StringUtils.getIfBlank(vctMetadataUriIntegrity, () -> defaultValue);
    }
}