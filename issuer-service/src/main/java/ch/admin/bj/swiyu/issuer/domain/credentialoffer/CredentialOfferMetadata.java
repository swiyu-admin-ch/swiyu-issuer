package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialOfferMetadata(
        Boolean deferred,
        @JsonProperty("vct#integrity") // must be set in order to prevent breaking changes
        String vctIntegrity,
        @JsonProperty("vct_metadata_uri")
        String vctMetadataUri,
        @JsonProperty("vct_metadata_uri#integrity")
        String vctMetadataUriIntegrity
) {

        public String getVctIntegrityOrDefault(String defaultValue) {
                return StringUtils.getIfBlank(vctIntegrity, () -> defaultValue);
        }

        public String getVctMetadataUriOrDefault(String defaultValue) {
                return StringUtils.getIfBlank(vctMetadataUri, () -> defaultValue);
        }

        public String getVctMetadataUriIntegrityOrDefault(String defaultValue) {
                return StringUtils.getIfBlank(vctMetadataUriIntegrity, () -> defaultValue);
        }
}