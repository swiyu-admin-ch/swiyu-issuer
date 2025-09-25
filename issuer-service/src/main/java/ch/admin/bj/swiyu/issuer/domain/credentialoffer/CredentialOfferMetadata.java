package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

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
}