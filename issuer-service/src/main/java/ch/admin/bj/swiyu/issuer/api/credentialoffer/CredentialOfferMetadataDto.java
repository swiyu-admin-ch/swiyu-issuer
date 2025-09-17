package ch.admin.bj.swiyu.issuer.api.credentialoffer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialOfferMetadataDto(
        @JsonProperty("deferred")
        Boolean deferred,
        @JsonProperty("vct#integrity")
        String vctIntegrity,
        // TODO: vct_metadata_uri claim is optional, but shall be used to therein reference oca and schema information.
        @JsonProperty("vct_metadata_uri")
        String vctMetadataUri,
        // TODO: vct_metadata_uri#integrity claim is optional - the Integrity String is a Subresource Integrity (SRI)
        @JsonProperty("vct_metadata_uri#integrity")
        String vctMetadataUriIntegrity
) {
}