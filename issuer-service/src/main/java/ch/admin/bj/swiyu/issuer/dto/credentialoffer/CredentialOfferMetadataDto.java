package ch.admin.bj.swiyu.issuer.dto.credentialoffer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.Size;

@JsonIgnoreProperties(ignoreUnknown = true) // needed as there might be some metadata with vct#integrity left
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialOfferMetadataDto(
        @Nullable
        @JsonProperty("deferred")
        Boolean deferred,
        @Nullable
        @JsonProperty("vct_metadata_uri")
        @Size(min = 1, message = "If provided, vct_metadata_uri must not be blank")
        // optional claim vct_metadata_uri
        String vctMetadataUri,
        // optional claim - the Integrity String is a Subresource Integrity (SRI)
        @Nullable
        @JsonProperty("vct_metadata_uri#integrity")
        @Size(min = 1, message = "If provided, vct_metadata_uri#integrity must not be blank")
        String vctMetadataUriIntegrity
) {
}