package ch.admin.bj.swiyu.issuer.api.credentialoffer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Size;
import org.springframework.lang.Nullable;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialOfferMetadataDto(
        @Nullable
        @JsonProperty("deferred")
        Boolean deferred,

        @Nullable
        @Size(min = 1, message = "If provided, vct#integrity must not be blank")
        @JsonProperty("vct#integrity")
        String vctIntegrity,
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