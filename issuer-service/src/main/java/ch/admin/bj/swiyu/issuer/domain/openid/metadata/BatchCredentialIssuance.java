package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

/**
 * This record is used to specify the batch size for credential issuance in the metadata.
 * see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p">...</a>
 */
public record BatchCredentialIssuance(
        @JsonProperty("batch_size")
        @NotNull
        @Min(value = 10, message = "Batch size must be at least 10")
        Integer batchSize
) {
}