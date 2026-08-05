package ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "DeferredCredentialPendingResponse")
public record DeferredCredentialResponseDto(

        /**
         * Mandatory String identifying a Deferred Issuance transaction. It MUST be present when the credential parameter is not returned.
         */
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED, type = "string",
                description = "String identifying the Deferred Issuance transaction for subsequent polling.")
        @JsonProperty("transaction_id")
        @NotNull
        String transactionId,

        @Schema(requiredMode = Schema.RequiredMode.REQUIRED,
                description = "Minimum number of seconds the Wallet MUST wait before polling again.")
        @JsonProperty("interval")
        @NotNull
        @Positive
        Long interval
) {
}
