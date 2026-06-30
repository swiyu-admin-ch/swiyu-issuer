package ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "DeferredCredentialPendingResponse")
public record DeferredCredentialPendingResponseDto(

        @Schema(requiredMode = Schema.RequiredMode.REQUIRED, type = "string",
                description = "String identifying the Deferred Issuance transaction for subsequent polling.")
        @JsonProperty("transaction_id")
        String transactionId,

        @Schema(requiredMode = Schema.RequiredMode.REQUIRED,
                description = "Minimum number of seconds the Wallet MUST wait before polling again.")
        @JsonProperty("interval")
        Long interval
) {
}
