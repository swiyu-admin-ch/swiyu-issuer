package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

@Schema(name = "DeferredData")
public record DeferredDataDto(
        /**
         * Mandatory String identifying a Deferred Issuance transaction. It MUST be present when the credential parameter is not returned.
         */
        @NotNull
        @JsonProperty("transaction_id")
        UUID transactionId
) {
}