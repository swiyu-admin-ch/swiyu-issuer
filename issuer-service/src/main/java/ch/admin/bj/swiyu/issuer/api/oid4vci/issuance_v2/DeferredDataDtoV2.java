package ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import java.util.UUID;

public record DeferredDataDtoV2(
        /**
         * Mandatory String identifying a Deferred Issuance transaction. It MUST be present when the credential parameter is not returned.
         */
        @NotNull
        @JsonProperty("transaction_id")
        UUID transactionId,
        @NotNull
        @Positive
        Integer interval
) {
}