package ch.admin.bj.swiyu.issuer.api.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialResponseDto(
        String format,
        String credential,
        @JsonProperty("transaction_id")
        UUID transactionId
) {
}