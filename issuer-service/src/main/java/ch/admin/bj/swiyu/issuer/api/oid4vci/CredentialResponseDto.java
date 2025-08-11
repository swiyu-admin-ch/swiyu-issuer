package ch.admin.bj.swiyu.issuer.api.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "CredentialResponse")
public record CredentialResponseDto(
        String format,
        String credential,
        @JsonProperty("transaction_id")
        UUID transactionId
) {
}