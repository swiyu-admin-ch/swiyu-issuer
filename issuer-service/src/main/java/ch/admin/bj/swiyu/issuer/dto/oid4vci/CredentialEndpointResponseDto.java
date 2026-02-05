package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.UUID;

@Deprecated(since = "OID4VCI")
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "CredentialEndpointResponse")
public record CredentialEndpointResponseDto(
        String format,
        String credential,
        @JsonProperty("transaction_id")
        UUID transactionId
) {
}