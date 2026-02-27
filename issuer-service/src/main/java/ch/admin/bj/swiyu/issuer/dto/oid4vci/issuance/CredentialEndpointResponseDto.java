package ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "CredentialEndpointResponse")
public record CredentialEndpointResponseDto(

        // OPTIONAL. Contains an array of one or more issued Credentials. MUST NOT be used if the transaction_id parameter is present.
        @JsonProperty("credentials")
        List<CredentialObjectDto> credentials,

        // OPTIONAL. String identifying a Deferred Issuance transaction
        @JsonProperty("transaction_id")
        String transactionId,

        //  REQUIRED if transaction_id is present. Contains a positive number that represents the minimum amount of time in seconds that the Wallet
        @JsonProperty("interval")
        Long interval
) {
}