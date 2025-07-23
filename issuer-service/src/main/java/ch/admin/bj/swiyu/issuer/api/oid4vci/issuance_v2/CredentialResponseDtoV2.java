package ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialResponseDtoV2(

        // OPTIONAL. Contains an array of one or more issued Credentials. MUST NOT be used if the transaction_id parameter is present.
        List<@Valid CredentialObjectDtoV2> credentials,

        // OPTIONAL. String identifying a Deferred Issuance transaction
        @JsonProperty("transaction_id")
        String transactionId,

        //  REQUIRED if transaction_id is present. Contains a positive number that represents the minimum amount of time in seconds that the Wallet
        Long interval
) {
}