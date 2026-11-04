package ch.admin.bj.swiyu.issuer.dto.credentialoffer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

/**
 * Data Transfer Object for Pre-Authorized Code.
 *
 * @param preAuthCode The pre-authorized code as a UUID.
 * @param txCode Optional Transaction Code indicating if a transaction code will be required
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PreAuthorizedCodeGrantDto(
        @JsonProperty("pre-authorized_code") UUID preAuthCode,
        @JsonProperty("tx_code") TransactionCodeDto txCode) {
}