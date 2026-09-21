package ch.admin.bj.swiyu.issuer.dto.credentialoffer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Data Transfer Object for Transaction Code (tx_code) as specified by OID4VCI 1.0
*/
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TransactionCodeDto(
    @JsonProperty("input_mode")
    @Schema(description = "OPTIONAL String specifying the input character set. Possible values are numeric (only digits) and text (any characters)", defaultValue = "numeric")
    String inputMode,
    @JsonProperty("length")
    @Schema(description = "OPTIONAL. Integer specifying the length of the Transaction Code. This helps the Wallet to render the input screen and improve the user experience.")
    Integer length,
    @JsonProperty("description")
    @Schema(description = "OPTIONAL. String containing guidance for the Holder of the Wallet on how to obtain the Transaction Code, e.g., describing over which communication channel it is delivered.")
    String description
) {  
}
