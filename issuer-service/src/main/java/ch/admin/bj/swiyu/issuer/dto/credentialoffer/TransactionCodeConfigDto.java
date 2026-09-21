package ch.admin.bj.swiyu.issuer.dto.credentialoffer;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration to enable and change behaviour of the transaction code
 */
@Data
@Builder
@AllArgsConstructor 
@NoArgsConstructor
@Schema(name = "CreateCredentialOfferRequest", description = "Initial credential creation request to start the offering process.")
public class TransactionCodeConfigDto {
    @JsonProperty("use_tx_code")
    @Schema(description = "Flag indicating if tx_code should be used. By default false.", defaultValue = "false")
    @Builder.Default
    private boolean useTransactionCode = false;

    @JsonProperty("description")
    @Schema(description = "String containing guidance for the Holder of the Wallet on how to obtain the Transaction Code.")
    private String description;

    @JsonProperty("length")
    @Schema(description = "Integer specifying the length of the Transaction Code.", defaultValue = "6")
    @Builder.Default
    private int length = 6;

    // input_mode is omitted as currently only numeric values are allowed
}
