package ch.admin.bj.swiyu.issuer.api.oid4vci;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

@Schema(name = "NonceResponse")
public record NonceResponseDto(
        @NotNull
        @JsonProperty("c_nonce")
        @Schema(description = "String containing an unpredictable challenge to be used when creating a proof of possession of the key.", type = "String")
        String nonce) {
}
