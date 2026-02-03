package ch.admin.bj.swiyu.issuer.dto.common;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;

@Schema(name = "ConfigurationOverride", description = "Override for configuration to be use for the created entity")
public record ConfigurationOverrideDto(
        @Schema(description = "Override to be used in place of the ISSUER_ID")
        @Nullable
        @JsonProperty("issuer_did")
        String issuerDid,
        @Schema(description = "Override for the verification method that is looked up in the did document during verification of the entity. Most often the full did and a unique id after #")
        @Nullable
        @JsonProperty("verification_method")
        String verificationMethod,
        @Schema(description = "ID of the key in the HSM")
        @Nullable
        @JsonProperty("key_id")
        String keyId,
        @Schema(description = "The pin which protects the key in the hsm, if any. Note that this only the key pin, not hsm password or partition pin.")
        @Nullable
        @JsonProperty("key_pin")
        String keyPin
) {
}
