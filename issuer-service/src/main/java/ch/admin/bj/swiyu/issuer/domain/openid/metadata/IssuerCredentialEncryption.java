package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.util.List;

@SuperBuilder(toBuilder = true)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class IssuerCredentialEncryption {
    @JsonProperty("enc_values_supported")
    @Schema(description = "List of supported JWE encryption algorithms")
    @NotEmpty
    @Builder.Default
    protected List<@Pattern(regexp = "^A128GCM$") String> encValuesSupported = List.of("A128GCM");
    @JsonProperty("zip_values_supported")
    @Schema(description = "If present must be a non-empty array of JWE compression algorithms")
    @Nullable
    @Builder.Default
    private List<String> zipValuesSupported = List.of("DEF");
    @JsonProperty("encryption_required")
    @Schema(description = "Boolean value specifying whether the Credential Issuer requires the additional encryption on top of TLS")
    @NotNull
    private boolean encRequired;
}
