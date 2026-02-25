package ch.admin.bj.swiyu.issuer.dto.statuslist;

import ch.admin.bj.swiyu.issuer.dto.common.ConfigurationOverrideDto;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Schema(name = "StatusListUpdate", description = "Optional overrides for status list updates.")
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class StatusListUpdateDto {

    @Schema(description = "Optional Parameter to override configured parameters, such as the DID used or the HSM key used in signing the status list")
    @Valid
    @Nullable
    @JsonProperty("configuration_override")
    private ConfigurationOverrideDto configurationOverride;
}

