package ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus;

import ch.admin.bj.swiyu.issuer.management.enums.CredentialStatusType;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Schema(name = "UpdateStatusResponse")
public class UpdateStatusResponseDto {

    private UUID id;

    @JsonProperty("status")
    private CredentialStatusType credentialStatus;
}
