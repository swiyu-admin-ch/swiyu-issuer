package ch.admin.bit.swiyu.issuer.management.api.dto;

import ch.admin.bit.swiyu.issuer.management.enums.CredentialStatusEnum;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Schema(name = "StatusResponse")
public class StatusResponseDto {

    private CredentialStatusEnum status;
}
