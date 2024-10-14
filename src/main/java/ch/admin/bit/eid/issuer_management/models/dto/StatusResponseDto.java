package ch.admin.bit.eid.issuer_management.models.dto;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class StatusResponseDto {

    private CredentialStatusEnum status;
}
