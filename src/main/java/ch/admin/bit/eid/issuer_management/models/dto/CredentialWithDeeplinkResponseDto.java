package ch.admin.bit.eid.issuer_management.models.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CredentialWithDeeplinkResponseDto {
    private UUID management_id;

    private String offer_deeplink;
}
