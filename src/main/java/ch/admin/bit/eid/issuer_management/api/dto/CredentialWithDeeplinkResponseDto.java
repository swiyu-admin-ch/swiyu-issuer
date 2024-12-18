package ch.admin.bit.eid.issuer_management.api.dto;

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
@Schema(name = "CredentialWithDeeplinkResponse")
public class CredentialWithDeeplinkResponseDto {

    @JsonProperty(value = "management_id")
    private UUID managementId;

    @JsonProperty(value = "offer_deeplink")
    private String offerDeeplink;
}
