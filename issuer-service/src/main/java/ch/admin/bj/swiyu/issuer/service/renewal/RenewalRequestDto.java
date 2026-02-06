package ch.admin.bj.swiyu.issuer.service.renewal;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.UUID;

@Schema(name = "RenewalRequest", description = "Request sent to the Business Issuer to renew a credential offer")
public record RenewalRequestDto(
        @JsonProperty("management_id") UUID managementId, @JsonProperty("offer_id") UUID offerId, String dpopKey) {
}