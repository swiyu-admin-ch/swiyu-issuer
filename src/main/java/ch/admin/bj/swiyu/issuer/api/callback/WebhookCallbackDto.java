package ch.admin.bj.swiyu.issuer.api.callback;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@Schema(name = "WebhookCallback", description = "Initial credential creation request to start the offering process.")
public class WebhookCallbackDto {

}
