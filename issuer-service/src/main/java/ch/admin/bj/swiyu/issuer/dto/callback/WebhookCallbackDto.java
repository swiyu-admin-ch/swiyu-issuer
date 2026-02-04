package ch.admin.bj.swiyu.issuer.dto.callback;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@Schema(name = "WebhookCallback", description = "Callback transmitting information about an event which occurred.")
public class WebhookCallbackDto {
    @JsonProperty(value = "subject_id")
    private UUID subjectId;
    @JsonProperty(value = "event_type")
    private CallbackEventTypeDto eventType;
    @JsonProperty(value = "event")
    private String event;
    @JsonProperty(value = "event_description")
    private String eventDescription;
    @JsonProperty(value = "event_trigger")
    private CallbackEventTriggerDto eventTrigger;
    @JsonProperty(value = "timestamp")
    private Instant timestamp;
}
