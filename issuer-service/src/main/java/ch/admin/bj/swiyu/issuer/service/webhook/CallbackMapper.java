package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.dto.callback.CallbackEventTypeDto;
import ch.admin.bj.swiyu.issuer.dto.callback.WebhookCallbackDto;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventType;
import lombok.experimental.UtilityClass;

@UtilityClass
public class CallbackMapper {
    public static WebhookCallbackDto toWebhookCallbackDto(CallbackEvent event) {
        return WebhookCallbackDto.builder()
                .subjectId(event.getSubjectId())
                .eventType(toCallbackEventTypeDto(event.getType()))
                .timestamp(event.getTimestamp())
                .event(event.getEvent()).build();
    }

    public static CallbackEventTypeDto toCallbackEventTypeDto(CallbackEventType eventType) {
        return switch (eventType) {
            case VC_STATUS_CHANGED -> CallbackEventTypeDto.VC_STATUS_CHANGED;
            case VC_DEFERRED -> CallbackEventTypeDto.VC_DEFERRED;
            case ERROR -> CallbackEventTypeDto.ISSUANCE_ERROR;

        };
    }
}