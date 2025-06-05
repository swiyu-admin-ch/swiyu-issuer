package ch.admin.bj.swiyu.issuer.service.mapper;

import ch.admin.bj.swiyu.issuer.api.callback.WebhookCallbackDto;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import lombok.experimental.UtilityClass;

@UtilityClass
public class EventMapper {
    public static WebhookCallbackDto toWebhookCallbackDto(CallbackEvent event) {
        return WebhookCallbackDto.builder()
                .subjectId(event.getSubjectId())
                .eventType(event.getType())
                .timestamp(event.getTimestamp())
                .event(event.getEvent()).build();
    }
}
