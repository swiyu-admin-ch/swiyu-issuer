package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.dto.callback.CallbackErrorEventTypeDto;

public record ErrorEvent(
        String errorMessage,
        CallbackErrorEventTypeDto errorCode,
        java.util.UUID credentialOfferId
) {
}