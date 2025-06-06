package ch.admin.bj.swiyu.issuer.api.callback;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "CallbackErrorEventType")
public enum CallbackErrorEventTypeDto {
    OAUTH_TOKEN_EXPIRED,
    KEY_BINDING_ERROR
}
