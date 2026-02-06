package ch.admin.bj.swiyu.issuer.dto.callback;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "CallbackEventType")
public enum CallbackEventTypeDto {
    VC_STATUS_CHANGED,
    VC_DEFERRED,
    ISSUANCE_ERROR
}