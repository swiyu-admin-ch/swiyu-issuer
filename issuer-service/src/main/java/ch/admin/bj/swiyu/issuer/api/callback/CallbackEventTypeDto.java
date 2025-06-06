package ch.admin.bj.swiyu.issuer.api.callback;

@Schema(name="CallbackEventType")
public enum CallbackEventTypeDto {
    VC_STATUS_CHANGED,
    ISSUANCE_ERROR
}