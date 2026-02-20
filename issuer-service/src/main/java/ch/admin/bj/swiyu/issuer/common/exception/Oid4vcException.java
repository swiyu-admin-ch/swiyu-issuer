package ch.admin.bj.swiyu.issuer.common.exception;

import lombok.Getter;

import java.util.Map;

@Getter
public class Oid4vcException extends RuntimeException {

    private final CredentialRequestError error;
    private final transient Map<String, Object> context;

    public Oid4vcException(CredentialRequestError error, String message) {
        super(message);
        this.error = error;
        this.context = Map.of();
    }

    public Oid4vcException(CredentialRequestError error, String message, Map<String, Object> context) {
        super(message);
        this.error = error;
        this.context = context == null || context.isEmpty() ? Map.of() : Map.copyOf(context);
    }

    public Oid4vcException(Throwable cause, CredentialRequestError error, String message) {
        super(message, cause);
        this.error = error;
        this.context = Map.of();
    }

    public Oid4vcException(Throwable cause, CredentialRequestError error, String message, Map<String, Object> context) {
        super(message, cause);
        this.error = error;
        this.context = context == null || context.isEmpty() ? Map.of() : Map.copyOf(context);
    }

}
