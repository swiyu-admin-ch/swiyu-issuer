package ch.admin.bj.swiyu.issuer.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatusCode;

import java.io.Serial;

@Getter
public class RenewalException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final HttpStatusCode httpStatus;

    public RenewalException(HttpStatusCode status, String message) {
        super(message);
        this.httpStatus = status;
    }

    public RenewalException(HttpStatusCode status, String message, Throwable cause) {
        super(message, cause);
        this.httpStatus = status;
    }
}