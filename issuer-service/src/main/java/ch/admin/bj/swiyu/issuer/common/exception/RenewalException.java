package ch.admin.bj.swiyu.issuer.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.io.Serial;

@Getter
public class RenewalException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;

    public RenewalException(HttpStatus status, String message) {
        super(message);
        this.httpStatus = status;
    }
}