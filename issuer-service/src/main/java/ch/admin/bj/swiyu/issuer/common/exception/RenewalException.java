package ch.admin.bj.swiyu.issuer.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class RenewalException extends RuntimeException{

    private final HttpStatus httpStatus;

    public RenewalException(HttpStatus status, String message) {
        super(message);
        this.httpStatus = status;
    }
}