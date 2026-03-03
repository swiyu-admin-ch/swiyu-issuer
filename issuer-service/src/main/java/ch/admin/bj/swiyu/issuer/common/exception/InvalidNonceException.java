package ch.admin.bj.swiyu.issuer.common.exception;

import java.io.Serial;

public class InvalidNonceException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    public InvalidNonceException(String message) {
        super(message);
    }
}