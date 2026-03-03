package ch.admin.bj.swiyu.issuer.common.exception;

import java.io.Serial;

public class ExpiredNonceException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    public ExpiredNonceException(String message) {
        super(message);
    }
}