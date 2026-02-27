package ch.admin.bj.swiyu.issuer.common.exception;

public class InvalidNonceException extends RuntimeException {

    public InvalidNonceException(String message) {
        super(message);
    }
}