package ch.admin.bj.swiyu.issuer.common.exception;

public class ExpiredNonceException extends RuntimeException {

    public ExpiredNonceException(String message) {
        super(message);
    }
}