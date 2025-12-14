package ch.admin.bj.swiyu.issuer.common.exception;

public class RenewalTooManyRequestsException extends RuntimeException {

    public RenewalTooManyRequestsException(String message) {
        super(message);
    }
}