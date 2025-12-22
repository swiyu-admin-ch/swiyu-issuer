package ch.admin.bj.swiyu.issuer.common.exception;

public class RenewalTooManyRequestsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public RenewalTooManyRequestsException(String message) {
        super(message);
    }
}