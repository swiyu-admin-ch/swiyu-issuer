package ch.admin.bit.eid.issuer_management.exceptions;

public class NotImplementedError extends RuntimeException {

    private static final String ERR_MESSAGE = "Not implemented";

    public NotImplementedError() {
        super(ERR_MESSAGE);
    }
}
