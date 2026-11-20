package ch.admin.bj.swiyu.issuer.service.statusregistry;

public class StatusListFetchFailedException extends RuntimeException {
    public StatusListFetchFailedException(String message) {
        super(message);
    }

    public StatusListFetchFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
