package ch.admin.bj.swiyu.issuer.service.statusregistry;

public class StatusListFetchFailedException extends RuntimeException {
    public StatusListFetchFailedException(String message) {
        super(message);
    }
}
