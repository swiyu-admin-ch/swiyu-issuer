package ch.admin.bj.swiyu.issuer.common.exception;

/**
 * Exception indicating that an error was made during a status list create call
 */
public class CreateStatusListException extends RuntimeException {

    public CreateStatusListException(String message) {
        super(message);
    }

    public CreateStatusListException(String message, Throwable cause) {
        super(message, cause);
    }
}
