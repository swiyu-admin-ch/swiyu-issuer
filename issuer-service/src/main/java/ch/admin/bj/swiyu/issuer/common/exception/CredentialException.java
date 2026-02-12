package ch.admin.bj.swiyu.issuer.common.exception;

/**
 * Errors being used when something structural or in context of the credential to be issued is wrong.
 */
public class CredentialException extends RuntimeException {
    public CredentialException(String message) {
        super(message);
    }

    public CredentialException(Throwable cause) {
        super(cause);
    }

    public CredentialException(String message, Throwable cause) {
        super(message, cause);
    }
}
