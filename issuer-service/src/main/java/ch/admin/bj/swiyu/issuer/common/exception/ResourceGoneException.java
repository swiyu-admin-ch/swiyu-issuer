package ch.admin.bj.swiyu.issuer.common.exception;

/**
 * Thrown when a resource existed but is no longer available, for example because it reached a terminal state.
 *
 * <p>Mapped to HTTP {@code 410 GONE} by the application's exception handler, so clients can distinguish a
 * resource that is permanently gone from one that never existed ({@code 404 NOT FOUND}).</p>
 */
public class ResourceGoneException extends RuntimeException {

    /**
     * Creates a new exception with the given detail message.
     *
     * @param message the detail message
     */
    public ResourceGoneException(String message) {
        super(message);
    }
}
