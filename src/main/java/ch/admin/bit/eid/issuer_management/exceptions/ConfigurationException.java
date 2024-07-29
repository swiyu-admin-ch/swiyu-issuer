package ch.admin.bit.eid.issuer_management.exceptions;

/**
 * Exception indicating that an error was made during the configuration phase of the service
 */
public class ConfigurationException extends RuntimeException {

    public ConfigurationException(String message) {
        super(message);
    }
}
