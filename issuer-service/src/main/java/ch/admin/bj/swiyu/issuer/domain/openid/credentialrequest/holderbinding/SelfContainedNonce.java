package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.dpop.DpopHashUtil;
import ch.admin.bj.swiyu.issuer.common.exception.ExpiredNonceException;
import ch.admin.bj.swiyu.issuer.common.exception.InvalidNonceException;
import lombok.Getter;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Self Contained Nonce, consisting of 3 parts
 * <ol type="1">
 * <li>Random UUID</li>
 * <li>Timestamp of creation of nonce</li>
 * <li>Hash created from the 2 previous values and a secret value only known the
 * the authorization server</li>
 * </ol>
 * <br>
 * The purpose of the hash is to prevent third parties creating nonces which
 * would be regarded as valid.
 */
@Getter
public class SelfContainedNonce {
    /**
     * The number of individual parts of a self contained nonce concatenated by double colons (::)
     */
    private static final int SELF_CONTAINED_NONCE_PARTS = 3;
    private final String nonce;

    /**
     * Creates a new self contained nonce with current timestamp and random uuid
     * 
     * @param secret the authorization server's secret to be used in the hash.
     */
    public SelfContainedNonce(NonceSecret secret) {
        var preNonce = UUID.randomUUID() + "::" + Instant.now().toString();
        nonce = preNonce + "::" + createHash(preNonce, secret);
    }

    /**
     * Creates a nonce object without validation
     * @param nonce the nonce to be created
     */
    public SelfContainedNonce(String nonce) {
        this.nonce = nonce;
    }

    public SelfContainedNonce(String nonce, int nonceLifetimeSeconds, NonceSecret secret)
            throws ExpiredNonceException, InvalidNonceException {

        this.nonce = nonce;

        if (!isSelfContainedNonce(nonce)) {
            throw new InvalidNonceException(
                    "Invalid nonce. Nonce must consist of 3 parts being split by double colon '::'");
        }

        if (!isValid(nonce, nonceLifetimeSeconds, secret)) {
            throw new ExpiredNonceException("Invalid nonce. Nonce is expired or has invalid hash.");
        }
    }

    /**
     * Validates if the nonce has not yet expired and has a valid hash
     */
    public boolean isValid(int lifetimeSeconds, NonceSecret secret) {
        return isValid(nonce, lifetimeSeconds, secret);
    }

    /**
     * Checks if the self-contained nonce has the correct format
     *
     * @return True if the nonce consists out of 3 parts being split by double colon
     *         '::'
     */
    public static boolean isSelfContainedNonce(String nonce) {
        return nonce.contains("::") && nonce.split("::").length == 3;
    }


    /**
     * Validates if the nonce has the correct format and has not expired,
     * as well as has a valid hash.
     *
     * It validates that the timestamp is within an acceptable range
     * based on the provided lifetime in seconds, and checks if the received hash
     * matches the calculated hash with the given secret.
     *
     * @param nonce the nonce string to be validated
     * @param lifetimeSeconds the maximum number of seconds a nonce is considered valid from its creation
     * @param secret the secret used to create the nonce hash
     * @return true if the nonce is valid
     * @throws InvalidNonceException if the nonce is malformed or the timestamp is invalid
     */
    public static boolean isValid(String nonce, int lifetimeSeconds, NonceSecret secret) {
        var now = Instant.now();
        var oldestAcceptableInstant = now.minus(lifetimeSeconds, ChronoUnit.SECONDS);

        if (!isSelfContainedNonce(nonce)) {
            throw new InvalidNonceException("Malformed nonce");
        }
        try {
        var components = getComponents(nonce);
        var preNonce = components[0] + "::" + components[1];
        var nonceInstant = Instant.parse(components[1]);
        var calculatedHash = createHash(preNonce, secret);
        var receivedHash = components[2];
        return oldestAcceptableInstant.isBefore(nonceInstant) && now.isAfter(nonceInstant)
                && calculatedHash.equals(receivedHash);
        } catch(DateTimeParseException e) {
            throw new InvalidNonceException("Malformed Date");
        }
    }

    public UUID getNonceId() {
        return UUID.fromString(getComponents(nonce)[0]);
    }

    public Instant getNonceInstant() {
        return Instant.parse(getComponents(nonce)[1]);
    }

    private static String[] getComponents(String nonce) {
        var components = nonce.split("::");
        if (components.length != SELF_CONTAINED_NONCE_PARTS) {
            throw new IllegalArgumentException("Malformed nonce");
        }
        return components;
    }

    /**
     * Creates a SHA-256 hash of a pre-nonce concatenated with a nonce secret ID.
     *
     * @param preNonce The pre-nonce used to create the hash.
     * @param secret The NonceSecret containing the secret ID.
     * @return A SHA-256 hash as a hexadecimal string.
     */
    public static String createHash(String preNonce, NonceSecret secret) {
        return DpopHashUtil.sha256(secret.getId().toString() + "," + preNonce);
    }
}