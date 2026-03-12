package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.common.crypto.HashUtil;
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
 * <li>Timestamp of nonce creation</li>
 * <li>Signature created by hashing the 2 previous values and a secret value
 * only known to the
 * the authorization server</li>
 * </ol>
 * <br>
 * The purpose of the hash is to prevent third parties creating nonces which
 * would be regarded as valid.
 */
@Getter
public class SelfContainedNonce {
    /**
     * The number of individual parts of a self contained nonce concatenated by
     * double colons (::)
     */
    private static final int SELF_CONTAINED_NONCE_PARTS = 3;

    /**
     * Full Nonce String representation
     */
    private final String nonce;
    /**
     * Nonce without signature hash
     */
    private final String preNonce;
    private final UUID nonceId;
    private final Instant nonceInstant;
    private final String nonceSignature;

    /**
     * Creates a new self contained nonce with current timestamp and random uuid
     * The Object created in this manner can <em>NOT</em> be validated!
     * 
     * @param secret the authorization server's secret to be used in the hash.
     */
    public SelfContainedNonce(IssuerSecret secret) {
        nonceId = UUID.randomUUID();
        nonceInstant = Instant.now();
        preNonce = calculatePreNonce(nonceId, nonceInstant);
        nonceSignature = createSignature(preNonce, secret);
        nonce = preNonce + "::" + nonceSignature;
    }

    /**
     * Constructor for creating a nonce with validated structure<br>
     * Note: Neither signature nor validity has been validated for this nonce
     * 
     * @param nonce
     * @param nonceLifetimeSeconds
     */
    public SelfContainedNonce(String nonce) {
        this.nonce = nonce;
        String[] components = splitComponents(nonce);
        nonceId = parseNonceId(components);
        nonceInstant = parseNonceInstant(components);
        preNonce = calculatePreNonce(nonceId, nonceInstant);
        nonceSignature = components[2];
    }

    /**
     * Create a validated self contained nonce
     * 
     * @param nonce                string representation of the nonce
     * @param nonceLifetimeSeconds lifetime window the nonce is valid in
     * @param secret               secret that was used to create the nonce
     * @throws ExpiredNonceException
     * @throws InvalidNonceException
     */
    public SelfContainedNonce(String nonce, int nonceLifetimeSeconds, IssuerSecret secret)
            throws ExpiredNonceException, InvalidNonceException {
        this(nonce);
        validateNonce(this, nonceLifetimeSeconds, secret);
    }

    /**
     * Validates if the nonce has not yet expired and has a valid hash
     */
    public boolean isValid(int lifetimeSeconds, IssuerSecret secret) {
        return !hasExpired(this, lifetimeSeconds, secret) && !hasInvalidSignature(this, secret);
    }

    /**
     * Validates if the nonce has a valid format and is not yet expired
     */
    private static void validateNonce(SelfContainedNonce nonce, int nonceLifetimeSeconds, IssuerSecret secret) {
        if (hasExpired(nonce, nonceLifetimeSeconds, secret)) {
            throw new ExpiredNonceException("Invalid nonce. Nonce is expired.");
        }
        if (hasInvalidSignature(nonce, secret)) {
            throw new InvalidNonceException("Nonce signature is incorrect");
        }
    }

    /**
     * Validates if the nonce has not expired.
     *
     * It validates that the timestamp is within an acceptable range
     * based on the provided lifetime in seconds
     *
     * @param nonce           the nonce string to be validated
     * @param lifetimeSeconds the maximum number of seconds a nonce is considered
     *                        valid from its creation
     * @param secret          the secret used to create the nonce hash
     * @return true if the nonce is valid
     */
    private static boolean hasExpired(SelfContainedNonce nonce, int lifetimeSeconds, IssuerSecret secret) {
        var now = Instant.now();
        var oldestAcceptableInstant = now.minus(lifetimeSeconds, ChronoUnit.SECONDS);
        return !(oldestAcceptableInstant.isBefore(nonce.nonceInstant) && now.isAfter(nonce.nonceInstant));
    }

    /**
     * Validates the signature of the nonce by
     * matching the calculated signature hash with the one given in the nonce.
     * 
     * @param nonce  the nonce string to be validated
     * @param secret the secret used to create the nonce hash
     * @return
     */
    private static boolean hasInvalidSignature(SelfContainedNonce nonce, IssuerSecret secret) {
        var calculatedSignature = createSignature(nonce.preNonce, secret);
        return !(calculatedSignature.equals(nonce.nonceSignature));
    }

    private static UUID parseNonceId(String[] components) {
        try {
            return UUID.fromString(components[0]);
        } catch (IllegalArgumentException e) {
            throw new InvalidNonceException("Malformed nonce");
        }
    }

    private static Instant parseNonceInstant(String[] components) {
        try {
            return Instant.parse(components[1]);
        } catch (DateTimeParseException e) {
            throw new InvalidNonceException("Malformed Date");
        }
    }

    private static String[] splitComponents(String nonce) {
        if (nonce == null) {
            throw new InvalidNonceException("Nonce is null");
        }
        var components = nonce.split("::");
        if (components.length != SELF_CONTAINED_NONCE_PARTS) {
            throw new InvalidNonceException("Malformed nonce");
        }
        return components;
    }

    private static String calculatePreNonce(UUID nonceId, Instant nonceInstant) {
        return nonceId + "::" + nonceInstant;
    }

    /**
     * Creates a SHA-256 hash of a pre-nonce concatenated with a nonce secret ID.
     *
     * @param preNonce The pre-nonce used to create the hash.
     * @param secret   The NonceSecret containing the secret ID.
     * @return A SHA-256 hash as a hexadecimal string.
     */
    public static String createSignature(String preNonce, IssuerSecret secret) {
        return HashUtil.createHMAC(preNonce, secret.getAsKeyParameter());
    }
}