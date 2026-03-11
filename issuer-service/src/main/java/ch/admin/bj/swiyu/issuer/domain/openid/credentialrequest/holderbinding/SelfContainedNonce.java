package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.common.exception.ExpiredNonceException;
import ch.admin.bj.swiyu.issuer.common.exception.InvalidNonceException;
import lombok.Getter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Getter
public class SelfContainedNonce {

    private final String nonce;
    private final int nonceLifetimeSeconds;

    public SelfContainedNonce(int nonceLifetimeSeconds) {
        this.nonceLifetimeSeconds = nonceLifetimeSeconds;
        this.nonce = UUID.randomUUID() + "::" + Instant.now().toString();
    }

    public SelfContainedNonce(String nonce, int nonceLifetimeSeconds) throws ExpiredNonceException, InvalidNonceException {

        this.nonceLifetimeSeconds = nonceLifetimeSeconds;
        this.nonce = nonce;

        validateNonce(this);
    }

    /**
     * Checks if the self-contained nonce has the correct format
     *
     * @return True if the nonce consists out of 2 parts being split by double colon '::'
     */
    public static boolean isSelfContainedNonce(String nonce) {
        return nonce != null && nonce.contains("::") && nonce.split("::").length == 2;
    }

    private static boolean isValid(String nonce, int lifetimeSeconds) {
        var now = Instant.now();
        var oldestAcceptableInstant = now.minus(lifetimeSeconds, ChronoUnit.SECONDS);

        var nonceInstant = Instant.parse(nonce.split("::")[1]);
        return oldestAcceptableInstant.isBefore(nonceInstant) && now.isAfter(nonceInstant);
    }

    /**
     * Validates if the nonce has a valid format and is not yet expired
     */
    public static void validateNonce(SelfContainedNonce nonce) {

        if (!isSelfContainedNonce(nonce.getNonce())) {
            throw new InvalidNonceException("Invalid nonce. Nonce must consist of 2 parts being split by double colon '::'");
        }

        if (!isValid(nonce.getNonce(), nonce.nonceLifetimeSeconds)) {
            throw new ExpiredNonceException("Invalid nonce. Nonce is expired.");
        }
    }

    public UUID getNonceId() {
        return UUID.fromString(getComponents()[0]);
    }

    public Instant getNonceInstant() {
        return Instant.parse(getComponents()[1]);
    }

    private String[] getComponents() {
        var components = nonce.split("::");
        if (components.length != 2) {
            throw new IllegalArgumentException("Malformed nonce");
        }
        return components;
    }
}