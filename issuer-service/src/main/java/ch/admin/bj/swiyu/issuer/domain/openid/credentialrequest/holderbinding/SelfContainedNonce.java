package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@AllArgsConstructor
@Getter
public class SelfContainedNonce {

    private String nonce;

    public SelfContainedNonce() {
        nonce = UUID.randomUUID() + "::" + Instant.now().toString();
    }

    /**
     * Checks if the self-contained nonce has the correct format
     *
     * @return True if the nonce consists out of 2 parts being split by double colon '::'
     */
    public boolean isSelfContainedNonce() {
        return nonce.contains("::") && nonce.split("::").length == 2;
    }

    /**
     * Validates if the nonce has not yet expired
     */
    public boolean isValid(int lifetimeSeconds) {
        var now = Instant.now();
        var oldestAcceptableInstant = now.minus(lifetimeSeconds, ChronoUnit.SECONDS);
        var nonceInstant = getNonceInstant();
        return oldestAcceptableInstant.isBefore(nonceInstant) && now.isAfter(nonceInstant);
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