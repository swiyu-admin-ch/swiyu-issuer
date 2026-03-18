package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class SelfContainedNonceTest {
    private final IssuerSecret secret = IssuerSecret.builder()
            .id(UUID.randomUUID())
            .build();

    @Test
    void isValid_shouldReturnTrue_whenNonceIsValid() {
        var nonce = new SelfContainedNonce(secret);

        assertTrue(nonce.isValid(60, secret));
    }

    @Test
    void isValid_shouldReturnFalse_whenNonceIsExpired() {
        var nonce = new SelfContainedNonce(secret);

        var expiredInstant = Instant.now().minusSeconds(120);
        var preNonce = nonce.getNonceId() + "::" + expiredInstant;
        var signature = SelfContainedNonce.createSignature(preNonce, secret);

        var expiredNonce = new SelfContainedNonce(preNonce + "::" + signature);

        assertFalse(expiredNonce.isValid(60, secret));
    }

    @Test
    void isValid_shouldReturnFalse_whenSignatureIsInvalid() {
        var nonce = new SelfContainedNonce(secret);

        var invalidNonce = new SelfContainedNonce(
                nonce.getPreNonce() + "::invalid-signature"
        );

        assertFalse(invalidNonce.isValid(60, secret));
    }

    @Test
    void constructor_shouldThrowException_whenMalformedNonce() {
        assertThrows(RuntimeException.class, () ->
                new SelfContainedNonce("invalid-format")
        );
    }
}
