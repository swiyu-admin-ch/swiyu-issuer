package ch.admin.bj.swiyu.issuer.migration.domain;

import java.time.Instant;
import java.util.UUID;

public final class CredentialOfferTestFactory {

    public static CredentialOfferData offered() {
        return base("OFFERED", false, false);
    }

    public static CredentialOfferData cancelled() {
        return base("CANCELLED", false, false);
    }

    public static CredentialOfferData inProgress() {
        return base("IN_PROGRESS", false, false);
    }

    public static CredentialOfferData deferred() {
        return base("DEFERRED", true, true);
    }

    public static CredentialOfferData ready() {
        return base("READY", true, false);
    }

    public static CredentialOfferData issued() {
        return base("ISSUED", true, false);
    }

    public static CredentialOfferData suspended() {
        return base("SUSPENDED", true, false);
    }

    public static CredentialOfferData revoked() {
        return base("REVOKED", true, false);
    }

    public static CredentialOfferData expired() {
        return base("EXPIRED", false, false);
    }

    private static CredentialOfferData base(
            String status,
            boolean withDpop,
            boolean withRefreshToken
    ) {
        final UUID id = UUID.randomUUID();

        return new CredentialOfferData(
                id,
                status,
                UUID.randomUUID(),
                withRefreshToken ? UUID.randomUUID() : null,
                withDpop ? randomDpopJson(id) : null,
                randomTimestamp()
        );
    }

    private static Long randomTimestamp() {
        return Instant.now().plusSeconds(3600).getEpochSecond();
    }

    private static String randomDpopJson(UUID id) {
        return """
                {
                  "x": "%s",
                  "y": "%s",
                  "crv": "P-256",
                  "kty": "EC",
                  "use": "sig",
                  "kid": "holder-dpop-key-%s"
                }
                """.formatted(
                randomBase64Like(),
                randomBase64Like(),
                id
        );
    }

    private static String randomBase64Like() {
        return UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 32);
    }
}