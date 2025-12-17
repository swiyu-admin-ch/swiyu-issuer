package ch.admin.bj.swiyu.issuer.migration.testdata;

import java.util.UUID;

public record CredentialOfferData(
        UUID id,
        String offerStatus,
        UUID accessToken,
        UUID refreshToken,
        String dpopKey,
        Long tokenExpirationTimestamp
) {
}