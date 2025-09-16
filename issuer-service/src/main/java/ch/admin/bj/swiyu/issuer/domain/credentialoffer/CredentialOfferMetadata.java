package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

public record CredentialOfferMetadata(
        Boolean deferred,
        String vctIntegrity
) {
}