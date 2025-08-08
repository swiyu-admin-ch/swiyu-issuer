package ch.admin.bj.swiyu.issuer.domain.credentialoffer;


public record ConfigurationOverride(
        String issuerDid,
        String verificationMethod,
        String keyId,
        String keyPin
) {}
