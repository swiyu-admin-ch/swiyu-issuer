package ch.admin.bj.swiyu.issuer.domain.credentialoffer;


import org.apache.commons.lang3.StringUtils;

public record ConfigurationOverride(
        String issuerDid,
        String verificationMethod,
        String keyId,
        String keyPin
) {

    public String issuerDidOrDefault(String defaultValue) {
        return StringUtils.getIfBlank(issuerDid, () -> defaultValue);
    }

    public String verificationMethodOrDefault(String defaultValue) {
        return StringUtils.getIfBlank(verificationMethod, () -> defaultValue);
    }
}
