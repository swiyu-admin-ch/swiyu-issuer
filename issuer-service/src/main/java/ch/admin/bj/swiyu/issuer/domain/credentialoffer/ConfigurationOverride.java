package ch.admin.bj.swiyu.issuer.domain.credentialoffer;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.apache.commons.lang3.StringUtils;

// JSON-PERSISTED (ZDD): serialized to JSON in the "credential_offer" and "status_list" tables
// (see CredentialOffer.configurationOverride and StatusList.configurationOverride).
// Keep this type backward compatible across releases: don't rename/remove fields without a migration
// path (e.g. @JsonAlias), and keep any new field optional with a default.
@JsonIgnoreProperties(ignoreUnknown = true)
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
