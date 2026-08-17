package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

// JSON-PERSISTED (ZDD): serialized to JSON in the "credential_offer" table (see CredentialOffer.clientAgentInfo).
// Keep this type backward compatible across releases: don't rename/remove fields without a migration
// path (e.g. @JsonAlias), and keep any new field optional with a default.
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientAgentInfo(
        String remoteAddr,
        String userAgent,
        String acceptLanguage,
        String acceptEncoding
) {
}