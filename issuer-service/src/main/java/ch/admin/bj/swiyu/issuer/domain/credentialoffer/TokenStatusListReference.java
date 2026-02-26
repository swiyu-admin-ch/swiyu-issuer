package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import java.util.Map;

/**
 * Referenced Token
 * See <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#name-status-list-token-in-jwt-fo">spec</a>
 * Status List reference written into VC
 * Should be added as "status_list" to a status json object in the vc
 */
public record TokenStatusListReference(int idx, String uri) implements VerifiableCredentialStatusReference {
    @Override
    public Map<String, Object> createVCRepresentation() {
        return Map.of("status", Map.of("status_list", Map.of("idx", idx, "uri", uri)));
    }

    @Override
    public String getIdentifier() {
        return uri;
    }
}
