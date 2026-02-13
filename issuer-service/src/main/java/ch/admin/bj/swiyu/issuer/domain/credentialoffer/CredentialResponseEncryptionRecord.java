package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import java.util.Map;

/**
 * information for encrypting the Credential Response.
 */
public record CredentialResponseEncryptionRecord(
        Map<String, Object> jwk,
        String alg,
        String enc
) {
}