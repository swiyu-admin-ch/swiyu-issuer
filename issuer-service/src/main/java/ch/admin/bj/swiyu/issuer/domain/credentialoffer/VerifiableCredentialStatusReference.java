package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import java.util.Map;

public interface VerifiableCredentialStatusReference {
    /**
     * Create a hashmap as to be used in the claims of a verifiable credential
     */
    Map<String, Object> createVCRepresentation();

    String getIdentifier();
}
