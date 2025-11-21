package ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialResponseEncryptionDto;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

/**
 * @param credentialConfigurationId
 * @param proofs
 * @param credentialResponseEncryption spec: <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request">...</a>
 */
@Schema(name = "CredentialEndpointRequestV2", description = "Request to the Credential Endpoint as defined in OID4VCI 1.0 specification")
public record CredentialEndpointRequestDtoV2(

        // credential_identifier has been omitted on purpose, Authorization Details of type openid_credential are not used by this implementation

        @NotBlank // This is only true, as we are not using credential_identifier
        @JsonProperty("credential_configuration_id")
        @Schema(description = """
                String that uniquely identifies one of the keys in the name/value pairs stored in
                the credential_configurations_supported Credential Issuer metadata.
                Only used if a credential_identifiers parameter was not returned from the Token Response as part of the authorization_details parameter.
                It MUST NOT be used otherwise.
                """, example = "university_example_sd_jwt")
        String credentialConfigurationId,

        @Valid
        @Schema(description = """
                Optional object providing 1+ proof of possessions of the cryptographic key material to
                which the issued Credential instances will be bound to
                """, example = """
                {
                   "jwt": [
                      "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJUZXN0LUtleSIsIngiOiJrdHFJRFpoUjFmY2NlM3VGanpxdDdLRVlEdVdweFJoX3pqdkszanZsS2k4IiwieSI6Ik1UV2ZObTJ6dy1CbklqM2szbW0xZVB3Q3hqTm9DSEowdXN6V25MeHVDemsiLCJpYXQiOjE3NTMyNjkyNzZ9fQ.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkNHZjaSIsIm5vbmNlIjoiY2U5YzEzNzgtODc2Yi00OGUyLTg0ZmUtOGE0ZjUwZGFkZmJmIiwiaWF0IjoxNzUzMjY5Mjc2fQ.ck-6Oq6IAav1VdFOkq9Qh7tzrl52jJvFBU3aPcZ_20oE73Cf4izN0ECmmiJm_qUMvYJlykQFsX2sW43gFC6vCw"
                   ]
                }
                """)
        ProofsDto proofs,

        @Schema(description = """
                Optional object providing information how to encrypt the Credential Response, if present.
                """, example = """
                {
                   "alg": "ECDH-ES",
                   "enc": "A128GCM",
                   "jwk": {"kty":"EC","crv":"P-256","kid":"transportEncKeyEC","x":"DTaouFJpyVkLvfhoOvuTDR6_nmTt7YTvEHsHzK0Ingk","y":"vOipfo61Sy64XpneRyR5g6NCGXLv_Q7f3-kEDMT-G9U"
                }
                """)
        @JsonProperty("credential_response_encryption")
        CredentialResponseEncryptionDto credentialResponseEncryption
) {

    @JsonIgnore
    public boolean hasProofs() {
        return proofs != null && proofs.jwt() != null && !proofs.jwt().isEmpty();
    }
}