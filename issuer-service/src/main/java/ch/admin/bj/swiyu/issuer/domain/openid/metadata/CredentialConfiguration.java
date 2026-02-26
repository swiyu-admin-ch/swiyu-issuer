package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@Validated
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialConfiguration {
    // TODO EIDOMNI-284: allow only dc+sd-jwt and start throwing errors for vc+sd-jwt (after issuers had some time to migrate)
    @NotNull
    @Pattern(regexp = "^[dv]c\\+sd-jwt$", message = "Only dc+sd-jwt format is supported")
    private String format;

    /**
     * SD-JWT specific field <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A.3.2">see specs</a>
     * Optional
     */
    @NotNull
    @Schema(description = """
            String designating the type of the Credential, as defined in sd-jwt-vc
            """)
    private String vct;

    @JsonProperty("vct_metadata_uri")
    @Schema(description = """
            Allowing for an indirection if using urn:vct resolver
            """)
    @Nullable
    private String vctMetadataUri;
    @JsonProperty("vct_metadata_uri#integrity")
    @Schema(description = """
            Allowing for validating content received from vct_metadata_uri as defined in W3C SRI (Subresource Integrity)
            """)
    @Nullable
    private String vctMetadataUriIntegrity;

    /**
     * SD-JWT specific field <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A.3.2">see specs</a>
     * Optional
     */
    @JsonProperty("claims")
    @Deprecated(since = "OID4VCI 1.0") // Replaced by credential_metadata.claims
    private Map<String, CredentialClaim> claims;

    /**
     * Field for VC not SD-JWT (VC Signed as JWT or JSON-LD)
     * Optional
     */
    @JsonProperty("credential_definition")
    @Null(message = "Credential definition is not allowed for the vc+sd-jwt format which is the only one supported")
    private CredentialDefinition credentialDefinition;

    /**
     * A non-empty array of case sensitive strings that identify the representation of the cryptographic key material that the issued Credential is bound to.
     * If missing, credential will be issued as unbound VC.
     */
    @JsonProperty("cryptographic_binding_methods_supported")
    @Schema(description = """
                 A non-empty array of case sensitive strings that identify the representation of the cryptographic key material that the issued Credential is bound.
                 If missing, credential will be issued as unbound VC.
            """)
    @Valid
    private List<@Pattern(regexp = "^(did:)?jwk$", message = "Only jwk and did:jwk are supported") String> cryptographicBindingMethodsSupported;

    /**
     * Case-sensitive strings that identify the algorithms that the Issuer uses to sign the issued Credential
     */
    @JsonProperty("credential_signing_alg_values_supported")
    @Valid
    private List<@Pattern(regexp = "^ES256$") String> credentialSigningAlgorithmsSupported;

    /**
     * Define what kind of proof the holder is allowed to provide for the credential
     */
    @JsonProperty("proof_types_supported")
    @Size(max = 1)
    @Valid
    private Map<@Pattern(regexp = "^jwt$", message = "Only jwt holder binding proofs are supported") String, SupportedProofType> proofTypesSupported;

    @Nullable
    @JsonProperty("display")
    @Deprecated(since = "OID4VCI 1.0")
    private List<MetadataCredentialDisplayInfo> display;

    @Nullable
    @JsonProperty("credential_metadata")
    private CredentialConfigurationMetadata credentialMetadata;


    @PostConstruct
    public void postConstruct() {
        if (!proofTypesSupported.isEmpty() && cryptographicBindingMethodsSupported.isEmpty()) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS,
                    "If proof types are supported, cryptographic binding methods must be specified as well",
                    Map.of(
                            "cryptographicBindingMethodsSupported", cryptographicBindingMethodsSupported
                    ));
        }
    }
}