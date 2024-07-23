package ch.admin.bit.eid.issuer_management.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialOffer {

    /*credential_offer = {
       "credential_issuer": external_url,
                "credential_configuration_ids": metadata_credential_supported_ids,
                "grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": pre_auth_code, "user_pin_required": pin_required}},
    }*/

    @JsonProperty("credential_issuer")
    private String credentialIssuer;
    @JsonProperty("credential_configuration_ids")
    private List<String> credentials;
    private Map<String, Object> grants;
}
