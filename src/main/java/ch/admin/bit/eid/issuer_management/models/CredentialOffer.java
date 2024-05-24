package ch.admin.bit.eid.issuer_management.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialOffer {

    /*credential_offer = {
       "credential_issuer": external_url,
                "credentials": metadata_credential_supported_ids,
                "grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": pre_auth_code, "user_pin_required": pin_required}},
    }*/

    private String credential_issuer;
    private String credentials;
    private Map<String, Object> grants;
}
