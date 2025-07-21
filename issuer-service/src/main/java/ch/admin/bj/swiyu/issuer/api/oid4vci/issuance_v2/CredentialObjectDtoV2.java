package ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2;

import jakarta.validation.constraints.NotBlank;

public record CredentialObjectDtoV2(

        // REQUIRED. Contains one issued Credential
        @NotBlank
        String credential
) {
}