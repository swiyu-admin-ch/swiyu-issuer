package ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record CredentialObjectDtoV2(

        @NotBlank
        @Schema(description = """
                One sdjwt credential as string, if multiple credentials are issued each is wrapped in 
                a separate CredentialObjectDtoV2 object.
                """)
        String credential
) {
}