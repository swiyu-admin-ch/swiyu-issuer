package ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance_v2;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

public record CredentialObjectDtoV2(
        @JsonProperty("credential")
        @Schema(description = """
                One sdjwt credential as string, if multiple credentials are issued each is wrapped in 
                a separate CredentialObjectDtoV2 object.
                """)
        String credential
) {
}