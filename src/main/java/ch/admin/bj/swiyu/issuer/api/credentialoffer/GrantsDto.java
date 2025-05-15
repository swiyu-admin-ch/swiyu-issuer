package ch.admin.bj.swiyu.issuer.api.credentialoffer;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "Grants", description = """
        Grants to be used in the credential offer. Currently only pre-authorized code is supported.
        """)
public record GrantsDto(
        @JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code") PreAuthorizedCodeDto preAuthorizedCode) {
}