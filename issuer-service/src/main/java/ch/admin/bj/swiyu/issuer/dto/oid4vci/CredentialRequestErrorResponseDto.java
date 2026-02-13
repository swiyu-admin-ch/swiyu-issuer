package ch.admin.bj.swiyu.issuer.dto.oid4vci;


import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

import java.io.Serial;
import java.io.Serializable;

@Schema(name = "CredentialRequestErrorResponse")
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialRequestErrorResponseDto(@JsonProperty("error") @NotNull CredentialRequestErrorDto error,
                                                @JsonProperty("error_description") String errorDescription) implements Serializable {
    @Serial
    private static final long serialVersionUID = 1905122041950251207L;

}
