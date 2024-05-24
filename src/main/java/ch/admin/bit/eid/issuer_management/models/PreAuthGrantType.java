package ch.admin.bit.eid.issuer_management.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Builder
@Data
public class PreAuthGrantType {

    @JsonProperty("pre-authorized_code_expires_in")
    private int preAuthorizedCodeExpiresIn;

    @JsonProperty("pre-authorized_code")
    private UUID preAuthorizedCode;

    @JsonProperty("pre-authorized_code")
    private String userPin;
}
