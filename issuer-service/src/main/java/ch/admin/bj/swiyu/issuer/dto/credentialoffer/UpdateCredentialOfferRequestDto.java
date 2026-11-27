package ch.admin.bj.swiyu.issuer.dto.credentialoffer;

import ch.admin.bj.swiyu.issuer.common.date.CustomInstantDeserializer;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import tools.jackson.databind.annotation.JsonDeserialize;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Schema(name = "UpdateCredentialOfferRequestV2", description = "Update credential offer, mostly used in deferred flow.")
public class UpdateCredentialOfferRequestDto {

    @JsonProperty(value = "deferred_offer_ready", defaultValue = "true")
    @Schema(description = """
            Sets deferred offers to ready as part of the update.
            For the state to be ready credential subject data must have been provided at some point in the process.
            """)
    private boolean ready = true;

    @JsonProperty(value = "credential_subject_data")
    @Schema(
            additionalProperties = Schema.AdditionalPropertiesValue.TRUE,
            description = """
                        User data to be written in the verifiable credential.
                        Will replace previously provided user data.
                    """,
            example = """
                    {
                        "lastName": "Example",
                        "firstName": "Edward"
                    }
                    """)
    private Map<String, Object> credentialSubjectData;

    @JsonProperty(value = "credential_subject_data_jwt")
    @Schema(
            description = """
                        User data to be written in the verifiable credential as a JWT, for ensuring data integrity.
                        Will replace previously provided user data.
                        JWT must be signed by one of the keys in JWKS_ALLOWLIST.
                        NOTE: If both credential_subject_data AND credential_subject_data_jwt are set, credential_subject_data_jwt will be used
                    """,
            example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsYXN0TmFtZSI6IkV4YW1wbGUiLCJmaXJzdE5hbWUiOiJFZHdhcmQiLCJkYXRlT2ZCaXJ0aCI6IjEuMS4xOTcwIn0.2VMjj1RpJ7jUjn1SJHDwwzqx3kygn88UxSsG5j1uXG8"
    )
    private String credentialSubjectDataJwt;


    /**
     * <a href="https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp">XMLSchema
     * dateTimeStamp</a>
     * eg. 2010-01-01T19:23:24.132Z
     **/
    @JsonDeserialize(using = CustomInstantDeserializer.class)
    @JsonProperty(value = "credential_valid_until")
    @Schema(description = "Setting for until when the VC shall be valid. XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp", example = "2010-01-01T19:23:24Z")
    @Nullable
    private Instant credentialValidUntil;

    /**
     * <a href="https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp">XMLSchema
     * dateTimeStamp</a>
     * eg. 2010-01-01T19:23:24.123Z
     **/
    @JsonDeserialize(using = CustomInstantDeserializer.class)
    @JsonProperty(value = "credential_valid_from")
    @Schema(description = "Setting for from when the VC shall be valid. XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp", example = "2010-01-01T18:23:24Z")
    @Nullable
    private Instant credentialValidFrom;


}
