package ch.admin.bj.swiyu.issuer.service.renewal;

import ch.admin.bj.swiyu.issuer.dto.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.issuer.common.date.CustomInstantDeserializer;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.util.List;

public record RenewalResponseDto(
        /**
         * ID as in credential metadata
         **/
        @NotEmpty(message = "'metadata_credential_supported_id' cannot be empty")
        @JsonProperty(value = "metadata_credential_supported_id")
        @ArraySchema(arraySchema = @Schema(description = "ID linking the offer to the issuer metadata.", example = "[\"myIssuerMetadataCredentialSupportedId\"]"))
        List<String> metadataCredentialSupportedId,

        @NotNull(message = "'credential_subject_data' must be set")
        @JsonProperty(value = "credential_subject_data")
        @Schema(description = """
                    The user data to be written in the verifiable credential. Can be a json object or a JWT.
                    credentialSubjectData": {"lastName": "Example","firstName": "Edward"}
                    When using data integrity JWT the value are as claims inside the JWT.
                    "credentialSubjectData": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsYXN0TmFtZSI6IkV4YW1wbGUiLCJmaXJzdE5hbWUiOiJFZHdhcmQiLCJkYXRlT2ZCaXJ0aCI6IjEuMS4xOTcwIn0.2VMjj1RpJ7jUjn1SJHDwwzqx3kygn88UxSsG5j1uXG8"
                """, example = """
                {
                    "lastName": "Example",
                    "firstName": "Edward"
                }
                """)
        Object credentialSubjectData,

        @JsonProperty(value = "credential_metadata")
        @Valid
        @Schema(description = """
                Various metadata to be used for credential creation.
                """,
                example = """
                        {"vct#integrity": "sha256-0000000000000000000000000000000000000000000="
                        }""")
        CredentialOfferMetadataDto credentialMetadata,

        @JsonDeserialize(using = CustomInstantDeserializer.class)
        @JsonProperty(value = "credential_valid_until")
        @Schema(description = "Setting for until when the VC shall be valid. XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp", example = "2010-01-01T19:23:24Z")
        Instant credentialValidUntil,

        @JsonDeserialize(using = CustomInstantDeserializer.class)
        @JsonProperty(value = "credential_valid_from")
        @Schema(description = "Setting for from when the VC shall be valid. XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp", example = "2010-01-01T18:23:24Z")
        Instant credentialValidFrom,

        @JsonProperty(value = "status_lists")
        @ArraySchema(arraySchema = @Schema(description = "List of URIs of the status lists to be used with the credential. Status Lists must be initialized. Can provide multiple status lists to have multiple status sources.", example = "[\"https://example-status-registry-uri/api/v1/statuslist/05d2e09f-21dc-4699-878f-89a8a2222c67.jwt\"]"))
        List<String> statusLists,
        @Schema(description = "Optional Parameter to override configured parameters, such as the DID used or the HSM key used in singing the request object")
        @Valid
        @Nullable
        @JsonProperty("configuration_override")
        ConfigurationOverrideDto configurationOverride
) {
}