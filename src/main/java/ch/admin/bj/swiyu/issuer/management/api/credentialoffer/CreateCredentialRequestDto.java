/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.api.credentialoffer;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.LinkedList;
import java.util.List;

import static ch.admin.bj.swiyu.issuer.management.common.date.DateTimeUtils.ISO8601_FORMAT;

@Data
@Builder
@Schema(name = "CreateCredentialRequest", description = "Initial credential creation request to start the offering process.")
public class CreateCredentialRequestDto {

    /**
     * ID as in credential metadata
     **/
    @NotEmpty(message = "'metadata_credential_supported_id' cannot be empty")
    @JsonProperty(value = "metadata_credential_supported_id")
    @ArraySchema(arraySchema = @Schema(description = "ID linking the offer to the issuer metadata.", example = "[\"myIssuerMetadataCredentialSupportedId\"]"))
    private List<String> metadataCredentialSupportedId;

    /**
     * Data to be used in VC
     **/
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
    private Object credentialSubjectData;

    /**
     * Validitiy how long the offer should be usable.
     **/
    @JsonProperty(value = "offer_validity_seconds")
    @Schema(description = "how long the offer should be usable in seconds. Example is 1 Day.", example = "86400")
    private int offerValiditySeconds;

    /**
     * <a href="https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp">XMLSchema
     * dateTimeStamp</a>
     * eg. 2010-01-01T19:23:24Z
     **/
    @JsonFormat(pattern = ISO8601_FORMAT, timezone = "UTC")
    @JsonProperty(value = "credential_valid_until")
    @Schema(description = "Setting for until when the VC shall be valid. XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp", example = "2010-01-01T19:23:24Z")
    private Instant credentialValidUntil;

    /**
     * <a href="https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp">XMLSchema
     * dateTimeStamp</a>
     * eg. 2010-01-01T19:23:24Z
     **/
    @JsonFormat(pattern = ISO8601_FORMAT, timezone = "UTC")
    @JsonProperty(value = "credential_valid_from")
    @Schema(description = "Setting for from when the VC shall be valid. XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp", example = "2010-01-01T18:23:24Z")
    private Instant credentialValidFrom;

    /**
     * URIs of the status lists to be used with the credential
     */
    @JsonProperty(value = "status_lists")
    @ArraySchema(arraySchema = @Schema(description = "List of URIs of the status lists to be used with the credential. Status Lists must be initialized. Can provide multiple status lists to have multiple status sources.", example = "[\"https://example-status-registry-uri/api/v1/statuslist/05d2e09f-21dc-4699-878f-89a8a2222c67.jwt\"]"))
    private List<String> statusLists;

    public List<String> getStatusLists() {
        if (statusLists == null) {
            return new LinkedList<>();
        }
        return statusLists;
    }
}
