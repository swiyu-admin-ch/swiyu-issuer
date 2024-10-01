package ch.admin.bit.eid.issuer_management.models.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.LinkedList;
import java.util.List;

import static ch.admin.bit.eid.issuer_management.util.DateTimeUtils.ISO8601_FORMAT;

@Data
@Builder
public class CreateCredentialRequestDto {

    /**
     * ID as in credential metadata
     **/
    @NotEmpty(message = "'metadata_credential_supported_id' cannot be empty")
    @JsonProperty(value = "metadata_credential_supported_id")
    private List<String> metadataCredentialSupportedId;

    /**
     * Data to be used in VC
     **/
    @NotNull(message = "'credential_subject_data' must be set")
    @JsonProperty(value = "credential_subject_data")
    private Object credentialSubjectData;

    /**
     * Validitiy how long the offer should be usable.
     **/
    @JsonProperty(value = "offer_validity_seconds")
    private int offerValiditySeconds = 60 * 60 * 24 * 30;  // 30 Days

    /**
     * XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp
     * eg. 2010-01-01T19:23:24Z
     **/
    @JsonFormat(pattern = ISO8601_FORMAT, timezone = "UTC")
    @JsonProperty(value = "credential_valid_until")
    private Instant credentialValidUntil;

    /**
     * XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp
     * eg. 2010-01-01T19:23:24Z
     **/
    @JsonFormat(pattern = ISO8601_FORMAT, timezone = "UTC")
    @JsonProperty(value = "credential_valid_from")
    private Instant credentialValidFrom;

    /**
     * URIs of the status lists to be used with the credential
     */
    @JsonProperty(value = "status_lists")
    private List<String> statusLists;

    public List<String> getStatusLists() {
        if (statusLists == null) {
            return new LinkedList<>();
        }
        return statusLists;
    }
}
