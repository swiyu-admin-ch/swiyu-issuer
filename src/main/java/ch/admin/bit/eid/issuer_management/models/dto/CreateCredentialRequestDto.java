package ch.admin.bit.eid.issuer_management.models.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.Map;

import static ch.admin.bit.eid.issuer_management.util.DateTimeUtils.ISO8601_FORMAT;

@Data
@Builder
public class CreateCredentialRequestDto {

    /**
     ID as in credential metadata
     **/
    @NotBlank(message = "'metadata_credential_supported_id' cannot be empty")
    private String metadata_credential_supported_id;

    /**
     Data to be used in VC
     **/
    @NotNull(message = "'credential_subject_data' must be set")
    private Map<String, Object> credential_subject_data;

    /**
     Validitiy how long the offer should be usable.
     **/
    private int offer_validity_seconds = 60 * 60 * 24 * 30;  // 30 Days

    /**
     XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp
     eg. 2010-01-01T19:23:24Z
     **/
    @JsonFormat(pattern = ISO8601_FORMAT)
    private Instant credential_valid_until;

    /**
     XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp
     eg. 2010-01-01T19:23:24Z
     **/
    @JsonFormat(pattern = ISO8601_FORMAT)
    private Instant credential_valid_from;

}
