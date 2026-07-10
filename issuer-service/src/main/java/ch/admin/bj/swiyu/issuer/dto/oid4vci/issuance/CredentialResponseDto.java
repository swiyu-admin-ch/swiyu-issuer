package ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

/**
 * Successful (HTTP 200) response of the Credential or Deferred Credential Endpoint.
 * <p>
 * A response with code 200 only carries the issued
 * {@code credentials}. The {@code transaction_id} and {@code interval} fields belong exclusively to the
 * pending (HTTP 202) response and MUST NOT be present here. Single issuance is modeled as batch issuance
 * with {@code batch_size = 1}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "CredentialEndpointResponse")
public record CredentialResponseDto(

        // OPTIONAL. Contains an array of one or more issued Credentials. MUST NOT be used if the transaction_id parameter is present.
        @JsonProperty("credentials")
        List<CredentialObjectDto> credentials
) {
}