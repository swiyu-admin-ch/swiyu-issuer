package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Helper DTO providing the http content type alongside the credential
 */
@Getter
@AllArgsConstructor
@Schema(name = "CredentialEnvelope")
public class CredentialEnvelopeDto {

    /**
     * Media type for OID4VCI JWT-format credential responses (OID4VCI 1.0 ch. 10).
     * Defined here so writer ({@code CredentialBuilder}) and reader ({@code IssuanceController})
     * share a single source for the value, avoiding drift.
     */
    public static final String APPLICATION_JWT_VALUE = "application/jwt";

    private String contentType;
    private String oid4vciCredentialJson;
    private HttpStatus httpStatus;
}