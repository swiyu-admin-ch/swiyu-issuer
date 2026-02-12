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
    private String contentType;
    private String oid4vciCredentialJson;
    private HttpStatus httpStatus;
}