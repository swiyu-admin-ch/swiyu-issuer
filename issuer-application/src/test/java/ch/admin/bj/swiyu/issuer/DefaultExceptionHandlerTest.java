package ch.admin.bj.swiyu.issuer;

import ch.admin.bj.swiyu.issuer.api.exception.ApiErrorDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestErrorDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthErrorDto;
import ch.admin.bj.swiyu.issuer.common.exception.*;
import ch.admin.bj.swiyu.issuer.infrastructure.web.DefaultExceptionHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class DefaultExceptionHandlerTest {

    private DefaultExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new DefaultExceptionHandler();
    }

    @ParameterizedTest
    @EnumSource(OAuthErrorDto.class)
    void handleOAuthExceptions_shouldReturnCodeAndType(OAuthErrorDto errorEnum) {
        var errorMessage = "Oauth error message";
        OAuthError error = OAuthError.valueOf(errorEnum.name());
        OAuthException ex = new OAuthException(error, errorMessage);

        ResponseEntity<ApiErrorDto> response = handler.handleOAuthException(ex);
        var body = response.getBody();

        // Then
        assertEquals(errorEnum.getHttpStatus(), response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorEnum.toString(), body.getErrorCode());
        assertEquals(errorMessage, body.getErrorDescription());
    }

    @ParameterizedTest
    @EnumSource(CredentialRequestErrorDto.class)
    void handleOAuthExceptions_shouldReturnCodeAndType(CredentialRequestErrorDto errorEnum) {
        var errorMessage = "Oauth error message";
        CredentialRequestError error = CredentialRequestError.valueOf(errorEnum.name());
        Oid4vcException ex = new Oid4vcException(error, errorMessage);

        ResponseEntity<ApiErrorDto> response = handler.handleOID4VCException(ex);
        var body = response.getBody();

        // Then
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorEnum.toString(), body.getErrorCode());
        assertEquals(errorMessage, body.getErrorDescription());
    }

    @Test
    void handleResourceNotFoundException_shouldReturnNotFound() {
        var errorMessage = "Resource not found";
        var exception = new ResourceNotFoundException("Resource not found");
        ResponseEntity<ApiErrorDto> response = handler.handleResourceNotFoundException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorMessage, body.getErrorDetails());
    }

    @Test
    void handleBadRequestException_shouldReturnBadRequest() {
        var errorMessage = "Bad Request error message";
        var exception = new BadRequestException(errorMessage);
        ResponseEntity<ApiErrorDto> response = handler.handleBadRequestException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorMessage, body.getErrorDetails());
    }

    @Test
    void handleStatusListException_shouldReturnInternalServerError() {
        var errorMessage = "Create StatusList error message";
        var exception = new CreateStatusListException(errorMessage);
        ResponseEntity<ApiErrorDto> response = handler.handleStatusListException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorMessage, body.getErrorDetails());
    }

    @Test
    void handleStatusListExceptionWithCause_shouldReturnInternalServerError() {
        HttpClientErrorException statusListException = new HttpClientErrorException(HttpStatus.NOT_FOUND, "Not found");
        var errorMessage = "Create StatusList error message";
        var expectedErrorMessage = "Create StatusList error message - caused by - %s".formatted(statusListException.getMessage());
        var exception = new CreateStatusListException(errorMessage, statusListException);
        ResponseEntity<ApiErrorDto> response = handler.handleStatusListException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(body);
        assertEquals(expectedErrorMessage, body.getErrorDetails());
    }

    @Test
    void handleUpdateStatusListException_shouldReturnInternalServerError() {
        var errorMessage = "Update StatusList error message";
        var exception = new UpdateStatusListException(errorMessage);
        ResponseEntity<ApiErrorDto> response = handler.handleStatusListException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorMessage, body.getErrorDetails());
    }

    @Test
    void handleConfigurationException_shouldReturnInternalServerError() {
        var errorMessage = "Configuration error message";
        var exception = new ConfigurationException(errorMessage);
        ResponseEntity<ApiErrorDto> response = handler.handleConfigurationException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorMessage, body.getErrorDetails());
    }

    @Test
    void handleFabricConfigurationException_shouldReturnInternalServerError() {
        var errorMessage = "Configuration error message";
        var exception = new io.fabric8.kubernetes.client.ResourceNotFoundException(errorMessage);
        ResponseEntity<ApiErrorDto> response = handler.handleConfigurationException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorMessage, body.getErrorDetails());
    }

    @Test
    void handleDefaultException_shouldReturnInternalServerError() {
        var errorMessage = "Default error message";
        var exception = new Exception(errorMessage);
        ResponseEntity<ApiErrorDto> response = handler.handle(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(body);
    }
}