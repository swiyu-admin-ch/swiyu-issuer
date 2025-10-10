package ch.admin.bj.swiyu.issuer;

import ch.admin.bj.swiyu.core.status.registry.client.model.ApiError;
import ch.admin.bj.swiyu.issuer.api.exception.ApiErrorDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestErrorDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthErrorDto;
import ch.admin.bj.swiyu.issuer.common.exception.*;
import ch.admin.bj.swiyu.issuer.infrastructure.web.DefaultExceptionHandler;
import jakarta.validation.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(OutputCaptureExtension.class)
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
    void handleStatusListException_shouldReturnInternalServerError(CapturedOutput output) {
        var errorMessage = "Create StatusList error message";
        var exception = new CreateStatusListException(errorMessage);
        ResponseEntity<ApiErrorDto> response = handler.handleStatusListException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorMessage, body.getErrorDetails());

        // test if error is logged
        assertThat(output.getAll()).contains(errorMessage);
    }

    @Test
    void handleStatusListExceptionWithCause_shouldReturnInternalServerError(CapturedOutput output) {
        HttpClientErrorException statusListException = new HttpClientErrorException(HttpStatus.NOT_FOUND, "Not found");
        var errorMessage = "Create StatusList error message";
        var expectedErrorMessage = "Create StatusList error message - caused by - %s".formatted(statusListException.getMessage());
        var exception = new CreateStatusListException(errorMessage, statusListException);
        ResponseEntity<ApiErrorDto> response = handler.handleStatusListException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(body);
      
        // test if error is logged
        assertThat(output.getAll()).contains("Status List Exception intercepted");
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
    void handleConfigurationException_shouldReturnInternalServerError(CapturedOutput output) {
        var errorMessage = "Configuration error message";
        var exception = new ConfigurationException(errorMessage);
        ResponseEntity<ApiErrorDto> response = handler.handleConfigurationException(exception);
        var body = response.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorMessage, body.getErrorDetails());

        // test if error is logged
        assertThat(output.getAll()).contains("Configuration Exception intercepted");
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

    @Test
    void handleCredentialException_shouldReturnBadRequest() {
        final String errorMessage = "Credential error message";
        final CredentialException exception = new CredentialException(errorMessage);
        final ResponseEntity<ApiErrorDto> response = handler.handleBadRequestException(exception);
        final ApiErrorDto body = response.getBody();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(body);
        assertEquals(errorMessage, body.getErrorDetails());
    }

    @Test
    void handleConstraintViolationException_shouldReturnUnprocessableEntity() {
        final ConstraintViolationException exception = new ConstraintViolationException("invalid field value", Set.of());
        final ResponseEntity<Object> response = handler.handleConstraintViolationException(exception);

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertThat(response.getBody()).isInstanceOf(ApiErrorDto.class);

        final ApiErrorDto body = (ApiErrorDto) response.getBody();
        assertEquals("Unprocessable Entity", body.getErrorDescription());
        assertEquals("invalid field value", body.getErrorDetails());
    }
}