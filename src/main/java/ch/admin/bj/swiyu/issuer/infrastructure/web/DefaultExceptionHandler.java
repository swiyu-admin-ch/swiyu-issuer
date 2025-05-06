/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web;

import ch.admin.bj.swiyu.issuer.api.exception.ApiErrorDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestErrorResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthErrorResponseDto;
import ch.admin.bj.swiyu.issuer.common.exception.*;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.issuer.service.CredentialMapper.toCredentialRequestErrorResponseDto;
import static ch.admin.bj.swiyu.issuer.service.CredentialMapper.toOAuthErrorResponseDto;
import static org.springframework.http.HttpStatus.*;

@RestControllerAdvice
@Slf4j
public class DefaultExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(OAuthException.class)
    ResponseEntity<OAuthErrorResponseDto> handleOAuthException(final OAuthException exception) {
        var resp = toOAuthErrorResponseDto(exception);
        return new ResponseEntity<>(resp, resp.error().getHttpStatus());
    }

    @ExceptionHandler(Oid4vcException.class)
    ResponseEntity<CredentialRequestErrorResponseDto> handleOID4VCException(final Oid4vcException exception) {
        return new ResponseEntity<>(toCredentialRequestErrorResponseDto(exception), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    protected ResponseEntity<ApiErrorDto> handleResourceNotFoundException(
            final ResourceNotFoundException exception, final WebRequest request) {
        final ApiErrorDto apiError = new ApiErrorDto(NOT_FOUND, exception.getMessage());
        log.debug("Resource not found", exception);
        return new ResponseEntity<>(apiError, apiError.status());
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiErrorDto> handleBadRequestException(final Exception exception) {
        final ApiErrorDto apiError = new ApiErrorDto(BAD_REQUEST, exception.getMessage());
        log.debug("Bad Request intercepted", exception);
        return new ResponseEntity<>(apiError, apiError.status());
    }

    @ExceptionHandler({CreateStatusListException.class, UpdateStatusListException.class})
    public ResponseEntity<ApiErrorDto> handleCreateStatusListException(final Exception exception) {
        var exceptionMessage = exception.getMessage();
        if (exception.getCause() != null) {
            exceptionMessage += " - caused by - " + exception.getCause().getMessage();
        }
        final ApiErrorDto apiError = new ApiErrorDto(INTERNAL_SERVER_ERROR, exceptionMessage);
        log.error("Status List Exception intercepted", exception);
        return new ResponseEntity<>(apiError, apiError.status());
    }

    @ExceptionHandler(ConfigurationException.class)
    public ResponseEntity<ApiErrorDto> handleConfigurationException(final Exception exception) {
        final ApiErrorDto apiError = new ApiErrorDto(INTERNAL_SERVER_ERROR, exception.getMessage());
        log.error("Configuration Exception intercepted", exception);
        return new ResponseEntity<>(apiError, apiError.status());
    }

    @ExceptionHandler(io.fabric8.kubernetes.client.ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    void handleResourceNotFoundException(io.fabric8.kubernetes.client.ResourceNotFoundException e) {
        log.debug("Resource not found", e);
    }

    @ExceptionHandler
    public ResponseEntity<ApiErrorDto> handle(final Exception exception, final WebRequest request) {
        final ApiErrorDto apiError = new ApiErrorDto(INTERNAL_SERVER_ERROR, null);
        log.error("Unknown Exception occurred", exception);
        return new ResponseEntity<>(apiError, apiError.status());
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  @NonNull HttpHeaders headers,
                                                                  @NonNull HttpStatusCode status,
                                                                  @NonNull WebRequest request) {

        String errors = Stream.concat(
                        ex.getBindingResult().getFieldErrors()
                                .stream().map(error -> String.format("%s: %s", error.getField(), error.getDefaultMessage())),
                        ex.getBindingResult().getGlobalErrors().stream().map(error -> String.format("%s: %s", error.getObjectName(), error.getDefaultMessage()))
                ).sorted()
                .collect(Collectors.joining(", "));

        log.info("Received bad request. Details: {}", errors);

        return new ResponseEntity<>(new ApiErrorDto(HttpStatus.UNPROCESSABLE_ENTITY, errors), HttpStatus.UNPROCESSABLE_ENTITY);
    }
}