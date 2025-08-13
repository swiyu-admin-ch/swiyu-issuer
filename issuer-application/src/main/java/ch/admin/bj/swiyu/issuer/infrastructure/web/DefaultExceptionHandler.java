/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web;

import ch.admin.bj.swiyu.issuer.api.exception.ApiErrorDtoV2;
import ch.admin.bj.swiyu.issuer.common.exception.*;
import jakarta.validation.ConstraintViolationException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.issuer.service.CredentialMapper.oauthErrorToApiErrorDto;
import static ch.admin.bj.swiyu.issuer.service.CredentialMapper.toCredentialRequestErrorResponseDto;
import static org.springframework.http.HttpStatus.*;

@RestControllerAdvice
@Slf4j
@RequiredArgsConstructor
public class DefaultExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<ApiErrorDtoV2> handleOAuthException(final OAuthException exception) {
        ApiErrorDtoV2 apiError = oauthErrorToApiErrorDto(exception);
        log.debug("OAuthException: {}", exception.getMessage());
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ExceptionHandler(Oid4vcException.class)
    public ResponseEntity<ApiErrorDtoV2> handleOID4VCException(final Oid4vcException exception) {
        log.debug("Oid4vcException: {}", exception.getMessage());
        var apiError = toCredentialRequestErrorResponseDto(exception);

        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorDtoV2> handleResourceNotFoundException(final ResourceNotFoundException exception) {
        final ApiErrorDtoV2 apiErrorV2 = ApiErrorDtoV2.builder()
                .errorDescription(NOT_FOUND.getReasonPhrase())
                .errorDetails(exception.getMessage())
                .status(NOT_FOUND)
                .build();
        log.debug("Resource not found", exception);
        return new ResponseEntity<>(apiErrorV2, apiErrorV2.getStatus());
    }

    @ExceptionHandler({BadRequestException.class, CredentialException.class})
    public ResponseEntity<ApiErrorDtoV2> handleBadRequestException(final Exception exception) {
        final ApiErrorDtoV2 apiErrorV2 = ApiErrorDtoV2.builder()
                .errorDescription(BAD_REQUEST.getReasonPhrase())
                .errorDetails(exception.getMessage())
                .status(BAD_REQUEST)
                .build();
        log.debug("Bad Request intercepted", exception);
        return new ResponseEntity<>(apiErrorV2, apiErrorV2.getStatus());
    }

    @ExceptionHandler({CreateStatusListException.class, UpdateStatusListException.class})
    public ResponseEntity<ApiErrorDtoV2> handleStatusListException(final Exception exception) {
        var exceptionMessage = exception.getMessage();
        if (exception.getCause() != null) {
            exceptionMessage += " - caused by - " + exception.getCause().getMessage();
        }

        final ApiErrorDtoV2 apiErrorV2 = ApiErrorDtoV2.builder()
                .errorDescription(INTERNAL_SERVER_ERROR.getReasonPhrase())
                .errorDetails(exceptionMessage)
                .status(INTERNAL_SERVER_ERROR)
                .build();
        log.error("Status List Exception intercepted", exception);
        return new ResponseEntity<>(apiErrorV2, apiErrorV2.getStatus());
    }

    @ExceptionHandler(ConfigurationException.class)
    public ResponseEntity<ApiErrorDtoV2> handleConfigurationException(final Exception exception) {
        final ApiErrorDtoV2 apiErrorV2 = ApiErrorDtoV2.builder()
                .errorDescription(INTERNAL_SERVER_ERROR.getReasonPhrase())
                .errorDetails(exception.getMessage())
                .status(INTERNAL_SERVER_ERROR)
                .build();
        log.error("Configuration Exception intercepted", exception);
        return new ResponseEntity<>(apiErrorV2, apiErrorV2.getStatus());
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Object> handleConstraintViolationException(final Exception exception) {
        var errors = exception.getMessage();

        return handleUnprocessableEntity(errors);
    }

    @ExceptionHandler(io.fabric8.kubernetes.client.ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    void handleResourceNotFoundException(io.fabric8.kubernetes.client.ResourceNotFoundException e) {
        log.debug("Resource not found", e);
    }

    @ExceptionHandler
    public ResponseEntity<ApiErrorDtoV2> handle(final Exception exception) {
        final ApiErrorDtoV2 apiErrorV2 = ApiErrorDtoV2.builder()
                .errorDescription(INTERNAL_SERVER_ERROR.getReasonPhrase())
                .status(INTERNAL_SERVER_ERROR)
                .build();

        log.error("Unknown Exception occurred", exception);
        return new ResponseEntity<>(apiErrorV2, apiErrorV2.getStatus());
    }

    @NotNull
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

        return handleUnprocessableEntity(errors);
    }

    private ResponseEntity<Object> handleUnprocessableEntity(String errors) {
        log.info("Received bad request. Details: {}", errors);

        final ApiErrorDtoV2 apiErrorV2 = ApiErrorDtoV2.builder()
                .errorDescription(UNPROCESSABLE_ENTITY.getReasonPhrase())
                .errorDetails(errors)
                .status(UNPROCESSABLE_ENTITY)
                .build();

        return new ResponseEntity<>(apiErrorV2, HttpStatus.UNPROCESSABLE_ENTITY);
    }
}