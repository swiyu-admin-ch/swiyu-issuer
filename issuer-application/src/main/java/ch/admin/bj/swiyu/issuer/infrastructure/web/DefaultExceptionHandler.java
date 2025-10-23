/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web;

import ch.admin.bj.swiyu.issuer.api.exception.ApiErrorDto;
import ch.admin.bj.swiyu.issuer.api.exception.DpopErrorDto;
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
    public ResponseEntity<ApiErrorDto> handleOAuthException(final OAuthException exception) {
        ApiErrorDto apiError = oauthErrorToApiErrorDto(exception);
        log.debug("OAuthException: {}", exception.getMessage());
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ExceptionHandler(Oid4vcException.class)
    public ResponseEntity<ApiErrorDto> handleOID4VCException(final Oid4vcException exception) {
        log.debug("Oid4vcException: {}", exception.getMessage());
        var apiError = toCredentialRequestErrorResponseDto(exception);

        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorDto> handleResourceNotFoundException(final ResourceNotFoundException exception) {
        final ApiErrorDto apiErrorV2 = ApiErrorDto.builder()
                .errorDescription(NOT_FOUND.getReasonPhrase())
                .errorDetails(exception.getMessage())
                .status(NOT_FOUND)
                .build();
        log.debug("Resource not found", exception);
        return new ResponseEntity<>(apiErrorV2, apiErrorV2.getStatus());
    }

    @ExceptionHandler({BadRequestException.class, CredentialException.class})
    public ResponseEntity<ApiErrorDto> handleBadRequestException(final Exception exception) {
        final ApiErrorDto apiErrorV2 = ApiErrorDto.builder()
                .errorDescription(BAD_REQUEST.getReasonPhrase())
                .errorDetails(exception.getMessage())
                .status(BAD_REQUEST)
                .build();
        log.debug("Bad Request intercepted", exception);
        return new ResponseEntity<>(apiErrorV2, apiErrorV2.getStatus());
    }

    @ExceptionHandler({CreateStatusListException.class, UpdateStatusListException.class})
    public ResponseEntity<ApiErrorDto> handleStatusListException(final Exception exception) {
        var exceptionMessage = exception.getMessage();
        if (exception.getCause() != null) {
            exceptionMessage += " - caused by - " + exception.getCause().getMessage();
        }

        final ApiErrorDto apiErrorV2 = ApiErrorDto.builder()
                .errorDescription(INTERNAL_SERVER_ERROR.getReasonPhrase())
                .errorDetails(exceptionMessage)
                .status(INTERNAL_SERVER_ERROR)
                .build();
        log.error("Status List Exception intercepted", exception);
        return new ResponseEntity<>(apiErrorV2, apiErrorV2.getStatus());
    }

    @ExceptionHandler(ConfigurationException.class)
    public ResponseEntity<ApiErrorDto> handleConfigurationException(final Exception exception) {
        final ApiErrorDto apiErrorV2 = ApiErrorDto.builder()
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

    @ExceptionHandler
    public ResponseEntity<ApiErrorDto> handle(final Exception exception) {
        final ApiErrorDto apiErrorV2 = ApiErrorDto.builder()
                .errorDescription(INTERNAL_SERVER_ERROR.getReasonPhrase())
                .status(INTERNAL_SERVER_ERROR)
                .build();

        log.error("Unknown Exception occurred", exception);
        return new ResponseEntity<>(apiErrorV2, apiErrorV2.getStatus());
    }

    @ExceptionHandler
    public ResponseEntity<DpopErrorDto> handleDpopException(final DemonstratingProofOfPossessionException ex) {

        HttpStatus responseStatus = UNAUTHORIZED;
        if (DemonstratingProofOfPossessionError.USE_DPOP_NONCE.equals(ex.getDpopError())) {
            responseStatus = BAD_REQUEST;
        }
        return new ResponseEntity<>(DpopErrorDto.builder()
                .errorCode(ex.getDpopError().getName())
                .errorDescription(ex.getMessage())
                .build(), responseStatus);
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

    @ExceptionHandler(io.fabric8.kubernetes.client.ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    void handleResourceNotFoundException(io.fabric8.kubernetes.client.ResourceNotFoundException e) {
        log.debug("Resource not found", e);
    }

    private ResponseEntity<Object> handleUnprocessableEntity(String errors) {
        log.info("Received bad request. Details: {}", errors);

        final ApiErrorDto apiErrorV2 = ApiErrorDto.builder()
                .errorDescription(UNPROCESSABLE_ENTITY.getReasonPhrase())
                .errorDetails(errors)
                .status(UNPROCESSABLE_ENTITY)
                .build();

        return new ResponseEntity<>(apiErrorV2, HttpStatus.UNPROCESSABLE_ENTITY);
    }
}