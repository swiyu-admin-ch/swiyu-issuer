/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web.signer;

import ch.admin.bj.swiyu.issuer.api.exception.ApiErrorDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestErrorResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthErrorResponseDto;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import io.fabric8.kubernetes.client.ResourceNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
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

import static ch.admin.bj.swiyu.issuer.service.CredentialMapper.toCredentialRequestErrorResponseDto;
import static ch.admin.bj.swiyu.issuer.service.CredentialMapper.toOAuthErrorResponseDto;

@Slf4j
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
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
    @ResponseStatus(HttpStatus.NOT_FOUND)
    void handleResourceNotFoundException(ResourceNotFoundException e) {
        log.debug("Resource not found", e);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  @NonNull HttpHeaders headers,
                                                                  @NonNull HttpStatusCode status,
                                                                  @NonNull WebRequest request) {

        var errors = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> String.format("%s: %s", error.getField(), error.getDefaultMessage()))
                .sorted()
                .collect(Collectors.joining(", "));

        log.info("Received bad request. Details: {}", errors);

        return new ResponseEntity<>(new ApiErrorDto(HttpStatus.UNPROCESSABLE_ENTITY, errors), HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(Exception.class)
    void handleGeneralException(final Exception exception, final HttpServletRequest request) {
        log.error("Unkown exception for URL {}", request.getRequestURL(), exception);
    }

}
