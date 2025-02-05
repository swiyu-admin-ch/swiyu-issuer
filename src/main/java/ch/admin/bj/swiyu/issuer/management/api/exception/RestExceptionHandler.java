/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.api.exception;

import ch.admin.bj.swiyu.issuer.management.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.management.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.management.common.exception.CreateStatusListException;
import ch.admin.bj.swiyu.issuer.management.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.management.common.exception.UpdateStatusListException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import static org.springframework.http.HttpStatus.*;

@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
@Slf4j
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

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
        final ApiErrorDto apiError = new ApiErrorDto(INTERNAL_SERVER_ERROR, exception.getMessage());
        log.error("Status List Exception intercepted", exception);
        return new ResponseEntity<>(apiError, apiError.status());
    }

    @ExceptionHandler(ConfigurationException.class)
    public ResponseEntity<ApiErrorDto> handleConfigurationException(final Exception exception) {
        final ApiErrorDto apiError = new ApiErrorDto(INTERNAL_SERVER_ERROR, exception.getMessage());
        log.error("Configuration Exception intercepted", exception);
        return new ResponseEntity<>(apiError, apiError.status());
    }

    @ExceptionHandler
    public ResponseEntity<ApiErrorDto> handle(final Exception exception, final WebRequest request) {
        final ApiErrorDto apiError = new ApiErrorDto(INTERNAL_SERVER_ERROR, null);
        log.error("Unknown Exception occurred", exception);
        return new ResponseEntity<>(apiError, apiError.status());
    }
}
