package ch.admin.bit.eid.issuer_management.exceptions;

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
    protected ResponseEntity<Object> handleResourceNotFoundException(
            final ResourceNotFoundException exception, final WebRequest request
    ) {
        final ApiError apiError = new ApiError(NOT_FOUND);
        apiError.setDetail(exception.getMessage());

        log.info("Resource not found", exception);

        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<Object> handleBadRequestException(final Exception exception, final WebRequest request) {
        final ApiError apiError = new ApiError(BAD_REQUEST);
        apiError.setDetail(exception.getMessage());
        log.info("Bad Request intercepted", exception);

        return new ResponseEntity<>(apiError.getDetail(), apiError.getStatus());
    }

    @ExceptionHandler
    public ResponseEntity<Object> handle(final Exception exception, final WebRequest request) {
        final ApiError apiError = new ApiError(INTERNAL_SERVER_ERROR);
        log.warn("General Exception handling", exception);

        return new ResponseEntity<>(apiError, apiError.getStatus());
    }
}
