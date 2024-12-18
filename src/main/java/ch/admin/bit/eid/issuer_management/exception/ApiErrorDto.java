package ch.admin.bit.eid.issuer_management.exception;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.http.HttpStatus;

@Schema(name = "ApiError", description = "Error response object")
public record ApiErrorDto(@JsonIgnore
                          HttpStatus status,
                          String detail) {
}
