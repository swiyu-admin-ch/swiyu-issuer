package ch.admin.bj.swiyu.issuer.api.exception;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Builder
@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
@Schema(name = "ApiError", description = "Error response object")
public class ApiErrorDto {
    @JsonProperty("error")
    String errorCode;
    @JsonProperty("error_description")
    String errorDescription;
    @JsonProperty("detail")
    String errorDetails;
    @JsonIgnore
    HttpStatus status;
}