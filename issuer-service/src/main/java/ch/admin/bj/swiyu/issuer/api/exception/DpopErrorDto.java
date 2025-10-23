package ch.admin.bj.swiyu.issuer.api.exception;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "DpopError", description = "Error response for DPoP")
public class DpopErrorDto {
    @JsonProperty("error")
    String errorCode;
    @JsonProperty("error_description")
    String errorDescription;
}
