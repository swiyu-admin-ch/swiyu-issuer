package ch.admin.bj.swiyu.issuer.api.credentialoffer;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ClientAgentInfoDto(
        @JsonProperty("remoteAddr")
        String remoteAddr,
        @JsonProperty("user-agent")
        String userAgent,
        @JsonProperty("accept-language")
        String acceptLanguage,
        @JsonProperty("accept-encoding")
        String acceptEncoding
) {
}