package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ClientAgentInfo(
        @JsonProperty("remoteAddr")
        String remoteAddr,
        @JsonProperty("user-agent")
        String userAgent,
        @JsonProperty("accept-language")
        String acceptLanguage,
        @JsonProperty("accept-encoding")
        String acceptEncoding) {
}