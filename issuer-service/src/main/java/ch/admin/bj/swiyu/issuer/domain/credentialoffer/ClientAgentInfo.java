package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientAgentInfo(
        String remoteAddr,
        String userAgent,
        String acceptLanguage,
        String acceptEncoding
) {
}