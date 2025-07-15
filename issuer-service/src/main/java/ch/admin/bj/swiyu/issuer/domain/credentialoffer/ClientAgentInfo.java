package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

public record ClientAgentInfo(
        String remoteAddr,
        String userAgent,
        String acceptLanguage,
        String acceptEncoding
) {
}