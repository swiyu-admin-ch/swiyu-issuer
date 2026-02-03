package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum OAuthTokenGrantType {
    PRE_AUTHORIZED_CODE("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
    REFRESH_TOKEN("refresh_token");

    private final String name;

}
