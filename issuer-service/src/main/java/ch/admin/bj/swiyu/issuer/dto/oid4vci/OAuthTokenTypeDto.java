package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "OAuthTokenType", enumAsRef = true)
public enum OAuthTokenTypeDto {
    BEARER("BEARER"),
    DPoP("DPoP");
    

    private final String stringRepresentation;

    OAuthTokenTypeDto(String stringRepresentation) {
        this.stringRepresentation = stringRepresentation;
    }

    @Override
    public String toString() {
        return this.stringRepresentation;
    }
}