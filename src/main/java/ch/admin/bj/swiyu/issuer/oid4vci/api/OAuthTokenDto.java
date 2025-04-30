/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springdoc.core.configuration.oauth2.SpringDocOAuth2Token;

import java.io.Serial;
import java.io.Serializable;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
@Setter
@Getter
@Schema(name = "OAuthToken")
public class OAuthTokenDto implements SpringDocOAuth2Token, Serializable {
    @Serial
    private static final long serialVersionUID = 1905122041950251307L;

    @NotNull
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("expires_in")
    private long expiresIn;
    @JsonProperty("c_nonce")
    private String cNonce;

    @Override
    public String getAccessToken() {
        return this.accessToken;
    }

    @Override
    public String getTokenType() {
        return "BEARER";
    }

    @Override
    public long getExpiresIn() {
        return this.expiresIn;
    }

    @Override
    public String getScope() {
        return null;
    }

    @Override
    public String getRefreshToken() {
        return null;
    }
}
