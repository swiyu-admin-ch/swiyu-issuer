package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object for the Oauth Access Token Request
 * JsonProperty is not working with the necessary media type application/x-www-form-urlencoded but are kept for documentation
 *
 */
@Schema(name = "OauthAccessTokenRequest")
public record OAuthAccessTokenRequestDto(
        @NotBlank
        @JsonProperty("grant_type")
        @Schema(description = "The type of grant being requested. Must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code' or 'refresh_token.", defaultValue = "urn:ietf:params:oauth:grant-type:pre-authorized_code")
        String grant_type,

        @Nullable
        @JsonProperty("pre-authorized_code")
        @Schema(description = " The code representing the authorization to obtain Credentials of a certain type. This parameter MUST be present if the grant_type is urn:ietf:params:oauth:grant-type:pre-authorized_code.")
        String preauthorized_code,

        @Nullable
        @JsonProperty("refresh_token")
        @Schema(description = "The refresh token, which can be used to obtain new access tokens.")
        String refresh_token,

        @Nullable 
        @JsonProperty("tx_code")
        @Schema(description = "String value containing a Transaction Code value itself. This value MUST be present if a tx_code object was present in the Credential Offer (including if the object was empty). This parameter MUST only be used if the grant_type is urn:ietf:params:oauth:grant-type:pre-authorized_code.")
        String tx_code


) {
}