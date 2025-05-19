package ch.admin.bj.swiyu.issuer.api.credentialoffer;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

/**
 * Data Transfer Object for Pre-Authorized Code.
 *
 * @param preAuthCode The pre-authorized code as a UUID.
 */
public record PreAuthorizedCodeGrantDto(
        @JsonProperty("pre-authorized_code") UUID preAuthCode) {
}