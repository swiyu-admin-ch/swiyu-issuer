package ch.admin.bit.eid.issuer_management.domain.ecosystem;

import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.PostExchange;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * The API which is provided by the token provider of the swiyu ecosystem api components.
 */
public interface TokenApi {

    @PostExchange( contentType = "application/x-www-form-urlencoded")
    TokenResponse getNewToken(

            @RequestParam
            String client_id,
            @RequestParam
            String client_secret,
            @RequestParam
            String grant_type
    );

    @PostExchange(contentType = "application/x-www-form-urlencoded")
    TokenResponse getNewToken(
            @RequestParam
            String client_id,
            @RequestParam
            String client_secret,
            @RequestParam(required = false)
            String refresh_token,
            @RequestParam
            String grant_type
    );

    record TokenResponse(
            String access_token,
            String refresh_token
    ) {
    }

}
