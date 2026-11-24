package ch.admin.bj.swiyu.issuer.common.logging;

import lombok.experimental.UtilityClass;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

/**
 * Formats HTTP response bodies of external systems for log output.
 */
@UtilityClass
public class ResponseBodyLogFormatter {

    static final int MAX_LOGGED_BODY_LENGTH = 2000;
    static final String EMPTY_BODY = "<empty body>";
    static final String TRUNCATED_SUFFIX = "...<truncated>";

    /**
     * @param body the response body, may be {@code null}
     * @return the body truncated to {@value #MAX_LOGGED_BODY_LENGTH} characters, or {@value #EMPTY_BODY} if it is null or blank
     */
    public static String format(String body) {
        if (body == null || body.isBlank()) {
            return EMPTY_BODY;
        }
        return body.length() > MAX_LOGGED_BODY_LENGTH
                ? body.substring(0, MAX_LOGGED_BODY_LENGTH) + TRUNCATED_SUFFIX
                : body;
    }

    /**
     * Describes a registry response (status and formatted body) for log output, e.g. {@code status=400, body=...}.
     */
    public static String describe(WebClientResponseException e) {
        return describe(e.getStatusCode().value(), e.getResponseBodyAsString());
    }

    /**
     * Describes a registry response (status and formatted body) for log output, e.g. {@code status=400, body=...}.
     */
    public static String describe(HttpStatusCodeException e) {
        return describe(e.getStatusCode().value(), e.getResponseBodyAsString());
    }

    private static String describe(int status, String body) {
        return "status=%s, body=%s".formatted(status, format(body));
    }
}
