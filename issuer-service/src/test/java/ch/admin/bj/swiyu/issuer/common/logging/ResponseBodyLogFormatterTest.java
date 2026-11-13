package ch.admin.bj.swiyu.issuer.common.logging;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class ResponseBodyLogFormatterTest {

    @Test
    void format_nullOrBlank_returnsEmptyHint() {
        assertThat(ResponseBodyLogFormatter.format(null)).isEqualTo("<empty body>");
        assertThat(ResponseBodyLogFormatter.format("")).isEqualTo("<empty body>");
        assertThat(ResponseBodyLogFormatter.format("   ")).isEqualTo("<empty body>");
    }

    @Test
    void format_shortBody_isReturnedUnchanged() {
        assertThat(ResponseBodyLogFormatter.format("{\"error\":\"x\"}")).isEqualTo("{\"error\":\"x\"}");
    }

    @Test
    void format_bodyAtLimit_isNotTruncated() {
        var body = "a".repeat(2000);
        assertThat(ResponseBodyLogFormatter.format(body)).isEqualTo(body);
    }

    @Test
    void format_bodyOverLimit_isTruncated() {
        var result = ResponseBodyLogFormatter.format("a".repeat(2001));
        assertThat(result).isEqualTo("a".repeat(2000) + "...<truncated>");
    }

    @Test
    void describe_webClientResponseException_containsStatusAndBody() {
        var e = WebClientResponseException.create(400, "Bad Request", HttpHeaders.EMPTY,
                "invalid".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        assertThat(ResponseBodyLogFormatter.describe(e)).isEqualTo("status=400, body=invalid");
    }

    @Test
    void describe_webClientResponseExceptionWithoutBody_containsEmptyHint() {
        var e = WebClientResponseException.create(500, "Error", HttpHeaders.EMPTY, null, null);
        assertThat(ResponseBodyLogFormatter.describe(e)).isEqualTo("status=500, body=<empty body>");
    }

    @Test
    void describe_httpStatusCodeException_containsStatusAndBody() {
        var e = HttpClientErrorException.create(HttpStatus.NOT_FOUND, "Not Found", HttpHeaders.EMPTY,
                "missing".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        assertThat(ResponseBodyLogFormatter.describe(e)).isEqualTo("status=404, body=missing");
    }
}
