package ch.admin.bj.swiyu.issuer.management.infrastructure.logging;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestLoggingFilterTest {

    @ParameterizedTest
    @ValueSource(strings = {"https://localhost:8080/api/1234", "https://example.ch"})
    void testUrlFilterPattern_ShouldNotMatch(String url) {
        // GIVEN
        var regex = Pattern.compile(".*/actuator/.*");
        // WHEN
        var matches = regex.matcher(url).matches();
        // THEN
        assertFalse(matches);
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://localhost:8080/actuator/health", "https://example.ch/actuator/health/readiness", "/actuator/info"})
    void testUrlFilterPattern_ShouldMatch(String url) {
        // GIVEN
        var regex = Pattern.compile(".*/actuator/.*");
        // WHEN
        var matches = regex.matcher(url).matches();
        // THEN
        assertTrue(matches);
    }
}