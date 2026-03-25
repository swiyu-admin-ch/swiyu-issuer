package ch.admin.bj.swiyu.issuer.common.utils;

import ch.admin.bj.swiyu.issuer.common.date.TimeUtils;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;

class TimeUtilsTest {

    @Test
    void testInstantToRoundedUnixTimestamp() {
        Instant now = Instant.now();
        Long timestamp = TimeUtils.instantToRoundedUnixTimestamp(now);
        assertNotNull(timestamp);
        assertTrue(now.getEpochSecond() <= timestamp);
        assertTrue(now.plus(1, ChronoUnit.DAYS).getEpochSecond() > timestamp);
        var timestampInstant = Instant.ofEpochSecond(timestamp).atZone(ZoneOffset.UTC);
        assertEquals(23, timestampInstant.getHour());
        assertEquals(59, timestampInstant.getMinute());
        assertEquals(59, timestampInstant.getSecond());
        // Nanosecond should be zero, as max precision of a Unix timestamp is a second
        assertEquals(0, timestampInstant.getNano());
    }

    @Test
    void testInstantRoundedUnixTimestamp_instantsOfSameDayShouldRoundToSameInstant() {
        var date = LocalDate.parse("2026-12-31");
        var instant1 = date.atStartOfDay(ZoneOffset.UTC).withHour(12).withMinute(30).withSecond(29).withNano(10).toInstant();
        var instant2 = date.atStartOfDay(ZoneOffset.UTC).withHour(7).withMinute(54).withSecond(13).withNano(928).toInstant();
        assertThat(TimeUtils.instantToRoundedUnixTimestamp(instant1)).isEqualTo(TimeUtils.instantToRoundedUnixTimestamp(instant2));
    }

    @Test
    void testInstantToUnixTimestampWithNull() {
        assertNull(TimeUtils.instantToRoundedUnixTimestamp(null));
    }

    @Test
    void testInstantToISO8601() {
        String iso8601 = TimeUtils.instantToISO8601(Instant.now());
        assertNotNull(iso8601);
        assertTrue(iso8601.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z"));
    }

    @Test
    void testInstantToISO8601WithNull() {
        assertNull(TimeUtils.instantToISO8601(null));
    }
}
