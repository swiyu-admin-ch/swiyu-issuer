/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.common.utils;

import ch.admin.bj.swiyu.issuer.common.date.TimeUtils;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

class TimeUtilsTest {

    @Test
    void testInstantToRoundedUnixTimestamp() {
        Instant now = Instant.now();
        Long timestamp = TimeUtils.instantToRoundedUnixTimestamp(now);
        assertNotNull(timestamp);
        assertTrue(now.getEpochSecond() > timestamp);
        assertTrue(now.plus(-1, ChronoUnit.DAYS).getEpochSecond() < timestamp);
        var timestampInstant = Instant.ofEpochSecond(timestamp).atZone(ZoneOffset.UTC);
        assertEquals(0, timestampInstant.getHour());
        assertEquals(0, timestampInstant.getMinute());
        assertEquals(0, timestampInstant.getSecond());
        assertEquals(0, timestampInstant.getNano());
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
