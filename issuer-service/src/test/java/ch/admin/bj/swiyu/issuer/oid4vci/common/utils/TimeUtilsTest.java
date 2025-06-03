/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.common.utils;

import ch.admin.bj.swiyu.issuer.common.date.TimeUtils;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

public class TimeUtilsTest {

    @Test
    void testInstantToUnixTimestamp() {
        Instant now = Instant.now();
        Long timestamp = TimeUtils.instantToUnixTimestamp(now);
        assertNotNull(timestamp);
        assertEquals(now.getEpochSecond(), timestamp);
    }

    @Test
    void testInstantToUnixTimestampWithNull() {
        assertNull(TimeUtils.instantToUnixTimestamp(null));
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
