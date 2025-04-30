/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.common.utils;

import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import static java.util.Objects.isNull;

@UtilityClass
public class TimeUtils {

    private static final DateTimeFormatter ISO_OFFSET_DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX").withZone(ZoneOffset.UTC);

    public static long getUnixTimeStamp() {
        return Instant.now().getEpochSecond();
    }

    public static Long instantToUnixTimestamp(Instant instant) {
        if (isNull(instant)) {
            return null;
        }

        return instant.getEpochSecond();
    }

    public static String instantToISO8601(Instant instant) {
        if (isNull(instant)) {
            return null;
        }

        return ISO_OFFSET_DATE_TIME_FORMATTER.format(instant.atOffset(ZoneOffset.UTC));
    }
}
