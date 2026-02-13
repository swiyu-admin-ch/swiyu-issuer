package ch.admin.bj.swiyu.issuer.common.date;

import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

import static java.util.Objects.isNull;

@UtilityClass
public class TimeUtils {

    private static final DateTimeFormatter ISO_OFFSET_DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX").withZone(ZoneOffset.UTC);

    /** returns the UNIX timestamp of the provided instant rounded down to the day.
     * E.g. 2025-01-09 10:15:30.12345 is truncated to 2025-01-09 00:00
     */
    public static Long instantToRoundedUnixTimestamp(Instant instant) {
        if (instant == null) {
            return null;
        }
        return instant.truncatedTo(ChronoUnit.DAYS).getEpochSecond();
    }

    public static String instantToISO8601(Instant instant) {
        if (isNull(instant)) {
            return null;
        }

        return ISO_OFFSET_DATE_TIME_FORMATTER.format(instant.atOffset(ZoneOffset.UTC));
    }
}
