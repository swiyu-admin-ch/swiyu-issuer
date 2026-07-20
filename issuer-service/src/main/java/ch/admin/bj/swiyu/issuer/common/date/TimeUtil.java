package ch.admin.bj.swiyu.issuer.common.date;

import lombok.experimental.UtilityClass;
import net.javacrumbs.shedlock.support.annotation.Nullable;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.isNull;

@UtilityClass
public class TimeUtil {

    private static final DateTimeFormatter ISO_OFFSET_DATE_TIME_FORMATTER = DateTimeFormatter
            .ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX").withZone(ZoneOffset.UTC);

    /**
     * returns the UNIX timestamp of the provided instant rounded up to the end of
     * the day.
     * E.g. 2025-01-09 10:15:30.12345 is truncated to 2025-01-09 23:59:59
     */
    public static Long instantToRoundedUpUnixTimestamp(Instant instant) {
        if (instant == null) {
            return null;
        }
        var zdt = instant.truncatedTo(ChronoUnit.DAYS).atZone(ZoneOffset.UTC);
        var adjusted = zdt.withHour(23).withMinute(59).withSecond(59);
        return adjusted.toInstant().getEpochSecond();
    }

    /**
     * returns the UNIX timestamp of the provided instant rounded down to the day.
     * E.g. 2025-01-09 10:15:30.12345 is truncated to 2025-01-09 00:00
     */
    public static Long instantToRoundedDownUnixTimestamp(Instant instant) {
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

    /**
     * Returns the minimum of two values, treating null as "no comparison".
     * 
     * @param accumulator   The base value (in nanoseconds).
     * @param nullableValue The nullable value to compare (in nanoseconds).
     * @return The smaller of the two values, or accumulator if nullableValue is
     *         null.
     */
    public long minWithNullable(long accumulator, @Nullable Long nullableLong) {
        return nullableLong == null ? accumulator : Math.min(accumulator, nullableLong);
    }

    /**
     * Converts seconds to nanoseconds, returning null if input is null.
     * 
     * @param nullableSeconds Seconds (nullable).
     * @return Nanoseconds, or null.
     */
    public Long secondsToNanos(@Nullable Integer nullableSeconds) {
        return nullableSeconds == null ? null : TimeUnit.SECONDS.toNanos(nullableSeconds);
    }

    /**
     * Converts seconds to nanoseconds, returning null if input is null.
     * 
     * @param nullableSeconds Seconds (nullable).
     * @return Nanoseconds, or null.
     */
    public Long secondsToNanos(@Nullable Long nullableSeconds) {
        return nullableSeconds == null ? null : TimeUnit.SECONDS.toNanos(nullableSeconds);
    }

    /**
     * Converts milliseconds to nanoseconds, returning null if input is null.
     * 
     * @param nullableLongMs Milliseconds (nullable).
     * @return Nanoseconds, or null.
     */
    public Long millisToNanos(@Nullable Long nullableLongMs) {
        return nullableLongMs == null ? null : TimeUnit.MILLISECONDS.toNanos(nullableLongMs);
    }

    /**
     * Calculates nanoseconds until expiry from epoch millis.
     * 
     * @param expirationTime Epoch in nanoseconds (nullable).
     * @return Nanoseconds until expiry, or null.
     */
    public static Long nanosUntilExpiry(@Nullable Long expirationTime) {
        if (expirationTime == null) {
            return null;
        }
        return Math.max(0, expirationTime - millisToNanos(Instant.now().toEpochMilli()));
    }

    /**
     * Calculates nanoseconds until expiry from Instant.
     * 
     * @param expirationTime Instant (nullable).
     * @return Nanoseconds until expiry, or null.
     */
    public static Long nanosUntilExpiry(@Nullable Date expirationTime) {
        if (expirationTime == null) {
            return null;
        }
        return nanosUntilExpiry(millisToNanos(expirationTime.getTime()));
    }

    /**
     * Returns the minimum of accumulator and time until expiry.
     * 
     * @param accumulator    Time in nanoseconds.
     * @param expirationTime Epoch nanoseconds (nullable).
     * @return Minimum of accumulator or time until expiry.
     */
    public static long minNanosUntilExpiry(long accumulator, @Nullable Long expirationTime) {
        if (expirationTime == null) {
            return accumulator;
        }
        return minWithNullable(accumulator, nanosUntilExpiry(expirationTime));
    }

    /**
     * Returns the minimum of accumulator and time until expiry.
     * 
     * @param accumulator    Time in nanoseconds.
     * @param expirationTime Instant (nullable).
     * @return Minimum of accumulator or time until expiry.
     */
    public static long minNanosUntilExpiry(long accumulator, @Nullable Date expirationTime) {
        if (expirationTime == null) {
            return accumulator;
        }
        return minWithNullable(accumulator, nanosUntilExpiry(expirationTime));
    }
}
