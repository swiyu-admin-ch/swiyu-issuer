package ch.admin.bj.swiyu.issuer.common.config;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for status list handling.
 * <p>
 * Holds settings that control caching and expiry semantics for status lists
 * used by the Issuer (e.g. caching TTL and how long a generated status list
 * is considered valid).
 */
@Slf4j
@Validated
@Getter
@Setter
@ConfigurationProperties(prefix = "application.status-list")
public class StatusListProperties extends SignatureConfiguration {
    /**
     * Configured limitation to the status list,
     * preventing accidental creation of status lists too large for sensible use.
     */
    private int statusListSizeLimit;

    /**
     * Time-to-live (in seconds) for cached status list entries.
     * This value is used by the in-memory cache to determine
     * how long a retrieved or computed status list should be kept before it
     * is considered stale.
     */
    @NotNull
    private Integer statusListCacheTimeSeconds;

    /**
     * Expiration duration (in seconds) for a status list artifact itself.
     * Represents how long a generated status list remains valid.
     */
    @NotNull
    private Long statusListExpirationSeconds;


}
