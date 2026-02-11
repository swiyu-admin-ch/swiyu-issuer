package ch.admin.bj.swiyu.issuer.common.config;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Slf4j
@Validated
@Getter
@Setter
@ConfigurationProperties(prefix = "application.status-list")
public class StatusListProperties extends SignatureConfiguration {
    /**
     * The Version of the swiyu status list data structures
     */
    private final String version = "1.0";
    /**
     * Configured limitation to the status list,
     * preventing accidental creation of status lists too large for sensible use.
     */
    private int statusListSizeLimit;

}
