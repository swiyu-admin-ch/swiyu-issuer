package ch.admin.bj.swiyu.issuer.management.common.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configures the maximum number of HTTP redirects by setting the `http.maxRedirects` system property.
 * This configuration is necessary because Spring Boot, by default, uses `HttpURLConnection` as the underlying
 * HTTP client for requests and `HttpURLConnection` respects the `http.maxRedirects` system property to manage redirects.
 *
 * Unlike properties such as `readTimeout` and `connectionTimeout`, which can be configured directly through
 * Spring's `application.yml`, the `http.maxRedirects` property must be set as a system property at the JVM level.
 * This is because `HttpURLConnection` does not expose a direct configuration property for controlling redirects.
 *
 * If the property is not set, the default behavior of `HttpURLConnection` will allow up to 20 redirects.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "http")
@Slf4j
public class HttpConfig {

    private Integer maxRedirects;

    @PostConstruct
    public void init() {
        if (maxRedirects != null) {
            System.setProperty("http.maxRedirects", String.valueOf(maxRedirects));
            log.info("http.maxRedirects set to: " + maxRedirects);
        } else {
            log.info("http.maxRedirects not set. Using default.");
        }
    }
}