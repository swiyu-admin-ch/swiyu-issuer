package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import lombok.Data;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
public class FilterConfig {

    private static final String[] URL_PATTERNS = {
            "/api/v1/private/credentials",
            "/api/v1/private/credentials/*",
            "/api/v1/private/status-list",
            "/api/v1/private/status-list/*",
    };
    private final ApplicationProperties applicationProperties;

    @Bean
    public JWTFilter jwtFilter() {
        return new JWTFilter(applicationProperties); // Create and return an instance of JWTFilter
    }


    @Bean
    public FilterRegistrationBean<JWTFilter> jwtFilterRegistration(JWTFilter jwtFilter) {
        FilterRegistrationBean<JWTFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(jwtFilter);
        registrationBean.addUrlPatterns(URL_PATTERNS);
        registrationBean.setOrder(1); // Set the order of the filter if needed
        return registrationBean;
    }
}