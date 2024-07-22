package ch.admin.bit.eid.issuer_management.interceptor;

import ch.admin.bit.eid.issuer_management.config.ApplicationConfig;
import ch.admin.bit.eid.issuer_management.exceptions.ConfigurationException;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.text.ParseException;

@Component
@Slf4j
@AllArgsConstructor
public class JWTFilter implements Filter {

    private final ApplicationConfig config;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if (! config.isEnableJwtAuthentication() || "GET".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, servletResponse);
            return;
        }

        try {
            filterChain.doFilter(JWTResolveRequestWrapper.createAndValidate(request, config.getAllowedKeySet()), servletResponse);
        } catch (ParseException e) {
            log.error("Provided Allow JWKSet can not be parsed! %s".formatted(config.getAuthenticationJwks()));
            throw new ConfigurationException("Provided Allow JWKSet can not be parsed! %s".formatted(config.getAuthenticationJwks()));
        }
    }
}
