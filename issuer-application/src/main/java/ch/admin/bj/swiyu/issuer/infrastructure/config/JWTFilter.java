package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

/**
 * "Filter" which verifies and unpacks JWT Secured Request Bodies.
 * The request is sent on with only the claims of the JWT in the request body.
 * It is only activate if enable-jwt-authentication is set to true.
 * GET Requests - which have no content - are excluded from this.
 */
@Slf4j
@AllArgsConstructor
public class JWTFilter implements Filter {

    private final ApplicationProperties config;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpServletRequest request = (HttpServletRequest) servletRequest;

        if (!config.isEnableJwtAuthentication() || "GET".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, servletResponse);
            return;
        }

        try {
            filterChain.doFilter(JWTResolveRequestWrapper.createAndValidate(request, config.getAllowedKeySet()),
                    servletResponse);
        } catch (Exception e) {
            // as filters cannot be handled by the default exception handler, we need to set the error code and message manually
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
        }
    }
}