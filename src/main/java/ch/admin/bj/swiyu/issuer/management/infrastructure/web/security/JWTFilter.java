/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.infrastructure.web.security;

import ch.admin.bj.swiyu.issuer.management.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.management.service.statusregistry.JWTResolveRequestWrapper;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * "Filter" which verifies and unpacks JWT Secured Request Bodies.
 * The request is sent on with only the claims of the JWT in the request body.
 * It is only activate if enable-jwt-authentication is set to true.
 * GET Requests - which have no content - are excluded from this.
 */
@Component
@Slf4j
@AllArgsConstructor
public class JWTFilter implements Filter {

    private final ApplicationProperties config;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if (!config.isEnableJwtAuthentication() || "GET".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, servletResponse);
            return;
        }
        filterChain.doFilter(JWTResolveRequestWrapper.createAndValidate(request, config.getAllowedKeySet()),
                servletResponse);
    }
}
