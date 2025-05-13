/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.service.statusregistry.JWTResolveRequestWrapper;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
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
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
        }
    }
}