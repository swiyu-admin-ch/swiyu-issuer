/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service.statusregistry;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Interceptor for status registry requests. Injects the authorization token
 * from the
 * token provider.
 */
@Component
@RequiredArgsConstructor
public class StatusRegistryTokenInterceptor implements ClientHttpRequestInterceptor {
    private final StatusRegistryTokenDomainService statusRegistryTokenDomainService;

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        request.getHeaders().add("Authorization", "Bearer " + statusRegistryTokenDomainService.getAccessToken());
        ClientHttpResponse response;
        response = execution.execute(request, body);
        if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            request.getHeaders().add("Authorization",
                    "Bearer " + statusRegistryTokenDomainService.forceRefreshAccessToken());
            response = execution.execute(request, body);
        }
        return response;
    }
}
