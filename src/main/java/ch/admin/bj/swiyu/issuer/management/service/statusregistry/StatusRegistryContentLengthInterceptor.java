/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service.statusregistry;

import java.io.IOException;

import ch.admin.bj.swiyu.issuer.management.common.config.StatusListProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class StatusRegistryContentLengthInterceptor implements ClientHttpRequestInterceptor {

    private final StatusListProperties statusListProperties;

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        ClientHttpResponse response = execution.execute(request, body);
        long contentLength = response.getHeaders().getContentLength();

        if (contentLength > statusListProperties.getStatusListSizeLimit()) {
            throw new IllegalArgumentException("Status list size from %s exceeds maximum allowed size".formatted(request.getURI()));
        }

        return response;
    }
}