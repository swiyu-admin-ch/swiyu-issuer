/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;

@RequiredArgsConstructor
@Component
public class StatusRegistryContentLengthInterceptor implements ClientHttpRequestInterceptor {

    private final StatusListProperties statusListProperties;

    @NonNull
    @Override
    public ClientHttpResponse intercept(@NonNull HttpRequest request, @NonNull byte[] body, ClientHttpRequestExecution execution) throws IOException {
        ClientHttpResponse response = execution.execute(request, body);
        long contentLength = response.getHeaders().getContentLength();

        String transferEncoding = response.getHeaders().getFirst(HttpHeaders.TRANSFER_ENCODING);

        // decline if transfer-encoding is chunked
        if ("chunked".equalsIgnoreCase(transferEncoding)) {
            throw new IllegalArgumentException(getStatusListSizeUnknownMessage(request.getURI()) + " (chunked transfer encoding)");
        }

        if (contentLength == -1) {
            throw new IllegalArgumentException(getStatusListSizeUnknownMessage(request.getURI()));
        }

        if (contentLength > statusListProperties.getStatusListSizeLimit()) {
            throw new IllegalArgumentException("Status list size from %s exceeds maximum allowed size".formatted(request.getURI()));
        }

        return response;
    }

    private String getStatusListSizeUnknownMessage(URI uri) {
        return "Status list size from %s could not be determined".formatted(uri);
    }
}