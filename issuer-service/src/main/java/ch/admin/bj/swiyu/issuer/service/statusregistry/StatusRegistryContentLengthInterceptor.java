package ch.admin.bj.swiyu.issuer.service.statusregistry;

import java.io.IOException;

import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class StatusRegistryContentLengthInterceptor implements ClientHttpRequestInterceptor {

    private final StatusListProperties statusListProperties;

    @NonNull
    @Override
    public ClientHttpResponse intercept(@NonNull HttpRequest request, @NonNull byte[] body, ClientHttpRequestExecution execution) throws IOException {
        ClientHttpResponse response = execution.execute(request, body);
        long contentLength = response.getHeaders().getContentLength();

        if (contentLength > statusListProperties.getStatusListSizeLimit()) {
            throw new IllegalArgumentException("Status list size from %s exceeds maximum allowed size".formatted(request.getURI()));
        }

        return response;
    }
}