package ch.admin.bj.swiyu.issuer;

import ch.admin.bj.swiyu.issuer.infrastructure.config.ContentLengthInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ContentLengthInterceptorTest {

    private final int exampleMaxSize = 1024;
    private ContentLengthInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new ContentLengthInterceptor(exampleMaxSize);
    }

    @Test
    void testInterceptWithinLimit_thenSuccess() throws IOException {
        HttpRequest request = mock(HttpRequest.class);
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);

        var headers = createHttpHeadersWithContentLength(exampleMaxSize - 1);

        when(request.getURI()).thenReturn(URI.create("http://example.com"));
        when(response.getHeaders()).thenReturn(headers);
        when(execution.execute(request, new byte[0])).thenReturn(response);

        ClientHttpResponse result = interceptor.intercept(request, new byte[0], execution);

        assertEquals(response, result);
    }

    @Test
    void testInterceptExceedsLimit_thenFailure() throws IOException {
        HttpRequest request = mock(HttpRequest.class);
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);

        var headers = createHttpHeadersWithContentLength(exampleMaxSize + 1);

        when(request.getURI()).thenReturn(URI.create("http://example.com"));
        when(response.getHeaders()).thenReturn(headers);
        when(execution.execute(request, new byte[0])).thenReturn(response);

        IllegalStateException thrown = assertThrows(IllegalStateException.class, () ->
                interceptor.intercept(request, new byte[0], execution)
        );

        assertTrue(thrown.getMessage().contains("exceeds maximum allowed size"));
    }

    private HttpHeaders createHttpHeadersWithContentLength(long contentLength) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentLength(contentLength);
        return headers;
    }
}