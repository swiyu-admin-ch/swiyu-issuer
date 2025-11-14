package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
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

class StatusRegistryContentLengthInterceptorTest {
    private StatusListProperties statusListProperties;
    private StatusRegistryContentLengthInterceptor interceptor;
    private HttpRequest request;
    private ClientHttpRequestExecution execution;
    private ClientHttpResponse response;
    private HttpHeaders headers;

    @BeforeEach
    void setUp() {
        statusListProperties = mock(StatusListProperties.class);
        interceptor = new StatusRegistryContentLengthInterceptor(statusListProperties);
        request = mock(HttpRequest.class);
        execution = mock(ClientHttpRequestExecution.class);
        response = mock(ClientHttpResponse.class);
        headers = mock(HttpHeaders.class);
        when(response.getHeaders()).thenReturn(headers);
        when(request.getURI()).thenReturn(URI.create("https://example.com/status-list"));
    }

    @Test
    void throwsIfTransferEncodingIsChunked() throws IOException {
        when(headers.getFirst(HttpHeaders.TRANSFER_ENCODING)).thenReturn("chunked");
        when(response.getHeaders().getContentLength()).thenReturn(100L);
        when(execution.execute(request, new byte[0])).thenReturn(response);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                interceptor.intercept(request, new byte[0], execution)
        );
        assertTrue(ex.getMessage().contains("chunked transfer encoding"));
    }

    @Test
    void throwsIfContentLengthIsMinusOne() throws IOException {
        when(headers.getFirst(HttpHeaders.TRANSFER_ENCODING)).thenReturn(null);
        when(headers.getContentLength()).thenReturn(-1L);
        when(execution.execute(request, new byte[0])).thenReturn(response);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                interceptor.intercept(request, new byte[0], execution)
        );
        assertTrue(ex.getMessage().contains("could not be determined"));
    }

    @Test
    void throwsIfContentLengthExceedsLimit() throws IOException {
        when(headers.getFirst(HttpHeaders.TRANSFER_ENCODING)).thenReturn(null);
        when(headers.getContentLength()).thenReturn(2000L);
        when(statusListProperties.getStatusListSizeLimit()).thenReturn(1000);
        when(execution.execute(request, new byte[0])).thenReturn(response);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                interceptor.intercept(request, new byte[0], execution)
        );
        assertTrue(ex.getMessage().contains("exceeds maximum allowed size"));
    }

    @Test
    void returnsResponseIfContentLengthIsValid() throws IOException {
        when(headers.getFirst(HttpHeaders.TRANSFER_ENCODING)).thenReturn(null);
        when(headers.getContentLength()).thenReturn(500L);
        when(statusListProperties.getStatusListSizeLimit()).thenReturn(1000);
        when(execution.execute(request, new byte[0])).thenReturn(response);
        ClientHttpResponse result = interceptor.intercept(request, new byte[0], execution);
        assertSame(response, result);
    }
}