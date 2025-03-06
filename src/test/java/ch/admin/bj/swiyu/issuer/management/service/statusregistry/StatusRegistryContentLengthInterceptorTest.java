package ch.admin.bj.swiyu.issuer.management.service.statusregistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StatusRegistryContentLengthInterceptorTest {

    private StatusRegistryContentLengthInterceptor statusRegistryContentLengthInterceptor;
    private HttpRequest request;
    private ClientHttpRequestExecution execution;
    private ClientHttpResponse response;

    @BeforeEach
    void setUp() {
        statusRegistryContentLengthInterceptor = new StatusRegistryContentLengthInterceptor();
        request = mock(HttpRequest.class);
        execution = mock(ClientHttpRequestExecution.class);
        response = mock(ClientHttpResponse.class);
    }

    @Test
    void testIntercept_ContentLengthWithinLimit() throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentLength(1024L); // 1 KB
        when(response.getHeaders()).thenReturn(headers);
        when(execution.execute(Mockito.any(HttpRequest.class), Mockito.any(byte[].class))).thenReturn(response);

        assertDoesNotThrow(() -> statusRegistryContentLengthInterceptor.intercept(request, new byte[0], execution));
    }

    @Test
    void testIntercept_ContentLengthExceedsLimit() throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentLength(10485761L); // 10 MB + 1 byte
        when(response.getHeaders()).thenReturn(headers);
        when(execution.execute(Mockito.any(HttpRequest.class), Mockito.any(byte[].class))).thenReturn(response);

        assertThrows(IllegalArgumentException.class, () -> statusRegistryContentLengthInterceptor.intercept(request, new byte[0], execution));
    }
}