package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.WebhookProperties;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventRepository;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.service.WebhookService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.*;

/*
 * Test class for the WebhookService.
 */
class WebhookServiceTest {

    @Mock
    private WebhookProperties webhookProperties;
    @Mock
    private CallbackEventRepository callbackEventRepository;
    @Mock
    private RestClient restClient;
    @Mock
    private RestClient.RequestBodyUriSpec requestBodyUriSpec;
    @Mock
    private RestClient.RequestBodySpec requestBodySpec;
    @Mock
    private RestClient.ResponseSpec responseSpec;

    @InjectMocks
    private WebhookService webhookService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(webhookProperties.getCallbackUri()).thenReturn("http://test/callback");
        when(webhookProperties.getApiKeyHeader()).thenReturn("x-api-key");
        when(webhookProperties.getApiKeyValue()).thenReturn("secret");
    }

    /**
     * This test verifies that the produceStateChangeEvent method saves a state change event
     */
    @Test
    void produceStateChangeEvent_savesEvent() {
        UUID id = UUID.randomUUID();
        webhookService.produceStateChangeEvent(id, CredentialStatusType.ISSUED);
        verify(callbackEventRepository).save(any(CallbackEvent.class));
    }

    /**
     * this test verifies that the produceErrorEvent method saves an error event
     */
    @Test
    void produceErrorEvent_savesEvent() {
        UUID id = UUID.randomUUID();
        webhookService.produceErrorEvent(id, CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED, "error");
        verify(callbackEventRepository).save(any(CallbackEvent.class));
    }

    /**
     * this test verifies that the triggerProcessCallback method sends the callback event
     */
    @Test
    void triggerProcessCallback_sendsAndDeletesEvent() {
        CallbackEvent event = CallbackEvent.builder()
                .id(UUID.randomUUID())
                .subjectId(UUID.randomUUID())
                .type(CallbackEventType.VC_STATUS_CHANGED)
                .event("ISSUED")
                .timestamp(Instant.now())
                .build();
        when(callbackEventRepository.findAll()).thenReturn(List.of(event));
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.header(anyString(), anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(Object.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        webhookService.triggerProcessCallback();

        verify(restClient).post();
        verify(callbackEventRepository).delete(event);
    }

    /**
     * This test verifies that if the RestClient throws an exception, the event is not deleted.
     */
    @Test
    void triggerProcessCallback_handlesRestClientException() {
        CallbackEvent event = CallbackEvent.builder()
                .id(UUID.randomUUID())
                .subjectId(UUID.randomUUID())
                .type(CallbackEventType.VC_STATUS_CHANGED)
                .event("ISSUED")
                .timestamp(Instant.now())
                .build();
        when(callbackEventRepository.findAll()).thenReturn(List.of(event));
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.header(anyString(), anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(Object.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenThrow(mock(RestClientResponseException.class));

        webhookService.triggerProcessCallback();

        verify(callbackEventRepository, never()).delete(event);
    }
}