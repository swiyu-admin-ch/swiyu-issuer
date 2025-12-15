package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.WebhookProperties;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventRepository;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.service.webhook.WebhookEventProducer;
import ch.admin.bj.swiyu.issuer.service.webhook.WebhookEventProcessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.*;

/**
 * Test class for the WebhookEventProducer and WebhookEventListener.
 */
class WebhookServiceTest {

    @Mock
    private WebhookProperties webhookProperties;
    @Mock
    private CallbackEventRepository callbackEventRepository;
    @Mock
    private WebClient webClient;
    @Mock
    private WebClient.RequestBodyUriSpec requestBodyUriSpec;
    @Mock
    private WebClient.RequestBodySpec requestBodySpec;
    @Mock
    private WebClient.ResponseSpec responseSpec;

    @InjectMocks
    private WebhookEventProducer webhookEventProducer;

    @InjectMocks
    private WebhookEventProcessor webhookEventProcessor;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        webhookEventProducer = new WebhookEventProducer(webhookProperties, callbackEventRepository);
        webhookEventProcessor = new WebhookEventProcessor(webhookProperties, callbackEventRepository, webClient);
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
        webhookEventProducer.produceStateChangeEvent(id, CredentialStatusType.ISSUED);
        verify(callbackEventRepository).save(any(CallbackEvent.class));
    }

    /**
     * this test verifies that the produceErrorEvent method saves an error event
     */
    @Test
    void produceErrorEvent_savesEvent() {
        UUID id = UUID.randomUUID();
        webhookEventProducer.produceErrorEvent(id, CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED, "error");
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
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        doReturn(requestBodySpec).when(requestBodySpec).header(anyString(), anyString());
        doReturn(requestBodySpec).when(requestBodySpec).contentType(MediaType.APPLICATION_JSON);
        doReturn(requestBodySpec).when(requestBodySpec).bodyValue(any(Object.class));
        doReturn(responseSpec).when(requestBodySpec).retrieve();
        when(responseSpec.toBodilessEntity()).thenReturn(Mono.empty());

        webhookEventProcessor.triggerProcessCallback();

        verify(webClient).post();
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
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        doReturn(requestBodySpec).when(requestBodySpec).header(anyString(), anyString());
        doReturn(requestBodySpec).when(requestBodySpec).contentType(MediaType.APPLICATION_JSON);
        doReturn(requestBodySpec).when(requestBodySpec).bodyValue(any(Object.class));
        doReturn(responseSpec).when(requestBodySpec).retrieve();
        when(responseSpec.toBodilessEntity()).thenReturn(Mono.error(mock(RestClientResponseException.class)));

        webhookEventProcessor.triggerProcessCallback();

        verify(callbackEventRepository, never()).delete(event);
    }
}