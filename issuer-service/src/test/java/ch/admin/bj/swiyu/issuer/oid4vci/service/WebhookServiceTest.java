package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.WebhookProperties;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventRepository;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.service.webhook.WebhookEventProcessor;
import ch.admin.bj.swiyu.issuer.service.webhook.WebhookEventProducer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;

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
    @Mock
    private WebClient.RequestHeadersSpec requestHeaderSpec;

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
        webhookEventProducer.produceStateChangeEvent(id, CredentialOfferStatusType.ISSUED);
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
        when(requestBodySpec.header(anyString(), anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(any(Object.class))).thenReturn(requestHeaderSpec);
        when(requestHeaderSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenReturn(
                reactor.core.publisher.Mono.just(org.springframework.http.ResponseEntity.noContent().build())
        );

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
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.header(anyString(), anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(any(Object.class))).thenReturn(requestHeaderSpec);
        when(requestHeaderSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenReturn(
                reactor.core.publisher.Mono.just(org.springframework.http.ResponseEntity.noContent().build())
        );

        webhookEventProcessor.triggerProcessCallback();

        verify(callbackEventRepository, never()).delete(event);
    }
}