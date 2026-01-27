package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.callback.CallbackEventTypeDto;
import ch.admin.bj.swiyu.issuer.api.callback.WebhookCallbackDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.service.webhook.WebhookEventProcessor;
import ch.admin.bj.swiyu.issuer.service.webhook.WebhookEventProducer;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.logging.LogManager;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

/**
 * Collection of flows we expect a callback
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
@ExtendWith(OutputCaptureExtension.class)
/**
 * Test Webhook Callbacks including if the RestClient has been used correctly.
 */
class WebhookIT {
    static final String API_KEY_HEADER = "x-api-key";
    static final String API_KEY_VALUE = "1235";


    // https://square.github.io/okhttp/#mockwebserver
    private static MockWebServer mockWebServer;
    @Autowired
    private WebhookEventProcessor webhookEventProcessor;
    @Autowired
    private WebhookEventProducer webhookEventProducer;
    @Autowired
    private ObjectMapper objectMapper;

    @DynamicPropertySource
    static void callbackServerProperties(DynamicPropertyRegistry registry) {
        mockWebServer = new MockWebServer();
        try {
            mockWebServer.start();
            registry.add("webhook.callback-uri", () -> mockWebServer.url("/callback").toString());
            registry.add("webhook.api-key-header", () -> API_KEY_HEADER);
            registry.add("webhook.api-key-value", () -> API_KEY_VALUE);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @AfterAll
    static void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    void testHighLevelCallback(CapturedOutput output) throws InterruptedException, IOException {
        // Note: This is in one single test as failing tests would influence other running tests
        // through the enqueued responses.
        mockWebServer.enqueue(new MockResponse().setResponseCode(200));
        this.webhookEventProducer.produceOfferStateChangeEvent(UUID.randomUUID(), CredentialOfferStatusType.ISSUED);

        // When triggered the callback event should be sent and received by our mock business server
        triggerCallBackProcess(1);
        var request = mockWebServer.takeRequest(100, TimeUnit.MILLISECONDS);
        Assertions.assertThat(request).isNotNull();
        Assertions.assertThat(request.getMethod()).isEqualTo("POST");
        Assertions.assertThat(request.getHeader(API_KEY_HEADER)).isEqualTo(API_KEY_VALUE);
        var dto = objectMapper.readValue(request.getBody().readByteArray(), WebhookCallbackDto.class);
        Assertions.assertThat(dto.getEvent()).isEqualTo(CredentialStatusTypeDto.ISSUED.name());
        Assertions.assertThat(dto.getEventType()).isEqualTo(CallbackEventTypeDto.VC_STATUS_CHANGED);
        // When triggered again, should not send a callback again
        // We need to enqueue a possible successful response, if we should receive a request
        mockWebServer.enqueue(new MockResponse().setResponseCode(200));
        triggerCallBackProcess(0);
        request = mockWebServer.takeRequest(100, TimeUnit.MILLISECONDS);
        Assertions.assertThat(request).isNull();
        consumeEnqueued(); // cleanup the mockWebServer

        // When multiple callbacks are there, should process all
        var num = 4;
        for (int i = 0; i < num; i++) {
            mockWebServer.enqueue(new MockResponse().setResponseCode(200));
            this.webhookEventProducer.produceOfferStateChangeEvent(UUID.randomUUID(), CredentialOfferStatusType.ISSUED);
        }
        this.webhookEventProcessor.triggerProcessCallback();
        for (int i = 0; i < num; i++) {
            // For each there should be a call to the webhook receiver
            request = mockWebServer.takeRequest(100, TimeUnit.MILLISECONDS);
            Assertions.assertThat(request).isNotNull();
        }

        // When triggered again, should not send a callback again
        mockWebServer.enqueue(new MockResponse().setResponseCode(200));
        this.webhookEventProcessor.triggerProcessCallback();
        request = mockWebServer.takeRequest(100, TimeUnit.MILLISECONDS);
        Assertions.assertThat(request).isNull();
        consumeEnqueued(); // cleanup the mockWebServer

        // If the server has an error we want to try again until success
        mockWebServer.enqueue(new MockResponse().setResponseCode(500));
        mockWebServer.enqueue(new MockResponse().setResponseCode(200));
        this.webhookEventProducer.produceOfferStateChangeEvent(UUID.randomUUID(), CredentialOfferStatusType.ISSUED);
        triggerCallBackProcess(1); // We received a message, but responded with 500
        triggerCallBackProcess(1); // We received a message, now responded with 200
        // test if error is logged
        assertThat(output.getAll()).contains("500 Internal Server Error from POST http://localhost:");
    }

    /**
     * Cleanup helper, preventing the need to restart the server to clear queue
     */
    private void consumeEnqueued() throws InterruptedException {
        this.webhookEventProducer.produceOfferStateChangeEvent(UUID.randomUUID(), CredentialOfferStatusType.ISSUED);
        triggerCallBackProcess(1);
        var request = mockWebServer.takeRequest(100, TimeUnit.MILLISECONDS);
        Assertions.assertThat(request).isNotNull();

    }

    private void triggerCallBackProcess(int numExpectedCallbacks) {
        var oldRequestCount = mockWebServer.getRequestCount();
        this.webhookEventProcessor.triggerProcessCallback();
        var newRequestCount = mockWebServer.getRequestCount();
        Assertions.assertThat(newRequestCount).isEqualTo(oldRequestCount + numExpectedCallbacks);
    }

    @AfterEach
    void reset() throws Exception {
        LogManager.getLogManager().readConfiguration();
    }
}