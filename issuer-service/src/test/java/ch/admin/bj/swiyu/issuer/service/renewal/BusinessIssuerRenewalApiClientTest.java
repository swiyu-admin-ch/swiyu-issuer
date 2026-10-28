package ch.admin.bj.swiyu.issuer.service.renewal;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.RenewalException;
import ch.admin.bj.swiyu.issuer.dto.renewal.RenewalRequestDto;
import ch.admin.bj.swiyu.issuer.dto.renewal.RenewalResponseDto;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BusinessIssuerRenewalApiClientTest {

    private final String apiKeyHeader = "X-API-KEY";
    private final String apiKeyValue = "secret-key";
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

    @Mock
    private ApplicationProperties applicationProperties;
    @Mock
    private RenewalResponseDto responseDto;

    @Mock
    private Mono<RenewalResponseDto> responseMono;

    private RenewalRequestDto requestDto;

    private Logger clientLogger;
    private ListAppender<ILoggingEvent> logAppender;

    @InjectMocks
    private BusinessIssuerRenewalApiClient businessIssuerRenewalApiClient;

    @BeforeEach
    void setUp() {
        requestDto = new RenewalRequestDto(UUID.randomUUID(), UUID.randomUUID(), "");
        String apiEndpoint = "https://api.example.com/renewal";
        when(applicationProperties.getBusinessIssuerRenewalApiEndpoint()).thenReturn(apiEndpoint);

        // Configure WebClient behaviour
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(any(URI.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(any(Object.class))).thenReturn(requestHeaderSpec);
        when(requestHeaderSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.onStatus(any(), any())).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(RenewalResponseDto.class)).thenReturn(responseMono);
        when(responseMono.block()).thenReturn(responseDto);

        // Capture the logs of the client to assert the log level of a failed renewal
        clientLogger = (Logger) LoggerFactory.getLogger(BusinessIssuerRenewalApiClient.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        clientLogger.addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        clientLogger.detachAppender(logAppender);
        logAppender.stop();
    }

    @Test
    void getRenewalData_whenNoApiKey_thenNoApiKeyHeader() {
        businessIssuerRenewalApiClient.getRenewalData(requestDto);

        verify(requestBodySpec, times(0)).header(apiKeyHeader, apiKeyValue);
    }

    @Test
    void getRenewalData_whenApiKeySet_thenWrittenToHeader() {
        when(applicationProperties.getBusinessIssuerRenewalApiKeyHeader()).thenReturn(apiKeyHeader);
        when(applicationProperties.getBusinessIssuerRenewalApiKeyValue()).thenReturn(apiKeyValue);

        when(requestBodySpec.header(anyString(), anyString())).thenReturn(requestBodySpec);

        businessIssuerRenewalApiClient.getRenewalData(requestDto);

        verify(requestBodySpec, times(1)).header(apiKeyHeader, apiKeyValue);
    }

    /**
     * Status codes the business issuer may legitimately answer with must not be logged as errors.
     */
    @ParameterizedTest
    @ValueSource(ints = {404, 409, 420, 451, 500, 503})
    void getRenewalData_whenStatusCodeIsLoggedAsInfo_thenLogsInfo(int statusCode) {
        var renewalException = triggerErrorStatus(statusCode);

        assertThat(renewalException.getHttpStatus().value()).isEqualTo(statusCode);
        assertThat(logAppender.list).hasSize(1);
        var logEvent = logAppender.list.getFirst();
        assertThat(logEvent.getLevel()).isEqualTo(Level.INFO);
        assertThat(logEvent.getFormattedMessage()).contains("failed with status code %d".formatted(statusCode));
    }

    /**
     * All other error status codes must still be logged as errors.
     */
    @ParameterizedTest
    @ValueSource(ints = {400, 401, 502})
    void getRenewalData_whenStatusCodeIsNotLoggedAsInfo_thenLogsError(int statusCode) {
        var renewalException = triggerErrorStatus(statusCode);

        assertThat(renewalException.getHttpStatus().value()).isEqualTo(statusCode);
        assertThat(logAppender.list).hasSize(1);
        var logEvent = logAppender.list.getFirst();
        assertThat(logEvent.getLevel()).isEqualTo(Level.ERROR);
        assertThat(logEvent.getFormattedMessage()).contains("failed with status code %d".formatted(statusCode));
    }

    @Test
    void getRenewalData_whenRestClientExceptionWithInfoStatus_thenLogsInfo() {
        var restClientException = mock(RestClientResponseException.class);
        when(restClientException.getStatusCode()).thenReturn(HttpStatusCode.valueOf(503));
        when(restClientException.getMessage()).thenReturn("Service Unavailable");
        when(responseMono.block()).thenThrow(restClientException);

        assertThrows(RenewalException.class, () -> businessIssuerRenewalApiClient.getRenewalData(requestDto));

        assertThat(logAppender.list).hasSize(1);
        var logEvent = logAppender.list.getFirst();
        assertThat(logEvent.getLevel()).isEqualTo(Level.INFO);
        assertThat(logEvent.getFormattedMessage())
                .contains("failed with status code 503 SERVICE_UNAVAILABLE")
                .contains("with message Service Unavailable");
    }

    @Test
    void getRenewalData_whenRestClientExceptionWithErrorStatus_thenLogsError() {
        var restClientException = mock(RestClientResponseException.class);
        when(restClientException.getStatusCode()).thenReturn(HttpStatusCode.valueOf(400));
        when(restClientException.getMessage()).thenReturn("Bad Request");
        when(responseMono.block()).thenThrow(restClientException);

        assertThrows(RenewalException.class, () -> businessIssuerRenewalApiClient.getRenewalData(requestDto));

        assertThat(logAppender.list).hasSize(1);
        var logEvent = logAppender.list.getFirst();
        assertThat(logEvent.getLevel()).isEqualTo(Level.ERROR);
        assertThat(logEvent.getFormattedMessage())
                .contains("failed with status code 400 BAD_REQUEST")
                .contains("with message Bad Request");
    }

    /**
     * Runs a renewal request, invokes the error status handler registered on the {@link WebClient} response and
     * returns the resulting exception.
     */
    @SuppressWarnings("unchecked")
    private RenewalException triggerErrorStatus(int statusCode) {
        businessIssuerRenewalApiClient.getRenewalData(requestDto);

        var handlerCaptor = ArgumentCaptor.forClass(Function.class);
        verify(responseSpec).onStatus(any(), handlerCaptor.capture());
        Function<ClientResponse, Mono<? extends Throwable>> errorHandler = handlerCaptor.getValue();

        var clientResponse = mock(ClientResponse.class);
        when(clientResponse.statusCode()).thenReturn(HttpStatusCode.valueOf(statusCode));

        return assertThrows(RenewalException.class, () -> errorHandler.apply(clientResponse).block());
    }
}
