package ch.admin.bj.swiyu.issuer.service.renewal;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.dto.renewal.RenewalRequestDto;
import ch.admin.bj.swiyu.issuer.dto.renewal.RenewalResponseDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BusinessIssuerRenewalApiClientTest {

    private final String apiEndpoint = "https://api.example.com/renewal";
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

    @InjectMocks
    private BusinessIssuerRenewalApiClient businessIssuerRenewalApiClient;

    @BeforeEach
    void setUp() {
        requestDto = new RenewalRequestDto(UUID.randomUUID(), UUID.randomUUID(), "");
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
}