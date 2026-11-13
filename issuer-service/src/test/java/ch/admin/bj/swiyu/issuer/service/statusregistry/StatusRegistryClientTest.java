package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusB2BApi;
import ch.admin.bj.swiyu.core.status.registry.client.api.StatusB2BV2Api;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.CreateStatusListException;
import ch.admin.bj.swiyu.issuer.common.exception.UpdateStatusListException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class StatusRegistryClientTest {

    private static final String TEST_URI = "https://example.com/";
    private StatusB2BApi statusBusinessApi;
    private StatusB2BV2Api statusBusinessV2Api;
    private SwiyuProperties swiyuProperties;
    private UrlRewriteProperties rewriteProperties;
    private ApplicationProperties applicationProperties;
    private StatusRegistryTokenService tokenDomainService;
    private StatusRegistryClient client;
    private ApiClient apiClient;
    private ListAppender<ILoggingEvent> logAppender;
    private Logger clientLogger;

    private String logs() {
        return logAppender.list.stream().map(ILoggingEvent::getFormattedMessage).reduce("", (a, b) -> a + "\n" + b);
    }

    private static WebClientResponseException registryError(HttpStatus status, String body) {
        return WebClientResponseException.create(status.value(), status.getReasonPhrase(), HttpHeaders.EMPTY,
                body == null ? null : body.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    private StatusList statusList() {
        return StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/" + UUID.randomUUID()).build();
    }

    @AfterEach
    void tearDown() {
        clientLogger.detachAppender(logAppender);
    }

    @BeforeEach
    void setUp() {
        swiyuProperties = Mockito.mock(SwiyuProperties.class);
        when(swiyuProperties.businessPartnerId()).thenReturn(UUID.randomUUID());
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        when(applicationProperties.getAcceptedRegistryHosts()).thenReturn(List.of(TEST_URI));
        rewriteProperties = Mockito.mock(UrlRewriteProperties.class);
        // Return unaltered URL
        when(rewriteProperties.getRewrittenUrl(anyString())).thenAnswer(a -> a.getArguments()[0]);


        statusBusinessApi = Mockito.mock(StatusB2BApi.class);
        statusBusinessV2Api = Mockito.mock(StatusB2BV2Api.class);
        apiClient = Mockito.mock(ApiClient.class);
        when(statusBusinessApi.getApiClient()).thenReturn(apiClient);

        clientLogger = (Logger) LoggerFactory.getLogger(StatusRegistryClient.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        clientLogger.addAppender(logAppender);

        tokenDomainService = Mockito.mock(StatusRegistryTokenService.class);
        when(tokenDomainService.getAccessToken()).thenReturn("access-token");

        client = new StatusRegistryClient(statusBusinessApi, statusBusinessV2Api, swiyuProperties, rewriteProperties, applicationProperties);
    }

    @Test
    void createStatusListEntry_success_returnsDto() {
        var expected = new StatusListEntryCreationDto().id(UUID.randomUUID()).statusRegistryUrl("https://example.com/entry");
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(Mono.just(expected));

        var result = client.createStatusListEntry();

        assertThat(result).isEqualTo(expected);
        verify(statusBusinessApi).createStatusListEntry(swiyuProperties.businessPartnerId());
    }

    @Test
    void createStatusListEntry_unauthorized_throwsConfigurationException() {
        var ex = WebClientResponseException.create(HttpStatus.UNAUTHORIZED.value(), "Unauthorized", HttpHeaders.EMPTY, null, null);
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(Mono.error(ex)).thenReturn(Mono.error(ex));

        assertThrows(ConfigurationException.class, () -> client.createStatusListEntry());
    }

    @Test
    void createStatusListEntry_forbidden_throwsConfigurationException() {
        var ex = WebClientResponseException.create(HttpStatus.FORBIDDEN.value(), "Forbidden", HttpHeaders.EMPTY, null, null);
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(Mono.error(ex));

        assertThrows(ConfigurationException.class, () -> client.createStatusListEntry());
    }

    @Test
    void createStatusListEntry_otherError_throwsCreateStatusListException() {
        var ex = WebClientResponseException.create(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Error", HttpHeaders.EMPTY, null, null);
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(Mono.error(ex));

        assertThrows(CreateStatusListException.class, () -> client.createStatusListEntry());
    }

    @Test
    void updateStatusListEntry_success_callsApi() {
        StatusList list = StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/" + UUID.randomUUID()).build();
        String jwt = "signedJwt";

        // no exception expected
        when(statusBusinessV2Api.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.empty());

        client.updateStatusListEntry(list, jwt);

        ArgumentCaptor<UUID> bpCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<UUID> idCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        verify(statusBusinessV2Api).updateStatusListEntry(bpCaptor.capture(), idCaptor.capture(), jwtCaptor.capture());
        assertThat(bpCaptor.getValue()).isEqualTo(swiyuProperties.businessPartnerId());
        assertThat(idCaptor.getValue()).isEqualTo(list.getRegistryId());
        assertThat(jwtCaptor.getValue()).isEqualTo(jwt);
    }

    @Test
    void createStatusListEntry_serverErrorWithBody_logsStatusAndBody() {
        var ex = registryError(HttpStatus.SERVICE_UNAVAILABLE, "{\"error\":\"registry down\"}");
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(Mono.error(ex));

        assertThrows(CreateStatusListException.class, () -> client.createStatusListEntry());

        assertThat(logs()).contains("status=503").contains("{\"error\":\"registry down\"}");
    }

    @Test
    void createStatusListEntry_clientErrorWithBody_logsStatusAndBody() {
        var ex = registryError(HttpStatus.BAD_REQUEST, "invalid partner");
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(Mono.error(ex));

        assertThrows(CreateStatusListException.class, () -> client.createStatusListEntry());

        assertThat(logs()).contains("status=400").contains("invalid partner");
    }

    @Test
    void createStatusListEntry_connectionError_logsErrorAndThrowsCreateStatusListException() {
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(Mono.error(new IllegalStateException("connection refused")));

        assertThrows(CreateStatusListException.class, () -> client.createStatusListEntry());

        assertThat(logs()).contains("Failed to create status list entry");
    }

    @Test
    void createStatusListEntry_emptyBody_logsEmptyHint() {
        var ex = registryError(HttpStatus.INTERNAL_SERVER_ERROR, "");
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(Mono.error(ex));

        assertThrows(CreateStatusListException.class, () -> client.createStatusListEntry());

        assertThat(logs()).contains("status=500").contains("<empty body>");
    }

    @Test
    void createStatusListEntry_unauthorizedAndForbidden_logStatusAndBody() {
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(Mono.error(registryError(HttpStatus.UNAUTHORIZED, "bad token")));
        assertThrows(ConfigurationException.class, () -> client.createStatusListEntry());
        assertThat(logs()).contains("status=401").contains("bad token");

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(Mono.error(registryError(HttpStatus.FORBIDDEN, "no access")));
        assertThrows(ConfigurationException.class, () -> client.createStatusListEntry());
        assertThat(logs()).contains("status=403").contains("no access");
    }

    @Test
    void updateStatusListEntry_unauthorized_throwsConfigurationException() {
        var list = statusList();
        when(statusBusinessV2Api.updateStatusListEntry(any(), any(), any()))
                .thenReturn(Mono.error(registryError(HttpStatus.UNAUTHORIZED, "token expired")));

        assertThrows(ConfigurationException.class, () -> client.updateStatusListEntry(list, "jwt"));
        assertThat(logs()).contains("status=401").contains("token expired");
    }

    @Test
    void updateStatusListEntry_forbidden_throwsConfigurationException_withMessage() {
        var list = statusList();
        when(statusBusinessV2Api.updateStatusListEntry(any(), any(), any()))
                .thenReturn(Mono.error(registryError(HttpStatus.FORBIDDEN, "not your list")));

        var ex = assertThrows(ConfigurationException.class, () -> client.updateStatusListEntry(list, "jwt"));
        // message should contain business partner id and registry id
        assertThat(ex.getMessage()).contains(list.getRegistryId().toString()).contains(swiyuProperties.businessPartnerId().toString());
        assertThat(logs()).contains("status=403").contains("not your list");
    }

    @Test
    void updateStatusListEntry_notFound_throwsUpdateStatusListException() {
        var list = statusList();
        when(statusBusinessV2Api.updateStatusListEntry(any(), any(), any()))
                .thenReturn(Mono.error(registryError(HttpStatus.NOT_FOUND, "no such list")));

        var ex = assertThrows(UpdateStatusListException.class, () -> client.updateStatusListEntry(list, "jwt"));
        assertThat(ex.getMessage()).contains(list.getRegistryId().toString()).contains("not found");
        assertThat(ex.getCause()).isInstanceOf(WebClientResponseException.class);
        assertThat(logs()).contains("status=404").contains("no such list");
    }

    @Test
    void updateStatusListEntry_otherHttpError_throwsUpdateStatusListException() {
        var list = statusList();
        when(statusBusinessV2Api.updateStatusListEntry(any(), any(), any()))
                .thenReturn(Mono.error(registryError(HttpStatus.BAD_REQUEST, "invalid jwt payload")));

        assertThrows(UpdateStatusListException.class, () -> client.updateStatusListEntry(list, "secret-jwt"));
        assertThat(logs()).contains("status=400").contains("invalid jwt payload").doesNotContain("secret-jwt");
    }

    @Test
    void updateStatusListEntry_unprocessableEntityEmptyBody_logsEmptyHint() {
        var list = statusList();
        when(statusBusinessV2Api.updateStatusListEntry(any(), any(), any()))
                .thenReturn(Mono.error(registryError(HttpStatus.UNPROCESSABLE_ENTITY, null)));

        assertThrows(UpdateStatusListException.class, () -> client.updateStatusListEntry(list, "jwt"));
        assertThat(logs()).contains("status=422").contains("<empty body>");
    }

    @Test
    void updateStatusListEntry_veryLongBody_isTruncated() {
        var list = statusList();
        var body = "x".repeat(10_000);
        when(statusBusinessV2Api.updateStatusListEntry(any(), any(), any()))
                .thenReturn(Mono.error(registryError(HttpStatus.BAD_GATEWAY, body)));

        assertThrows(UpdateStatusListException.class, () -> client.updateStatusListEntry(list, "jwt"));
        assertThat(logs()).contains("status=502").contains("x".repeat(2000)).doesNotContain("x".repeat(2001)).contains("truncated");
    }

    @Test
    void updateStatusListEntry_nonUtf8Body_doesNotFailWhileLogging() {
        var list = statusList();
        var ex = WebClientResponseException.create(HttpStatus.BAD_REQUEST.value(), "Bad Request", HttpHeaders.EMPTY,
                new byte[]{(byte) 0xff, (byte) 0xfe, (byte) 0xfd}, Charset.forName("UTF-8"));
        when(statusBusinessV2Api.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.error(ex));

        assertThrows(UpdateStatusListException.class, () -> client.updateStatusListEntry(list, "jwt"));
        assertThat(logs()).contains("status=400");
    }

    @Test
    void updateStatusListEntry_otherException_throwsUpdateStatusListException() {
        StatusList list = StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/" + UUID.randomUUID()).build();
        String jwt = "jwt";
        doThrow(new RuntimeException("boom")).when(statusBusinessV2Api).updateStatusListEntry(any(), any(), any());

        assertThrows(UpdateStatusListException.class, () -> client.updateStatusListEntry(list, jwt));
    }

    @Test
    void resolveStatusList_notFoundWithBody_logsStatusAndBody() {
        var webClient = WebClient.builder().exchangeFunction(req ->
                Mono.just(ClientResponse.create(HttpStatus.NOT_FOUND).body("list gone").build())).build();
        when(apiClient.getWebClient()).thenReturn(webClient);
        when(applicationProperties.getAcceptedRegistryHosts()).thenReturn(List.of("example.com"));

        assertThrows(StatusListFetchFailedException.class, () -> client.resolveStatusList(TEST_URI + "list"));
        assertThat(logs()).contains("status=404").contains("list gone");
    }

    @Test
    void resolveStatusList_serverErrorEmptyBody_logsEmptyHint() {
        var webClient = WebClient.builder().exchangeFunction(req ->
                Mono.just(ClientResponse.create(HttpStatus.INTERNAL_SERVER_ERROR).build())).build();
        when(apiClient.getWebClient()).thenReturn(webClient);
        when(applicationProperties.getAcceptedRegistryHosts()).thenReturn(List.of("example.com"));

        assertThrows(StatusListFetchFailedException.class, () -> client.resolveStatusList(TEST_URI + "list"));
        assertThat(logs()).contains("status=500").contains("<empty body>");
    }
}
