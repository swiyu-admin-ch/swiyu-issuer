// ...existing code...
package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.CreateStatusListException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.common.exception.UpdateStatusListException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class StatusRegistryClientTest {

    private SwiyuProperties swiyuProperties;
    private StatusBusinessApiApi statusBusinessApi;
    private StatusRegistryTokenDomainService tokenDomainService;
    private StatusRegistryClient client;
    private ApiClient apiClient;

    @BeforeEach
    void setUp() {
        swiyuProperties = Mockito.mock(SwiyuProperties.class);
        when(swiyuProperties.businessPartnerId()).thenReturn(UUID.randomUUID());

        statusBusinessApi = Mockito.mock(StatusBusinessApiApi.class);
        apiClient = Mockito.mock(ApiClient.class);
        when(statusBusinessApi.getApiClient()).thenReturn(apiClient);

        tokenDomainService = Mockito.mock(StatusRegistryTokenDomainService.class);
        when(tokenDomainService.getAccessToken()).thenReturn("access-token");

        client = new StatusRegistryClient(swiyuProperties, statusBusinessApi, tokenDomainService);
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
        when(statusBusinessApi.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.empty());

        client.updateStatusListEntry(list, jwt);

        ArgumentCaptor<UUID> bpCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<UUID> idCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        verify(statusBusinessApi).updateStatusListEntry(bpCaptor.capture(), idCaptor.capture(), jwtCaptor.capture());
        assertThat(bpCaptor.getValue()).isEqualTo(swiyuProperties.businessPartnerId());
        assertThat(idCaptor.getValue()).isEqualTo(list.getRegistryId());
        assertThat(jwtCaptor.getValue()).isEqualTo(jwt);
    }

    @Test
    void updateStatusListEntry_unauthorized_throwsConfigurationException() {
        StatusList list = StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/" + UUID.randomUUID()).build();
        String jwt = "jwt";
        doThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED)).when(statusBusinessApi).updateStatusListEntry(any(), any(), any());

        assertThrows(ConfigurationException.class, () -> client.updateStatusListEntry(list, jwt));
    }

    @Test
    void updateStatusListEntry_forbidden_throwsConfigurationException_withMessage() {
        StatusList list = StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/" + UUID.randomUUID()).build();
        String jwt = "jwt";
        doThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN)).when(statusBusinessApi).updateStatusListEntry(any(), any(), any());

        var ex = assertThrows(ConfigurationException.class, () -> client.updateStatusListEntry(list, jwt));
        // message should contain business partner id and registry id
        assertThat(ex.getMessage()).contains(list.getRegistryId().toString()).contains(swiyuProperties.businessPartnerId().toString());
    }

    @Test
    void updateStatusListEntry_notFound_throwsResourceNotFoundException() {
        StatusList list = StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/" + UUID.randomUUID()).build();
        String jwt = "jwt";
        doThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND)).when(statusBusinessApi).updateStatusListEntry(any(), any(), any());

        assertThrows(ResourceNotFoundException.class, () -> client.updateStatusListEntry(list, jwt));
    }

    @Test
    void updateStatusListEntry_otherHttpError_throwsUpdateStatusListException() {
        StatusList list = StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/" + UUID.randomUUID()).build();
        String jwt = "jwt";
        doThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST)).when(statusBusinessApi).updateStatusListEntry(any(), any(), any());

        assertThrows(UpdateStatusListException.class, () -> client.updateStatusListEntry(list, jwt));
    }

    @Test
    void updateStatusListEntry_otherException_throwsUpdateStatusListException() {
        StatusList list = StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/" + UUID.randomUUID()).build();
        String jwt = "jwt";
        doThrow(new RuntimeException("boom")).when(statusBusinessApi).updateStatusListEntry(any(), any(), any());

        assertThrows(UpdateStatusListException.class, () -> client.updateStatusListEntry(list, jwt));
    }
}