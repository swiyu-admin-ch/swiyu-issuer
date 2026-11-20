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
import ch.admin.bj.swiyu.issuer.common.logging.ResponseBodyLogFormatter;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.net.MalformedURLException;
import java.net.URI;

import static org.apache.commons.lang3.ObjectUtils.isEmpty;

/**
 * A service to interact with the status registry from the swiyu ecosystem.
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class StatusRegistryClient {

    private final StatusB2BApi statusB2BApi;
    private final StatusB2BV2Api statusB2BV2Api;
    private final SwiyuProperties swiyuProperties;
    private final UrlRewriteProperties urlRewriteProperties;
    private final ApplicationProperties applicationProperties;

    /**
     * Both generated API classes (v1 and v2) share the same {@link ApiClient} instance,
     * see {@link StatusRegistryConfig}. Base path and web client are therefore taken from one place.
     */
    private ApiClient apiClient() {
        return statusB2BApi.getApiClient();
    }

    /**
     * Creates a status list entry for the configured business partner
     *
     * @return response of the status registry
     */
    public StatusListEntryCreationDto createStatusListEntry() {

        var businessPartnerId = swiyuProperties.businessPartnerId();

        var client = apiClient();

        log.debug("Creating status list entry for business partner id {} on {}", businessPartnerId, client.getBasePath());

        try {
            return statusB2BApi
                    .createStatusListEntry(businessPartnerId)
                    .block();
        } catch (WebClientResponseException e) {
            log.error("Failed to create status list entry for business partner id {} on {} - registry responded with {}",
                    businessPartnerId, client.getBasePath(), ResponseBodyLogFormatter.describe(e), e);
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new ConfigurationException(
                        "Failed to create status list - Please check your Swiyu Status API access configuration.",
                        e);
            } else if (e.getStatusCode() == HttpStatus.FORBIDDEN) {
                throw new ConfigurationException(
                        String.format("Failed to create status list for business partner %s.", businessPartnerId), e);
            }
            throw new CreateStatusListException(
                    String.format("Failed to create status list. External system %s responded with: %s.",
                            apiClient().getBasePath(), e.getStatusCode()),
                    e);
        } catch (Exception e) {
            log.error("Failed to create status list entry for business partner id {} on {}",
                    businessPartnerId, client.getBasePath(), e);
            throw new CreateStatusListException("Failed to create status list", e);
        }
    }

    public void updateStatusListEntry(StatusList target, String statusListJWT) {

        try {
            log.debug("Updating status list entry {} for business partner id {} on {}", target.getUri(),
                    swiyuProperties.businessPartnerId(),
                    apiClient().getBasePath());
            statusB2BV2Api.updateStatusListEntry(
                            swiyuProperties.businessPartnerId(),
                            target.getRegistryId(),
                            statusListJWT)
                    .block();
        } catch (WebClientResponseException e) {
            var registryId = target.getRegistryId();
            var basePath = apiClient().getBasePath();
            switch (e.getStatusCode()) {
                case HttpStatus.UNAUTHORIZED -> {
                    log.error("Failed to update status list {} - unauthorized. Check Swiyu Status API access configuration. Registry responded with {}", registryId, ResponseBodyLogFormatter.describe(e), e);
                    throw new ConfigurationException(
                            "Failed to update status list - Please check your Swiyu Status API access configuration.",
                            e);
                }
                case HttpStatus.FORBIDDEN -> {
                    log.error("Failed to update status list {} - forbidden for business partner {}. Registry responded with {}", registryId, swiyuProperties.businessPartnerId(), ResponseBodyLogFormatter.describe(e), e);
                    throw new ConfigurationException(
                            String.format(
                                    "Failed to update status list - the status list %s does not belong to swiyu partner %s.",
                                    registryId,
                                    swiyuProperties.businessPartnerId()),
                            e);
                }
                case HttpStatus.NOT_FOUND -> {
                    log.error("Failed to update status list {} - not found on swiyu status registry. Registry responded with {}", registryId, ResponseBodyLogFormatter.describe(e), e);
                    throw new UpdateStatusListException(
                            String.format(
                                    "Failed to update status list - status list %s not found on swiyu status registry",
                                    registryId),
                            e);
                }
                default -> {
                    log.error("Failed to update status list {} - external system {} responded with {}", registryId, basePath, ResponseBodyLogFormatter.describe(e), e);
                    throw new UpdateStatusListException(
                            String.format("Failed to update status list. External system %s responded with: %s",
                                    basePath,
                                    e.getStatusCode()),
                            e);
                }
            }
        } catch (Exception e) {
            log.error("Failed to update status list {}.", target.getRegistryId(), e);
            throw new UpdateStatusListException(
                    "Failed to update status list.", e);
        }
    }

    /**
     * Resolve Status Lists, skipping verification where the status is from. Should only be used
     *
     * @param uri
     * @return
     */
    public String resolveStatusList(String uri) {
        var rewrittenUrl = urlRewriteProperties.getRewrittenUrl(uri);
        var statusListWebClient = apiClient().getWebClient();
        log.debug("HTTP Request after url rewrite to status list from {}", rewrittenUrl);
        try {
            // check if https request otherwise throw exception
            if (!isHttpsUrl(uri)) {
                throw new IllegalArgumentException("StatusList %s does not use HTTPS"
                        .formatted(uri));
            }
            if (!containsValidHost(rewrittenUrl)) {
                throw new IllegalArgumentException("StatusList %s does not contain a valid host from %s"
                        .formatted(rewrittenUrl, applicationProperties.getAcceptedRegistryHosts()));
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Malformed URL %s in StatusList".formatted(rewrittenUrl), e);
        }

        String result;
        try {
            result = statusListWebClient
                    .get()
                    .uri(rewrittenUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
        } catch (WebClientRequestException e) {
            // e.g. connection refused, timeout or DNS failure
            log.error("Error while fetching status list from {}: {}", rewrittenUrl, e.getMessage());
            throw new StatusListFetchFailedException(
                    "Status list with uri: %s could not be retrieved".formatted(rewrittenUrl), e);
        } catch (WebClientResponseException e) {
            if (e.getCause() != null && e.getCause().toString().contains("DataBufferLimitException")) {
                throw new StatusListFetchFailedException(
                        "Status list size from %s exceeds maximum allowed size".formatted(rewrittenUrl), e);
            }
            log.error("Error while fetching status list from {}: {}", rewrittenUrl, ResponseBodyLogFormatter.describe(e));
            throw new StatusListFetchFailedException(
                    "Status list with uri: %s could not be retrieved".formatted(rewrittenUrl), e);
        }

        if (result == null) {
            throw new StatusListFetchFailedException(
                    "Status list with uri: %s returned an empty response".formatted(rewrittenUrl));
        }
        return result;
    }

    private boolean isHttpsUrl(String url) {
        return url.startsWith("https://");
    }

    private boolean containsValidHost(String rewrittenUrl) throws MalformedURLException {

        var acceptedStatusListHosts = applicationProperties.getAcceptedRegistryHosts();
        var url = URI.create(rewrittenUrl).toURL();

        if (isEmpty(acceptedStatusListHosts)) {
            return true;
        }

        return applicationProperties.getAcceptedRegistryHosts().contains(url.getHost());
    }
}