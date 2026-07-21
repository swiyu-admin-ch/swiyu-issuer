package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.CreateStatusListException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.common.exception.UpdateStatusListException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.net.MalformedURLException;
import java.net.URI;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import static org.apache.commons.lang3.ObjectUtils.isEmpty;

/**
 * A service to interact with the status registry from the swiyu ecosystem.
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class StatusRegistryClient {

    private final StatusBusinessApiApi statusBusinessApi;
    private final SwiyuProperties swiyuProperties;
    private final UrlRewriteProperties urlRewriteProperties;
    private final ApplicationProperties applicationProperties;

    /**
     * Creates a status list entry for the configured business partner
     *
     * @return response of the status registry
     */
    public StatusListEntryCreationDto createStatusListEntry() {

        var businessPartnerId = swiyuProperties.businessPartnerId();

        var client = statusBusinessApi.getApiClient();

        log.debug("Creating status list entry for business partner id {} on {}", businessPartnerId, client.getBasePath());

        try {
            return statusBusinessApi
                    .createStatusListEntry(businessPartnerId)
                    .block();
        } catch (WebClientResponseException e) {
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
                            statusBusinessApi.getApiClient().getBasePath(), e.getStatusCode()),
                    e);
        } catch (ConfigurationException e) {
            throw e;
        } catch (Exception e) {
            throw new CreateStatusListException("Failed to create status list", e);
        }
    }

    public void updateStatusListEntry(StatusList target, String statusListJWT) {

        try {
            log.debug("Updating status list entry {} for business partner id {} on {}", target.getUri(), swiyuProperties.businessPartnerId(), statusBusinessApi.getApiClient().getBasePath());
            statusBusinessApi.updateStatusListEntry(
                            swiyuProperties.businessPartnerId(),
                            target.getRegistryId(),
                            statusListJWT)
                    .block();
        } catch (HttpClientErrorException e) {

            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                log.error("Failed to update status list {} - unauthorized. Check Swiyu Status API access configuration.", target.getRegistryId(), e);
                throw new ConfigurationException(
                        "Failed to update status list - Please check your Swiyu Status API access configuration.",
                        e);
            } else if (e.getStatusCode() == HttpStatus.FORBIDDEN) {
                log.error("Failed to update status list {} - forbidden for business partner {}.", target.getRegistryId(), swiyuProperties.businessPartnerId(), e);
                throw new ConfigurationException(
                        String.format(
                                "Failed to update status list - the status list %s does not belong to swiyu partner %s.",
                                target.getRegistryId(),
                                swiyuProperties.businessPartnerId()),
                        e);
            } else if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                log.error("Failed to update status list {} - not found on swiyu status registry.", target.getRegistryId(), e);
                throw new ResourceNotFoundException(
                        String.format(
                                "Failed to update status list - does the status list %s exist on swiyu status registry?",
                                target.getRegistryId()),
                        e);
            }
            log.error("Failed to update status list {} - external system {} responded with: {}.", target.getRegistryId(), statusBusinessApi.getApiClient().getBasePath(), e.getStatusCode(), e);
            throw new UpdateStatusListException(
                    String.format("Failed to update status list. External system %s responded with: %s",
                            statusBusinessApi.getApiClient().getBasePath(),
                            e.getStatusCode()),
                    e);
        } catch (Exception e) {
            log.error("Failed to update status list {}.", target.getRegistryId(), e);
            throw new UpdateStatusListException(
                    "Failed to update status list.", e);
        }
    }

    /**
     * Resolve Status Lists, skipping verification where the status is from. Should only be used
     * @param uri
     * @return
     */
    public String resolveStatusList(String uri) {
        var rewrittenUrl = urlRewriteProperties.getRewrittenUrl(uri);
        var statusListWebClient = statusBusinessApi.getApiClient().getWebClient();       
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

        var result = statusListWebClient
                .get()
                .uri(rewrittenUrl)
                .retrieve()
                .onStatus(status -> status != HttpStatusCode.valueOf(200), response ->
                        Mono.error(new StatusListFetchFailedException(
                                "Status list with uri: %s could not be retrieved".formatted(rewrittenUrl))))
                .bodyToMono(String.class)
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getCause().toString().contains("DataBufferLimitException")) {
                        return Mono.error(new StatusListFetchFailedException(
                                "Status list size from %s exceeds maximum allowed size".formatted(rewrittenUrl)));
                    }
                    log.error("Error while fetching status list from {}: {}", rewrittenUrl, ex.getMessage());
                    return Mono.error(new StatusListFetchFailedException(
                            "Status list with uri: %s could not be retrieved".formatted(rewrittenUrl)));
                })
                .block();

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