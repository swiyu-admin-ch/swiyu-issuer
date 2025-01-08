package ch.admin.bj.swiyu.issuer.management.service.statusregistry;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.management.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.management.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.management.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

/**
 * A service to interact with the status registry from the swiyu ecosystem.
 */
@RequiredArgsConstructor
@Service
public class StatusRegistryClient {

    private final SwiyuProperties swiyuProperties;
    private final StatusBusinessApiApi statusBusinessApi;

    public StatusListEntryCreationDto createStatusList() {

        var businessPartnerId = swiyuProperties.businessPartnerId();
        try {
            return statusBusinessApi.createStatusListEntry(businessPartnerId);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new ResourceNotFoundException("Failed to create status list. Please check your Swiyu Status API access configuration.", e);
            } else if (e.getStatusCode() == HttpStatus.FORBIDDEN) {
                throw new ResourceNotFoundException(String.format("Failed to create status list for business partner %s.", businessPartnerId), e);
            }
            throw new ConfigurationException(String.format("Failed to create status list. External system %s responded with: %s.", statusBusinessApi.getApiClient().getBasePath(), e.getStatusCode()), e);
        } catch (Exception e) {
            throw new ConfigurationException("Failed to create status list", e);
        }
    }

    public void updateStatusList(StatusList target, String statusListJWT) {

        try {
            statusBusinessApi.updateStatusListEntry(
                    swiyuProperties.businessPartnerId(),
                    target.getRegistryId(),
                    statusListJWT);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new ResourceNotFoundException(
                        "Failed to update status list - Please check your Swiyu Status API access configuration.",
                        e);
            } else if (e.getStatusCode() == HttpStatus.FORBIDDEN) {
                throw new ResourceNotFoundException(
                        String.format("Failed to update status list - the status list %s does not belong to swiyu partner %s.",
                                target.getRegistryId(),
                                swiyuProperties.businessPartnerId()),
                        e);
            } else if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                throw new ResourceNotFoundException(
                        String.format("Failed to update status list - does the status list %s exist on swiyu status registry?",
                                target.getRegistryId()),
                        e);
            }
            throw new ConfigurationException(
                    String.format("Failed to update status list. External system %s responded with: %s",
                            statusBusinessApi.getApiClient().getBasePath(),
                            e.getStatusCode()),
                    e);
        } catch (Exception e) {
            throw new ConfigurationException(
                    "Failed to update status list.",
                    e);
        }
    }
}
