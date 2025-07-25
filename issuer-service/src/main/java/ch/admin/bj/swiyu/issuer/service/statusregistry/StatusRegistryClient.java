/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.CreateStatusListException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.common.exception.UpdateStatusListException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

/**
 * A service to interact with the status registry from the swiyu ecosystem.
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class StatusRegistryClient {

    private final SwiyuProperties swiyuProperties;
    private final StatusBusinessApiApi statusBusinessApi;

    /**
     * Creates a status list entry for the configured business partner
     * @return response of the status registry
     */
    public StatusListEntryCreationDto createStatusListEntry() {

        var businessPartnerId = swiyuProperties.businessPartnerId();
        try {
            log.debug("Creating status list entry for business partner id {} on {}", businessPartnerId, statusBusinessApi.getApiClient().getBasePath());
            return statusBusinessApi.createStatusListEntry(businessPartnerId);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new ConfigurationException(
                        "Failed to create status list. Please check your Swiyu Status API access configuration.", e);
            } else if (e.getStatusCode() == HttpStatus.FORBIDDEN) {
                throw new ConfigurationException(
                        String.format("Failed to create status list for business partner %s.", businessPartnerId), e);
            }
            throw new CreateStatusListException(
                    String.format("Failed to create status list. External system %s responded with: %s.",
                            statusBusinessApi.getApiClient().getBasePath(), e.getStatusCode()),
                    e);
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
                    statusListJWT);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new ConfigurationException(
                        "Failed to update status list - Please check your Swiyu Status API access configuration.",
                        e);
            } else if (e.getStatusCode() == HttpStatus.FORBIDDEN) {
                throw new ConfigurationException(
                        String.format(
                                "Failed to update status list - the status list %s does not belong to swiyu partner %s.",
                                target.getRegistryId(),
                                swiyuProperties.businessPartnerId()),
                        e);
            } else if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                throw new ResourceNotFoundException(
                        String.format(
                                "Failed to update status list - does the status list %s exist on swiyu status registry?",
                                target.getRegistryId()),
                        e);
            }
            throw new UpdateStatusListException(
                    String.format("Failed to update status list. External system %s responded with: %s",
                            statusBusinessApi.getApiClient().getBasePath(),
                            e.getStatusCode()),
                    e);
        } catch (Exception e) {
            throw new UpdateStatusListException(
                    "Failed to update status list.",
                    e);
        }
    }
}
