/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web.management;

import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListOrchestrator;
import io.micrometer.core.annotation.Timed;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping(value = {"/management/api/status-list"})
@AllArgsConstructor
@Tag(name = "Status List API", description = "Exposes API endpoints for managing status lists used in verifiable " +
        "credential status tracking. Supports creating and initializing new status lists and retrieving status list " +
        "information by ID. Ensures status list configuration is immutable after initialization. (IF-113)")
public class StatusListController {

    private final StatusListOrchestrator statusListOrchestrator;
    private final ApplicationProperties applicationProperties;

    @Timed
    @PostMapping("")
    @Operation(summary = "Create and initialize a new status list.", description = "Initialize and link a status list slot to to this service. "
            +
            "This process can be only done once per status list! Status List type, " +
            "configuration or length can not be changed after initialization!")
    public StatusListDto createStatusList(@Valid @RequestBody StatusListCreateDto request) {
        return this.statusListOrchestrator.createStatusList(request);
    }

    @Timed
    @GetMapping("/{statusListId}")
    @Operation(summary = "Get the status information of a status list.")
    public StatusListDto getStatusListInformation(@PathVariable UUID statusListId) {
        return this.statusListOrchestrator.getStatusListInformation(statusListId);
    }

    @Timed
    @PostMapping("/{statusListId}")
    @Operation(summary = "Update the status list registry entry manually.",
            description = "Update the status list registry entry manually. This endpoint is only available when " +
                    "automatic status list synchronization is disabled in the application configuration.")
    public StatusListDto updateStatusListRegistryEntry(@PathVariable UUID statusListId) {
        if (!applicationProperties.isAutomaticStatusListSynchronizationDisabled()) {
            throw new ConfigurationException("Automatic status list synchronization is enabled. Manual update via API is disabled.");
        }
        return this.statusListOrchestrator.updateStatusList(statusListId);
    }
}