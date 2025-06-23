/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web.management;

import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.service.StatusListService;
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
@RequestMapping(value = {"/api/v1/private/status-list"})
@AllArgsConstructor
@Tag(name = "Status List API", description = "Exposes API endpoints for managing status lists used in verifiable " +
        "credential status tracking. Supports creating and initializing new status lists and retrieving status list " +
        "information by ID. Ensures status list configuration is immutable after initialization. (IF-113)")
public class StatusListController {

    private final StatusListService statusListService;

    @Timed
    @PostMapping("")
    @Operation(summary = "Create and initialize a new status list.", description = "Initialize and link a status list slot to to this service. "
            +
            "This process can be only done once per status list! Status List type, " +
            "configuration or length can not be changed after initialization!")
    public StatusListDto createStatusList(@Valid @RequestBody StatusListCreateDto request) {
        return this.statusListService.createStatusList(request);
    }

    @Timed
    @GetMapping("/{statusListId}")
    @Operation(summary = "Get the status information of a status list.")
    public StatusListDto getStatusListInformation(@PathVariable UUID statusListId) {
        return this.statusListService.getStatusListInformation(statusListId);
    }
}