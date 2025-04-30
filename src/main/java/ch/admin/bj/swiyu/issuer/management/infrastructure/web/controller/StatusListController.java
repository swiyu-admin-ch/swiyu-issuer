/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.management.service.StatusListService;
import io.micrometer.core.annotation.Timed;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping(value = {"/api/v1/status-list"})
@AllArgsConstructor
@Tag(name = "Status List", description = "Status List Management API")
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
