package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.management.service.StatusListService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Deprecated(since = "0.1.3-SNAPSHOT", forRemoval = true)
@Slf4j
@RestController
@RequestMapping(value = {"/status-list"})
@AllArgsConstructor
@Tag(name = "Status List", description = "Status List Management API")
public class DeprecatedStatusListController {

    private final StatusListService statusListService;

    @PostMapping("")
    @Operation(summary = "Create and initialize a new status list.", description = "Initialize and link a status list slot to to this service. "
            +
            "This process can be only done once per status list! Status List type, " +
            "configuration or length can not be changed after initialization!")
    public StatusListDto createStatusList(@Valid @RequestBody StatusListCreateDto request) {
        return this.statusListService.createStatusList(request);
    }

    @GetMapping("/{statusListId}")
    @Operation(summary = "Get the status information of a status list.")
    public StatusListDto getStatusListInformation(@PathVariable UUID statusListId) {
        return this.statusListService.getStatusListInformation(statusListId);
    }
}
