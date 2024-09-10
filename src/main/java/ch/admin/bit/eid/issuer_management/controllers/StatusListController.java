package ch.admin.bit.eid.issuer_management.controllers;

import ch.admin.bit.eid.issuer_management.models.dto.StatusListCreateDto;
import ch.admin.bit.eid.issuer_management.services.StatusListService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/status-list")
@AllArgsConstructor
public class StatusListController {

    private final StatusListService service;

    @PostMapping("")
    @Operation(summary = "Create a new status list.")
    public void createStatusList(@Valid @RequestBody StatusListCreateDto statusListCreateDto) {
        service.createStatusList(statusListCreateDto);
    }
}
