package ch.admin.bit.eid.issuer_management.controllers;

import ch.admin.bit.eid.issuer_management.models.dto.StatusListCreateDto;
import ch.admin.bit.eid.issuer_management.services.StatusListService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(value = "/status-list")
@AllArgsConstructor
@Tag(name = "Status List API")
public class StatusListController {

    private final StatusListService statusListService;

    @PostMapping("")
    @Operation(summary = "Initialize a new status list.", description = "Initialize and link a status list slot to to this service. This process can be only done once per status list! Status List type, configuration or length can not be changed after initialization!")
    public void createStatusList(@Valid  @RequestBody StatusListCreateDto request) {
        this.statusListService.createStatusList(request);
    }


}
