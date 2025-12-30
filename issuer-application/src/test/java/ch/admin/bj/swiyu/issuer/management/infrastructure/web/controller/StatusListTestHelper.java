package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.api.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListConfigDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListTypeDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class StatusListTestHelper {

    public static final String BASE_URL = "/management/api/status-list";
    public static final String STATUS_REGISTRY_URL_TEMPLATE = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt";

    private final MockMvc mvc;
    private final ObjectMapper objectMapper;

    public StatusListTestHelper(MockMvc mvc,
                                ObjectMapper objectMapper) {
        this.mvc = mvc;
        this.objectMapper = objectMapper;
    }

    public StatusListDto createStatusList(final StatusListTypeDto statusListTypeDto, final int length, final String purpose,
                                          final int bits, final String issuerDid, final String verificationMethod, final String keyId,
                                          final String keyPin) throws Exception {
        final ConfigurationOverrideDto configurationOverrideDto = new ConfigurationOverrideDto(issuerDid, verificationMethod, keyId, keyPin);

        final StatusListCreateDto statusListCreateDto = StatusListCreateDto.builder()
                .type(statusListTypeDto)
                .maxLength(length)
                .config(StatusListConfigDto.builder().purpose(purpose).bits(bits).build())
                .configurationOverride(configurationOverrideDto)
                .build();

        final MvcResult result = mvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(statusListCreateDto)))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readValue(result.getResponse().getContentAsByteArray(), StatusListDto.class);
    }

    public StatusListEntryCreationDto buildStatusListEntryById(final UUID statusRegistryId) {
        final String newStatusRegistryUrl = STATUS_REGISTRY_URL_TEMPLATE.formatted(statusRegistryId);

        final StatusListEntryCreationDto statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusRegistryId);
        statusListEntryCreationDto.setStatusRegistryUrl(newStatusRegistryUrl);

        return statusListEntryCreationDto;
    }

    public StatusListEntryCreationDto buildStatusListEntry() {
        return buildStatusListEntryById(UUID.randomUUID());
    }
}