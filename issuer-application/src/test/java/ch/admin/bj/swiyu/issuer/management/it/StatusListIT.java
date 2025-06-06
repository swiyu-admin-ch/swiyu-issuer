/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.it;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@AutoConfigureMockMvc
class StatusListIT {

    public static final String STATUS_LIST_BASE_URL = "/api/v1/status-list";
    private static final String BASE_URL = "/api/v1/credentials";
    private final UUID statusListUUID = UUID.randomUUID();
    private final String statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
            .formatted(statusListUUID);
    @Autowired
    private SwiyuProperties swiyuProperties;
    @Autowired
    private MockMvc mvc;
    @Autowired
    private StatusListProperties statusListProperties;

    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;

    @BeforeEach
    void setUp() {
        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusListUUID);
        statusListEntryCreationDto.setStatusRegistryUrl(statusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(statusListEntryCreationDto);
    }

    @Test
    void createNewStatusList_thenSuccess() throws Exception {
        var type = "TOKEN_STATUS_LIST";
        var maxLength = 255;
        var bits = 2;
        var payload = String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": {\"bits\": %d}}", type, maxLength,
                bits);

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.statusRegistryUrl").isNotEmpty())
                .andExpect(jsonPath("$.type").value(type))
                .andExpect(jsonPath("$.maxListEntries").value(maxLength))
                .andExpect(jsonPath("$.remainingListEntries").value(maxLength))
                .andExpect(jsonPath("$.nextFreeIndex").value(0))
                .andExpect(jsonPath("$.config.bits").value(bits))
                .andReturn();

        // check if get info endpoint return the same values
        mvc.perform(get(STATUS_LIST_BASE_URL + "/" + JsonPath.read(result.getResponse().getContentAsString(), "$.id")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.statusRegistryUrl").isNotEmpty())
                .andExpect(jsonPath("$.type").value(type))
                .andExpect(jsonPath("$.maxListEntries").value(maxLength))
                .andExpect(jsonPath("$.remainingListEntries").value(maxLength))
                .andExpect(jsonPath("$.nextFreeIndex").value(0))
                .andExpect(jsonPath("$.config.bits").value(bits));
    }

    @Test
    void createOfferWithoutStatusList_thenBadRequest() throws Exception {
        String minPayloadWithEmptySubject = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(RandomStringUtils.insecure().next(10), statusRegistryUrl);

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isBadRequest())
                .andReturn();
    }

    @Test
    void getNotExistingStatusList_thenSuccess() throws Exception {
        var notExistingstatusListUUID = UUID.fromString("00000000-0000-0000-0000-000000000000");
        var requestUrl = String.format("%s/%s", STATUS_LIST_BASE_URL, notExistingstatusListUUID);
        String minPayloadWithEmptySubject = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(RandomStringUtils.insecure().next(10), statusRegistryUrl);

        mvc.perform(get(requestUrl).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isNotFound())
                .andReturn();
    }

    @Test
    void createOfferThenGetStatusList_thenSuccess() throws Exception {

        var type = "TOKEN_STATUS_LIST";
        var maxLength = 255;
        var bits = 2;
        var payload = String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": {\"bits\": %d}}", type, maxLength,
                bits);
        var freeIndex = 0;
        var remainigEntries = maxLength - freeIndex;

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();

        String offerCred = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(RandomStringUtils.insecure().next(10), statusRegistryUrl);

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(offerCred))
                .andExpect(status().isOk())
                .andReturn();

        // check if next free index increased
        var statusListId = JsonPath.read(result.getResponse().getContentAsString(), "$.id");
        var expectedNextFreeIndex = 1;

        mvc.perform(get(STATUS_LIST_BASE_URL + "/" + statusListId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.statusRegistryUrl").isNotEmpty())
                .andExpect(jsonPath("$.type").value(type))
                .andExpect(jsonPath("$.maxListEntries").value(maxLength))
                .andExpect(jsonPath("$.remainingListEntries").value(remainigEntries - expectedNextFreeIndex))
                .andExpect(jsonPath("$.maxListEntries").value(maxLength))
                .andExpect(jsonPath("$.nextFreeIndex").value(expectedNextFreeIndex))
                .andExpect(jsonPath("$.config.bits").value(bits)).andExpect(jsonPath("$.config.purpose").isEmpty());
    }

    @Test
    void createStatusListWithPurpose_thenSuccess() throws Exception {
        var bits = 1;
        var purpose = "test";
        var payload = String.format("{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": %d,\"config\": {\"bits\": %d, \"purpose\": \"%s\"}}", statusListProperties.getStatusListSizeLimit(), bits, purpose);

        var newStatusList = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();


        // check if get info endpoint return the same values
        mvc.perform(get(STATUS_LIST_BASE_URL + "/" + JsonPath.read(newStatusList.getResponse().getContentAsString(), "$.id")))
                .andExpect(jsonPath("$.config.bits").value(bits))
                .andExpect(jsonPath("$.config.purpose").value(purpose))
        ;
    }

    @Test
    void createStatusList_invalidStatusListType_thenBadRequest() throws Exception {
        var type = "NOT_TOKEN_STATUS_LIST";
        var bits = 1;
        var payload = getCreateStatusListPayload(type, statusListProperties.getStatusListSizeLimit(), bits);

        mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createStatusList_maxLengthExceeded_thenSuccess() throws Exception {
        var bits = 1;
        var payload = getCreateTokenStatusListPayload(statusListProperties.getStatusListSizeLimit() + 1, bits);
        var invalidTotalSize = (statusListProperties.getStatusListSizeLimit() + 1) * bits;

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse().getContentAsString();

        assertTrue(result.contains("statusListCreateDto: Status list has invalid size %s cannot exceed the maximum size limit of %s"
                .formatted(invalidTotalSize, statusListProperties.getStatusListSizeLimit())));
    }

    @Test
    void createStatusList_maxLengthExceededWithBits_thenSuccess() throws Exception {
        var bits = 2;
        var invalidMaxLength = (statusListProperties.getStatusListSizeLimit() / bits) + 1;
        var payload = getCreateTokenStatusListPayload(invalidMaxLength, bits);
        var invalidTotalSize = invalidMaxLength * bits;

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse().getContentAsString();

        assertTrue(result.contains("statusListCreateDto: Status list has invalid size %s cannot exceed the maximum size limit of %s"
                .formatted(invalidTotalSize, statusListProperties.getStatusListSizeLimit())));
    }

    @Test
    void createStatusList_invalidConfig_thenSuccess() throws Exception {
        var bits = 3;
        var validMaxLength = 100;
        var payload = getCreateTokenStatusListPayload(validMaxLength, bits);

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isUnprocessableEntity())
                .andReturn()
                .getResponse().getContentAsString();

        assertTrue(result.contains("config.bits: Bits can only be 1, 2, 4 or 8"));
    }

    @Test
    void createStatusList_invalidBitsAmount_thenBadRequest() throws Exception {
        var type = "TOKEN_STATUS_LIST";
        var invalidMaxLength = statusListProperties.getStatusListSizeLimit();
        var payload = String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": null}", type, invalidMaxLength);

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse()
                .getContentAsString();

        assertTrue(result.contains("statusListCreateDto: Status list size cannot be evaluated due to missing infos in config"));
        assertTrue(result.contains("config: must not be null"));
    }

    private String getCreateTokenStatusListPayload(int maxLength, int bits) {
        return String.format("{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": %d,\"config\": {\"bits\": %d}}", maxLength, bits);
    }

    private String getCreateStatusListPayload(String type, int maxLength, int bits) {
        return String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": {\"bits\": %d}}", type, maxLength, bits);
    }
}