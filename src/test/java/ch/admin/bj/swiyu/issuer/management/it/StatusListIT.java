package ch.admin.bj.swiyu.issuer.management.it;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.management.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusListRepository;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
class StatusListIT {

    private static final String BASE_URL = "/credentials";
    private static final String STATUS_LIST_BASE_URL = "/status-list";

    @Autowired
    private SwiyuProperties swiyuProperties;
    private UUID statusListUUID;
    private String statusListUrl;
    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private StatusRegistryClient statusRegistryClient;

    @Test
    void createNewStatusList_thenSuccess() throws Exception {
        var type = "TOKEN_STATUS_LIST";
        var maxLength = 255;
        var bits = 2;
        var payload = String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": {\"bits\": %d}}", type, maxLength,
                bits);

        var result = mvc.perform(post("/status-list")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.statusRegistryUrl").isNotEmpty())
                .andExpect(jsonPath("$.type").value(type))
                .andExpect(jsonPath("$.maxLength").value(maxLength))
                .andExpect(jsonPath("$.nextFreeIndex").value(0))
                .andExpect(jsonPath("$.config.bits").value(bits))
                .andReturn();

        // check if get info endpoint return the same values
        mvc.perform(get("/status-list/" + JsonPath.read(result.getResponse().getContentAsString(), "$.id")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.statusRegistryUrl").isNotEmpty())
                .andExpect(jsonPath("$.type").value(type))
                .andExpect(jsonPath("$.maxLength").value(maxLength))
                .andExpect(jsonPath("$.nextFreeIndex").value(0))
                .andExpect(jsonPath("$.config.bits").value(bits));
    }

    @Test
    void createOfferWithoutStatusList_thenBadRequest() throws Exception {
        String minPayloadWithEmptySubject = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(RandomStringUtils.random(10), statusListUrl);

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isBadRequest())
                .andReturn();
    }

    @Test
    void getNotExistingStatusList_thenSuccess() throws Exception {
        var notExistingstatusListUUID = UUID.fromString("00000000-0000-0000-0000-000000000000");
        var requestUrl = String.format("%s/%s", STATUS_LIST_BASE_URL, notExistingstatusListUUID);
        String minPayloadWithEmptySubject = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(RandomStringUtils.random(10), statusListUrl);

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

        var result = mvc.perform(post("/status-list")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isOk())
                .andReturn();

        String offerCred = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(RandomStringUtils.random(10), statusListUrl);

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(offerCred))
                .andExpect(status().isOk())
                .andReturn();

        // check if next free index increased
        var statusListId = JsonPath.read(result.getResponse().getContentAsString(), "$.id");

        mvc.perform(get("/status-list/" + statusListId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.statusRegistryUrl").isNotEmpty())
                .andExpect(jsonPath("$.type").value(type))
                .andExpect(jsonPath("$.maxLength").value(maxLength))
                .andExpect(jsonPath("$.nextFreeIndex").value(1))
                .andExpect(jsonPath("$.config.bits").value(bits));
    }
}
