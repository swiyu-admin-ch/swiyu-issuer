package ch.admin.bit.swiyu.issuer.management.it;

import ch.admin.bit.swiyu.issuer.management.domain.ecosystem.StatusRegistryClient;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static ch.admin.bit.swiyu.issuer.management.it.BaseIt.BASE_URL;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
class StatusListIT {
    @Autowired
    private MockMvc mvc;

    @MockBean
    private StatusRegistryClient statusRegistryClient;

    @Test
    void createStatusList() throws Exception {
        mvc.perform(post("/status-list")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"uri\": \"https://status-data-service-d.bit.admin.ch/api/v1/statuslist/44bca201-f8b4-469d-8157-4ee48879b23e.jwt\",\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": 255,\"config\": {\"bits\": 2}}")
        ).andExpect(status().isOk());

        // Duplicate call does a bad request and not crash
        mvc.perform(post("/status-list")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"uri\": \"https://status-data-service-d.bit.admin.ch/api/v1/statuslist/44bca201-f8b4-469d-8157-4ee48879b23e.jwt\",\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": 255,\"config\": {\"bits\": 2}}")
        ).andExpect(status().isBadRequest());
    }

    @Test
    void createOfferWithoutStatusList_thenBadRequest() throws Exception {
        String minPayloadWithEmptySubject = String.format("{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"https://status-data-service-d.bit.admin.ch/api/v1/statuslist/44bca201-f8b4-469d-8157-4ee48879b23e.jwt\"]}", RandomStringUtils.random(10));

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isBadRequest())
                .andReturn();
    }
}
