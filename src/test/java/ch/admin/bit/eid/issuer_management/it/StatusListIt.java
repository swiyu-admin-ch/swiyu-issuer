package ch.admin.bit.eid.issuer_management.it;

import ch.admin.bit.eid.issuer_management.services.RestService;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static ch.admin.bit.eid.issuer_management.it.BaseIt.BASE_URL;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
class StatusListTests {
    @Autowired
    private MockMvc mvc;

    @MockBean
    private RestService restService;

    @BeforeEach
    void setupMock() {
        Mockito.doNothing().when(restService).updateStatusList(ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(String.class));
    }

    @Test
    void createStatusList() throws Exception {
        mvc.perform(post("/status-list")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"uri\": \"https://status-data-service-d.apps.p-szb-ros-shrd-npr-01.cloud.admin.ch/api/v1/statuslist/874e5579-928e-42a4-8051-a3f9e9ead16f.jwt\",\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": 255,\"config\": {\"bits\": 2}}")
        ).andExpect(status().isOk());

        // Duplicate call does a bad request and not crash
        mvc.perform(post("/status-list")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"uri\": \"https://status-data-service-d.apps.p-szb-ros-shrd-npr-01.cloud.admin.ch/api/v1/statuslist/874e5579-928e-42a4-8051-a3f9e9ead16f.jwt\",\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": 255,\"config\": {\"bits\": 2}}")
        ).andExpect(status().isBadRequest());
    }

    @Test
    void createOfferWithoutStatusList_thenBadRequest() throws Exception {
        String minPayloadWithEmptySubject = String.format("{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"https://status-data-service-d.apps.p-szb-ros-shrd-npr-01.cloud.admin.ch/api/v1/statuslist/874e5579-928e-42a4-8051-a3f9e9ead16f.jwt\"]}", RandomStringUtils.random(10));

        MvcResult result = mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isBadRequest())
                .andReturn();
    }
}
