package ch.admin.bit.eid.issuer_management.it;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
class StatusListTests {
    @Autowired
    private MockMvc mvc;

    @Test
    void createStatusList() throws Exception {
        mvc.perform(post("/status-list")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"uri\": \"https://status-data-service-d.apps.p-szb-ros-shrd-npr-01.cloud.admin.ch/api/v1/statuslist/874e5579-928e-42a4-8051-a3f9e9ead16f.jwt\",\"type\": \"TokenStatusList\",\"maxLength\": 255,\"config\": {\"bits\": 2}}")
        ).andExpect(status().isOk());
    }
}
