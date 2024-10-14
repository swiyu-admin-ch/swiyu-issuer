package ch.admin.bit.eid.issuer_management.models.dto;

import ch.admin.bit.eid.issuer_management.models.statuslist.StatusListType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Map;

@Data
public class StatusListCreateDto {
    /**
     * URI where the status list is located
     */
    @NotEmpty
    @Schema(description = """
            Status list URI to initialize. This is the read URI as will be used by the holder to read the status list.
            """
            ,example="https://example-status-registry-uri/api/v1/statuslist/05d2e09f-21dc-4699-878f-89a8a2222c67.jwt")
    private String uri;
    /**
     * Type of the status list in camel case; eg TokenStatusList
     */
    @NotNull
    @Schema(description = "Technical type of the status list to be used. This influences the options available in config.")
    private StatusListType type;
    /**
     * How many status entries can be part of the status list
     */
    @NotNull
    @Schema(description = "How many status entries can be part of the status list. The memory size of the status list is depending on the type and the config of the status list.", example = "800000")
    private Integer maxLength;
    /**
     * Additional config parameters, depending on the status list type
     * eg {"bits": 2} for token status list with revocation & suspension
     * or {"purpose": "suspension"} for a bit string status list for suspension
     */
    @Schema(description = """
                 Additional config parameters, depending on the status list type. For Example
                 {"bits": 2}
                 for token status list with revocation & suspension
                 {"purpose": "suspension"}
                 for a bit string status list for suspension
            """, example = """
            {"bits": 2}
            """)
    private Map<String, Object> config;

}
