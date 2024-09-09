package ch.admin.bit.eid.issuer_management.models.dto;

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
    private String uri;
    /**
     * Type of the status list in camel case; eg TokenStatusList
     */
    @NotEmpty
    private String type;
    /**
     * How many status entries can be part of the status list
     */
    @NotNull
    private Integer maxLength;
    /**
     * Additional config parameters, depending on the status list type
     * eg {"bits": 2} for token status list with revocation & suspension
     * or {"purpose": "suspension"} for a bit string status list for suspension
     */
    private Map<String, Object> config;

}
