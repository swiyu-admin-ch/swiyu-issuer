/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.api.statuslist;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Map;

@Data
@Schema(name = "StatusListCreate")
public class StatusListCreateDto {

    /**
     * Type of the status list in camel case; eg TokenStatusList
     */
    @NotNull
    @Schema(description = "Technical type of the status list to be used. This influences the options available in config.")
    private StatusListTypeDto type;
    /**
     * How many status entries can be part of the status list
     */
    @NotNull
    @Schema(description = "How many status entries can be part of the status list. The memory size of the status list is depending on the type and the config of the status list.", example = "100000")
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
