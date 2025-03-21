/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.api.statuslist;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.util.Map;
import java.util.UUID;

@Data
@Builder
@Schema(name = "StatusList")
public class StatusListDto {

    @Schema(description = "Id of the status list used by the business issuer.")
    private UUID id;

    @Schema(description = "URI of the status list used by registry.")
    private String statusRegistryUrl;

    @Schema(description = "Technical type of the status list to be used. This influences the options available in config.")
    private StatusListTypeDto type;

    @Schema(description = "How many status entries can be part of the status list. The memory size of the status list is depending on the type and the config of the status list.", example = "100000")
    private Integer maxListEntries;

    @Schema(description = "How many status entries are not used in the  status list.", example = "12")
    private Integer remainingListEntries;

    @Schema(description = "Shows which is the next free status entry that can be used")
    private Integer nextFreeIndex;

    @Schema(description = "Version of the status list schema")
    private String version;

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
