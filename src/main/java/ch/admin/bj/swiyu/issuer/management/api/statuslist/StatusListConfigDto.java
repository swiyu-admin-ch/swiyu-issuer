/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.api.statuslist;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(name = "StatusListCreateConfig")
public class StatusListConfigDto {

    private String purpose;

    @NotNull
    @ValidStatusListBits
    @Schema(description = "The number of bits used per Referenced Token. Possible values are 1, 2, 4, 8.", example = "2")
    private Integer bits;
}