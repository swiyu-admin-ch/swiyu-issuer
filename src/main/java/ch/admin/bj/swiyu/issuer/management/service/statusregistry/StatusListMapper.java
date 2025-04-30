/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service.statusregistry;

import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusListType;
import lombok.experimental.UtilityClass;

@UtilityClass
public class StatusListMapper {

    public static StatusListDto toStatusListDto(StatusList statusList, String version) {
        return StatusListDto.builder()
                .id(statusList.getId())
                .statusRegistryUrl(statusList.getUri())
                .type(toStatusListTypeDto(statusList.getType()))
                .maxListEntries(statusList.getMaxLength())
                .remainingListEntries(statusList.getMaxLength() - statusList.getNextFreeIndex())
                .nextFreeIndex(statusList.getNextFreeIndex())
                .config(statusList.getConfig())
                .version(version)
                .build();
    }

    public static StatusListTypeDto toStatusListTypeDto(StatusListType statusListType) {
        return StatusListTypeDto.valueOf(statusListType.name());
    }
}
