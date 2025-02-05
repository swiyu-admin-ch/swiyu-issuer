/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.statuslist;

import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusListType;
import ch.admin.bj.swiyu.issuer.management.service.statusregistry.StatusListMapper;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Random;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StatusListMapperTest {

    @Test
    void testToStatusListDto() {
        var statusListType = StatusListType.TOKEN_STATUS_LIST;
        var maxLength = new Random().nextInt();
        var nextFreeIndex = new Random().nextInt();
        var remainingEntries = maxLength - nextFreeIndex;
        var configMap = new HashMap<String, Object>();
        var id = UUID.randomUUID();
        var statusRegistryUrl = "uri";
        var version = "1.0";
        configMap.put("key", "value");

        StatusList statusList = StatusList.builder()
                .id(id)
                .uri(statusRegistryUrl)
                .type(statusListType)
                .maxLength(maxLength)
                .nextFreeIndex(nextFreeIndex)
                .config(configMap)
                .build();

        StatusListDto statusListDto = StatusListMapper.toStatusListDto(statusList, version);

        assertEquals(id, statusListDto.getId());
        assertEquals(statusRegistryUrl, statusListDto.getStatusRegistryUrl());
        assertEquals(StatusListTypeDto.TOKEN_STATUS_LIST, statusListDto.getType());
        assertEquals(maxLength, statusListDto.getMaxListEntries());
        assertEquals(remainingEntries, statusListDto.getRemainingListEntries());
        assertEquals(nextFreeIndex, statusListDto.getNextFreeIndex());
        assertEquals(configMap, statusListDto.getConfig());
        assertEquals(version, statusListDto.getVersion());
    }

    @Test
    void testToStatusListTypeDto() {
        StatusListType statusListType = StatusListType.TOKEN_STATUS_LIST;

        StatusListTypeDto statusListTypeDto = StatusListMapper.toStatusListTypeDto(statusListType);

        assertEquals(StatusListTypeDto.TOKEN_STATUS_LIST, statusListTypeDto);
    }
}
