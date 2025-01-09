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

public class StatusListMapperTest {

    @Test
    public void testToStatusListDto() {
        var statusListType = StatusListType.TOKEN_STATUS_LIST;
        var maxLength = new Random().nextInt();
        var nextFreeIndex = new Random().nextInt();
        var configMap = new HashMap<String, Object>();
        var id = UUID.randomUUID();
        var statusRegistryUrl = "uri";
        configMap.put("key", "value");

        StatusList statusList = StatusList.builder()
                .id(id)
                .uri(statusRegistryUrl)
                .type(statusListType)
                .maxLength(maxLength)
                .nextFreeIndex(nextFreeIndex)
                .config(configMap)
                .build();

        StatusListDto statusListDto = StatusListMapper.toStatusListDto(statusList);

        assertEquals(id, statusListDto.getId());
        assertEquals(statusRegistryUrl, statusListDto.getStatusRegistryUrl());
        assertEquals(StatusListTypeDto.TOKEN_STATUS_LIST, statusListDto.getType());
        assertEquals(maxLength, statusListDto.getMaxLength());
        assertEquals(nextFreeIndex, statusListDto.getNextFreeIndex());
        assertEquals(configMap, statusListDto.getConfig());
    }

    @Test
    public void testToStatusListTypeDto() {
        StatusListType statusListType = StatusListType.TOKEN_STATUS_LIST;

        StatusListTypeDto statusListTypeDto = StatusListMapper.toStatusListTypeDto(statusListType);

        assertEquals(StatusListTypeDto.TOKEN_STATUS_LIST, statusListTypeDto);
    }
}
