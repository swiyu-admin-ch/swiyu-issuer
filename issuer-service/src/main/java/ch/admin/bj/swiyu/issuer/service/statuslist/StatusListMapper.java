package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListType;
import lombok.experimental.UtilityClass;

@UtilityClass
public class StatusListMapper {

    public static StatusListDto toStatusListDto(StatusList statusList, int availableEntries, String version) {
        return StatusListDto.builder()
                .id(statusList.getId())
                .statusRegistryUrl(statusList.getUri())
                .type(toStatusListTypeDto(statusList.getType()))
                .maxListEntries(statusList.getMaxLength())
                .remainingListEntries(availableEntries)
                .config(statusList.getConfig())
                .version(version)
                .build();
    }

    public static StatusListTypeDto toStatusListTypeDto(StatusListType statusListType) {
        return StatusListTypeDto.valueOf(statusListType.name());
    }
}
