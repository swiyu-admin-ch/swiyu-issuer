package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import lombok.experimental.UtilityClass;

@UtilityClass
public class StatusListMapper {

    public static StatusListDto toStatusListDto(StatusList statusList, int availableEntries) {
        return StatusListDto.builder()
                .id(statusList.getId())
                .statusRegistryUrl(statusList.getUri())
                .maxListEntries(statusList.getMaxLength())
                .remainingListEntries(availableEntries)
                .config(statusList.getConfig())
                .build();
    }
}
