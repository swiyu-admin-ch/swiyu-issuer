package ch.admin.bit.eid.issuer_management.models.statuslist;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum TokenStatsListBit {
    REVOKE(1),
    SUSPEND(2);

    private int bitNumber;
}
