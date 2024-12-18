package ch.admin.bit.swiyu.issuer.management.domain.status_list;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum TokenStatsListBit {
    VALID(0),
    REVOKE(1),
    SUSPEND(2);

    /**
     * Value as defined in Token Status List Spec
     */
    private final int value;
}
