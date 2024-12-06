package ch.admin.bit.eid.issuer_management.enums;


import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * A list of global locks in the application.
 */
@Getter
@RequiredArgsConstructor
public enum GlobalLocksEnum {
    STATUS_REGISTRY_TOKEN_MANAGER_TOKEN_REFRESH("STATUS_REGISTRY_TOKEN_MANAGER_TOKEN_REFRESH");

    private final String lockId;
}