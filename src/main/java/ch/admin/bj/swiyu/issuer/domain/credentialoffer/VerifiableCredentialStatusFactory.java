/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListType.TOKEN_STATUS_LIST;

public class VerifiableCredentialStatusFactory {
    public VerifiableCredentialStatusReference createStatusListReference(CredentialOfferStatus offerStatus) {
        var statusListType = offerStatus.getStatusList().getType();
        return switch (statusListType) {
            case TOKEN_STATUS_LIST ->
                    new TokenStatusListReference(offerStatus.getIndex(), offerStatus.getStatusList().getUri(), offerStatus.getStatusList().getType().displayName);
        };
    }

    public Map<String, Object> mergeStatus(Map<String, Object> accumulator, Map<String, Object> statusMap) {
        Set<String> mergeConflicts = setIntersection(accumulator.keySet(), statusMap.keySet());

        for (String key : statusMap.keySet()) {
            if (mergeConflicts.contains(key)) {
                if (accumulator.get(key) instanceof Map && statusMap.get(key) instanceof Map) {
                    mergeStatus((Map<String, Object>) accumulator.get(key), (Map<String, Object>) statusMap.get(key));
                }
                // If we can't merge it we ignore it
            } else {
                accumulator.put(key, statusMap.get(key));
            }
        }
        return accumulator;
    }

    private static Set<String> setIntersection(Set<String> a, Set<String> b) {
        Set<String> intersectionSet = new HashSet<>(a);
        intersectionSet.retainAll(b);
        return intersectionSet;
    }
}
