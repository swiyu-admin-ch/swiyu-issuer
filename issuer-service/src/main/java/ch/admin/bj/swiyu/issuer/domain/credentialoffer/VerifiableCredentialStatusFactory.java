/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class VerifiableCredentialStatusFactory {
    public VerifiableCredentialStatusReference createStatusListReference(Integer index, StatusList statusList) {
        var statusListType = statusList.getType();
        return switch (statusListType) {
            case TOKEN_STATUS_LIST ->
                    new TokenStatusListReference(index, statusList.getUri(), statusList.getType().displayName);
        };
    }

    public Map<String, Object> mergeStatus(Map<String, Object> accumulator, Map<String, Object> statusMap) {
        Set<String> mergeConflicts = setIntersection(accumulator.keySet(), statusMap.keySet());


        for (Map.Entry<String, Object> entry : statusMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (mergeConflicts.contains(key)) {
                if (accumulator.get(key) instanceof Map && value instanceof Map) {
                    mergeStatus((Map<String, Object>) accumulator.get(key), (Map<String, Object>) value);
                }
                // If we can't merge it we ignore it
            } else {
                accumulator.put(key, value);
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
