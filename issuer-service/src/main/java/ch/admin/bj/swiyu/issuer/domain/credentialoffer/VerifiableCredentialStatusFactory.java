/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;

import java.util.*;

public class VerifiableCredentialStatusFactory {
    private static Set<String> setIntersection(Set<String> a, Set<String> b) {
        Set<String> intersectionSet = new HashSet<>(a);
        intersectionSet.retainAll(b);
        return intersectionSet;
    }

    public VerifiableCredentialStatusReference createStatusListReference(Integer index, StatusList statusList) {
        var statusListType = statusList.getType();
        return switch (statusListType) {
            case TOKEN_STATUS_LIST ->
                    new TokenStatusListReference(index, statusList.getUri(), statusList.getType().displayName);
        };
    }

    public Map<String, List<VerifiableCredentialStatusReference>> mergeByIdentifier(Map<String, List<VerifiableCredentialStatusReference>> accumulator,
                                                                                    VerifiableCredentialStatusReference item) {
        var identifier = item.getIdentifier();
        accumulator.putIfAbsent(identifier, new LinkedList<>());
        accumulator.get(identifier).add(item);
        return accumulator;
    }

    public int getMaxSize(Map<String, List<VerifiableCredentialStatusReference>> references) {
        return references.values().stream().map(List::size).reduce(Integer::max).orElse(0);
    }

    /**
     * A sane configuration has 1 entry (using the same for all instances) or one entry per instance (batch size)
     */
    public boolean isSane(@NotNull Map<String, List<VerifiableCredentialStatusReference>> accumulatedStatusReferences,
                          @Nullable Integer batchSize) {
        int size = 1;
        if (batchSize != null) {
            size = batchSize;
        }
        for (List<VerifiableCredentialStatusReference> referenceList : accumulatedStatusReferences.values()) {


            if (referenceList.size() != size && referenceList.size() != 1) {
                // Not 1 per batch element or 1 (same reference used everywhere)
                return false;
            }
        }
        return true;
    }

    /**
     * Merges the JSON representations of status references together. If there are merge conflicts (aka; same status type is used multiple times), will take only the first one.
     */
    public Map<String, Object> mergeStatus(Map<String, Object> accumulator, Map<String, Object> statusMap) {
        if (accumulator == null) {
            accumulator = new HashMap<>();
        }
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
}
