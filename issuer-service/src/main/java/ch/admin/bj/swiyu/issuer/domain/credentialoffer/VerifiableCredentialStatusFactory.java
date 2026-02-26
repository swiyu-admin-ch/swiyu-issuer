package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;

import java.util.*;

public class VerifiableCredentialStatusFactory {
    private static Set<String> intersection(Set<String> a, Set<String> b) {
        Set<String> intersectionSet = new HashSet<>(a);
        intersectionSet.retainAll(b);
        return intersectionSet;
    }

    public VerifiableCredentialStatusReference createStatusListReference(Integer index, StatusList statusList) {
        return new TokenStatusListReference(index, statusList.getUri());
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
    public boolean isCompatibleStatusReferencesToBatchSize(@NotNull Map<String, List<VerifiableCredentialStatusReference>> accumulatedStatusReferences,
                                                           @Nullable Integer batchSize) {
        int size = 1;
        if (batchSize != null && batchSize > 0) {
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
        Map<String, Object> acc = (accumulator != null) ? accumulator : new HashMap<>();

        if (statusMap.isEmpty()) {
            return acc;
        }

        Set<String> conflicts = intersection(acc.keySet(), statusMap.keySet());

        for (Map.Entry<String, Object> entry : statusMap.entrySet()) {
            String key = entry.getKey();
            Object incoming = entry.getValue();

            if (!conflicts.contains(key)) {
                acc.put(key, incoming);
                continue;
            }
            Object existing = acc.get(key);
            if (existing instanceof Map && incoming instanceof Map) {
                // Recursive merge; unchecked but guarded by instanceof
                @SuppressWarnings("unchecked")
                Map<String, Object> existingMap = (Map<String, Object>) existing;
                @SuppressWarnings("unchecked")
                Map<String, Object> incomingMap = (Map<String, Object>) incoming;
                mergeStatus(existingMap, incomingMap);
            }
        }
        return acc;
    }
}
