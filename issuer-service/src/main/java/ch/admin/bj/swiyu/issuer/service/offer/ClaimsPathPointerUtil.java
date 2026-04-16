package ch.admin.bj.swiyu.issuer.service.offer;

import lombok.experimental.UtilityClass;
import org.springframework.util.CollectionUtils;

import java.util.*;

@UtilityClass
public class ClaimsPathPointerUtil {

    /**
     * Validate if the requestedClaims are present in the jwt
     * Throws Illegal Argument Exception if something is wrong with the presented object map
     *
     * @throws IllegalArgumentException if not all requested claims are present, if path does not exist, value mismatch in the sd jwt's claims
     */
    public static void validateRequestedClaims(Map<String, Object> objectMap, List<Object> requestedClaimsPointerPath, List<Object> requestedValues) {
        if (CollectionUtils.isEmpty(requestedClaimsPointerPath)) {
            throw new IllegalArgumentException("Requested claims pointer path is empty");
        }

        var claims = selectClaim(objectMap, requestedClaimsPointerPath);

        List<Object> sanitizedRequestValues = requestedValues;

        if (requestedValues != null) {
            // if number cast to double as the sdjwt uses GSON which unmarshals all numbers to double
            sanitizedRequestValues = requestedValues.stream().map(value -> value instanceof Number number ? number.doubleValue() : value).toList();
        }

        if (requestedValues != null && Collections.disjoint(claims, sanitizedRequestValues)) {
            throw new IllegalArgumentException("Not all requested claim values are satisfied");
        }
    }

    static Set<List<Object>> flatten(Object obj,
                                     List<Object> path) {

        Set<List<Object>> result = new HashSet<>();

        if (obj instanceof Map<?, ?> map) {

            for (Map.Entry<?, ?> entry : map.entrySet()) {
                List<Object> newPath = new ArrayList<>(path);
                newPath.add(entry.getKey()); // String key
                result.addAll(flatten(entry.getValue(), newPath));
            }

        } else if (obj instanceof List<?> list) {

            for (Object o : list) {
                List<Object> newPath = new ArrayList<>(path);

                newPath.add(null); // wildcard

                result.addAll(flatten(o, newPath));
            }

        } else {
            if (!path.isEmpty()) {
                result.add(path);
            }
        }

        return result;
    }

    private static List<Object> selectClaim(Map<String, Object> objectMap, List<Object> claimsPointerPath) {
        var selected = new DcqlPathSelection(objectMap);
        for (Object path : claimsPointerPath) {
            switch (path) {
                case null -> selected = selected.selectAll();
                case Number number -> selected = selected.selectElement(number.intValue());
                case String s -> selected = selected.selectElement(s);
                default ->
                        throw new IllegalArgumentException("Illegal request path type; was %s".formatted(path.getClass()));
            }
        }
        return selected.selected;
    }

    private record DcqlPathSelection(List<Object> selected) {
        /**
         * Select the root element of the Credential, i.e., the top-level JSON object.
         */
        public DcqlPathSelection(Object root) {
            this(List.of(root));
        }

        /**
         * If the set of elements currently selected is empty, abort processing and return an error.
         */
        private DcqlPathSelection {
            if (CollectionUtils.isEmpty(selected)) {
                throw new IllegalArgumentException("Requested DCQL path could not be found");
            }
        }

        /**
         * If the component is a string, select the element in the respective key in the currently selected element(s).
         * If any of the currently selected element(s) is not an object, abort processing and return an error.
         * If the key does not exist in any element currently selected, remove that element from the selection
         */
        public DcqlPathSelection selectElement(String key) {
            List<Object> newSelection = new LinkedList<>();
            for (Object currentSelected : selected) {
                if (!(currentSelected instanceof Map)) {
                    throw new IllegalArgumentException("Illegal claim type for selection %s - found %s instead of Json Object".formatted(key, currentSelected.getClass()));
                }
                var newElement = ((Map<?, ?>) currentSelected).get(key);
                if (newElement != null) {
                    newSelection.add(newElement);
                }
            }
            return new DcqlPathSelection(newSelection);
        }

        /**
         * If the component is a non-negative integer, select the element at the respective index in the currently selected array(s).
         * If any of the currently selected element(s) is not an array, abort processing and return an error.
         * If the index does not exist in a selected array, remove that array from the selection.
         */
        public DcqlPathSelection selectElement(int index) {
            List<Object> newSelection = new LinkedList<>();
            for (Object currentSelected : selected) {
                if (!(currentSelected instanceof List)) {
                    throw new IllegalArgumentException("Illegal claim type for selection %s - found %s instead of Json Array".formatted(index, currentSelected.getClass()));
                }
                if (index < ((List<?>) currentSelected).size()) {
                    newSelection.add(((List<?>) currentSelected).get(index));
                }
            }
            return new DcqlPathSelection(newSelection);
        }

        /**
         * If the component is null, select all elements of the currently selected array(s).
         * If any of the currently selected element(s) is not an array, abort processing and return an error.
         */
        public DcqlPathSelection selectAll() {
            List<Object> newSelection = new LinkedList<>();
            for (Object currentSelected : selected) {
                if (!(currentSelected instanceof List)) {
                    throw new IllegalArgumentException("Illegal claim type for selecting all array elements - found %s instead of Json Array".formatted(currentSelected.getClass()));
                }
                newSelection.addAll((List<?>) currentSelected);
            }
            // unpack array to selected
            return new DcqlPathSelection(newSelection);
        }
    }
}