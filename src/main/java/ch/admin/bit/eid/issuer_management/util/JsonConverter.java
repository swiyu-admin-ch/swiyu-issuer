package ch.admin.bit.eid.issuer_management.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Converter
@Slf4j
public class JsonConverter implements AttributeConverter<Map<String, Object>, String> {

    // TODO check logger & what is logged
    private static final Logger logger = LoggerFactory.getLogger(JsonConverter.class);

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(Map<String, Object> stringObjectMap) {
        try {
            return objectMapper.writeValueAsString(stringObjectMap);
        } catch (final JsonProcessingException e) {
            logger.error("JSON writing error", e);
            return null;
        }
    }

    @Override
    public Map<String, Object> convertToEntityAttribute(String value) {
        // TODO check if correct approach
        try {
            return objectMapper.readValue(value, new TypeReference<HashMap<String, Object>>() {});
        } catch (final IOException e) {
            logger.error("JSON error", e);
            return null;
        }
    }
}
