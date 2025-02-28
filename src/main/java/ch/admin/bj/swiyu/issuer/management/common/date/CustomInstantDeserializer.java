package ch.admin.bj.swiyu.issuer.management.common.date;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class CustomInstantDeserializer extends JsonDeserializer<Instant> {
    private static final DateTimeFormatter ISO8601 = DateTimeFormatter
            .ofPattern(DateTimeUtils.ISO8601_FORMAT)
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter ISO8601_WITHOUT_MS = DateTimeFormatter
            .ofPattern(DateTimeUtils.ISO8601_FORMAT_WITHOUT_MS)
            .withZone(ZoneOffset.UTC);
    @Override
    public Instant deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        String text = jsonParser.getText();
        try {
            return Instant.from(ISO8601.parse(text));
        } catch (Exception e) {
            return Instant.from(ISO8601_WITHOUT_MS.parse(text));
        }
    }
}
