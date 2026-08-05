package ch.admin.bj.swiyu.issuer.common.date;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ValueDeserializer;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class CustomInstantDeserializer extends ValueDeserializer<Instant> {
    private static final DateTimeFormatter ISO8601 = DateTimeFormatter
            .ofPattern(DateTimeUtils.ISO8601_FORMAT)
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter ISO8601_WITHOUT_MS = DateTimeFormatter
            .ofPattern(DateTimeUtils.ISO8601_FORMAT_WITHOUT_MS)
            .withZone(ZoneOffset.UTC);

    @Override
    public Instant deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) {
        String text = jsonParser.getString();
        try {
            return Instant.from(ISO8601.parse(text));
        } catch (Exception e) {
            return Instant.from(ISO8601_WITHOUT_MS.parse(text));
        }
    }
}
