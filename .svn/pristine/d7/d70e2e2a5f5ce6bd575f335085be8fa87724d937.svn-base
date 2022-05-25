package com.wise.comp.pivotgrid.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.wise.comp.model.DataAggregation;

/**
 * Utility to be used when caching {@code DataAggregation} object internally.
 */
public final class DataAggregationCacheUtils {

    private DataAggregationCacheUtils() {
    }

    public static void writeDataAggregationMap(final ObjectMapper objectMapper, final OutputStream out,
            final Map<String, DataAggregation> dataAggregationMap) throws IOException {
        objectMapper.writeValue(out, dataAggregationMap);
    }

    public static Map<String, DataAggregation> readDataAggregationMap(final ObjectMapper objectMapper,
            final InputStream input) throws IOException {
        final ObjectReader reader = objectMapper.readerForMapOf(DataAggregation.class);
        return reader.readValue(input);
    }

    public static void writeDataAggregation(final ObjectMapper objectMapper, final OutputStream out,
            final DataAggregation dataAggregation) throws IOException {
        objectMapper.writeValue(out, dataAggregation);
    }

    public static DataAggregation readDataAggregation(final ObjectMapper objectMapper,
            final InputStream input) throws IOException {
        return objectMapper.readValue(input, DataAggregation.class);
    }
}
