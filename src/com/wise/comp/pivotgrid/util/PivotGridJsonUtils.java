package com.wise.comp.pivotgrid.util;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Iterator;
import java.util.List;

import com.fasterxml.jackson.core.JsonGenerator;
import com.wise.common.util.WINumberUtils;
import com.wise.comp.model.AbstractSummaryContainer;
import com.wise.comp.model.DataFrame;
import com.wise.comp.model.DataGroup;
import com.wise.comp.model.DataRow;
import com.wise.comp.model.Paging;
import com.wise.comp.model.SummaryValue;

public final class PivotGridJsonUtils {

    private PivotGridJsonUtils() {
    }

    public static void writeSummaryContainerToJson(final JsonGenerator gen,
            final AbstractSummaryContainer<?> summaryContainer, final String key,
            final String childDataGroupArrayFieldName, final Paging paging, final boolean visibleOnly, String sql) throws IOException {
        gen.writeStartObject();

        if (key != null) {
            gen.writeStringField("key", key);
        }
        if (sql != null) {
            gen.writeStringField("sql", sql);
        }

        gen.writeFieldName("summary");

        gen.writeStartArray();
        final List<SummaryValue> summaryValues = summaryContainer.getSummaryValues();
        if (summaryValues != null) {
            for (SummaryValue summaryValue : summaryValues) {
                gen.writeNumber(summaryValue.getRepresentingValue());
            }
        }
        gen.writeEndArray();

        if (paging != null && paging.getOffset() >= 0 && paging.getLimit() > 0) {
            gen.writeFieldName("paging");
            gen.writeStartObject();
            gen.writeNumberField("offset", paging.getOffset());
            gen.writeNumberField("limit", paging.getLimit());
            gen.writeNumberField("count", paging.getCount());
            gen.writeNumberField("total", paging.getTotal());
            gen.writeNumberField("distinctTotal", paging.getDistinctTotal());
            gen.writeEndObject();
        }

        gen.writeFieldName(childDataGroupArrayFieldName);
        final List<DataGroup> childDataGroups = summaryContainer.getChildDataGroups(visibleOnly);
        if (childDataGroups == null) {
            gen.writeNull();
        }
        else {
            gen.writeStartArray();
            for (DataGroup childDataGroup : childDataGroups) {
                writeSummaryContainerToJson(gen, childDataGroup, childDataGroup.getKey(), "items", null, visibleOnly, sql);
            }
            gen.writeEndArray();
        }

        gen.writeEndObject();
    }

    public static void writeTabularDataToJson(final JsonGenerator gen, final DataFrame dataFrame,
            final int skip, final int take) throws IOException {
    	
//    	gen.writeStartObject();
//    	gen.writeFieldName("datas");
    	
        gen.writeStartArray();

        Iterator<DataRow> it = dataFrame.iterator();

        if (skip > 0) {
            for (int i = 0; i < skip && it.hasNext(); i++) {
                it.next();
            }
        }

        final String[] columnNames = dataFrame.getColumnNames();
        int iterCount = 0;

        while (it.hasNext()) {
            final DataRow row = it.next();

            if (take > 0 && ++iterCount > take) {
                break;
            }

            gen.writeStartObject();

            for (String columnName : columnNames) {
                final String value = row.getStringValue(columnName);

                if (WINumberUtils.isNumber(value)) {
                    gen.writeNumberField(columnName, new BigDecimal(value));
                }
                else {
                    gen.writeStringField(columnName, value);
                }
            }

            gen.writeEndObject();
        }

        gen.writeEndArray();
        
        // 전체데이터를 한번 더 씀
//        gen.writeFieldName("gdata");
//    	
//        gen.writeStartArray();
//        
//        it = dataFrame.iterator();
//        
//        while (it.hasNext()) {
//            final DataRow row = it.next();
//
//            gen.writeStartObject();
//
//            for (String columnName : columnNames) {
//                final String value = row.getStringValue(columnName);
//
//                if (WINumberUtils.isNumber(value)) {
//                    gen.writeNumberField(columnName, new BigDecimal(value));
//                }
//                else {
//                    gen.writeStringField(columnName, value);
//                }
//            }
//
//            gen.writeEndObject();
//        }
//        
//        gen.writeEndArray();
//        
//        gen.writeEndObject();
    }
}