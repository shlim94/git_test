package com.wise.comp.impl.json;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.wise.comp.model.AbstractDataRow;

public class ObjectNodeDataRow extends AbstractDataRow {

	private final ObjectNode record;

    public ObjectNodeDataRow(final ObjectNode objectNode) {
        this.record = objectNode;
    }

    @Override
    public String getInternalStringValue(final String columnName) {
        return record.has(columnName) ? record.get(columnName).asText() : null;
    }
}
