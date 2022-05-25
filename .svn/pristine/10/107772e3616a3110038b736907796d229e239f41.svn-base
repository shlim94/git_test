package com.wise.comp.impl.json;

import com.wise.comp.model.AbstractDataRow;

import net.sf.json.JSONObject;

public class JSONObjectDataRow extends AbstractDataRow {

    private final JSONObject record;

    public JSONObjectDataRow(final JSONObject objectNode) {
        this.record = objectNode;
    }

    @Override
    public String getInternalStringValue(final String columnName) {
        return record.has(columnName) ? record.getString(columnName) : null;
    }
}
