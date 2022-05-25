package com.wise.comp.model;

import java.math.BigDecimal;
import java.util.Date;

/**
 * 원본 데이터셋 {@link DataFrame}의 하나의 행을 표현.
 */
public interface DataRow {

    public String getStringValue(final String columnName);

    public String getStringValue(final String columnName, final String dateInterval);

    public Date getDateValue(final String columnName);

    public BigDecimal getBigDecimalValue(final String columnName);

    public boolean hasCustomColumnValue(final String columnName);

    public Object getCustomColumnValue(final String columnName);

    public void setCustomColumnValue(final String columnName, final Object value);
    
    public boolean isString(final String columnName);

}
