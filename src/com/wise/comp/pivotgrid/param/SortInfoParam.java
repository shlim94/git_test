package com.wise.comp.pivotgrid.param;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

public class SortInfoParam {

    private String sortOrder;
    private String dataField;
    private String sortByField;

    public SortInfoParam() {
    }

    public SortInfoParam(final String sortOrder, final String dataField, final String sortByField) {
        this.sortOrder = sortOrder;
        this.dataField = dataField;
        this.sortByField = sortByField;
    }

    public String getSortOrder() {
        return sortOrder;
    }

    public void setSortOrder(String sortOrder) {
        this.sortOrder = sortOrder;
    }

    public String getDataField() {
        return dataField;
    }

    public void setDataField(String dataField) {
        this.dataField = dataField;
    }

    public String getSortByField() {
        return sortByField;
    }

    public void setSortByField(String sortByField) {
        this.sortByField = sortByField;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SortInfoParam)) {
            return false;
        }

        final SortInfoParam that = (SortInfoParam) o;

        if (!StringUtils.equals(sortOrder, that.sortOrder)) {
            return false;
        }

        if (!StringUtils.equals(dataField, that.dataField)) {
            return false;
        }

        if (!StringUtils.equals(sortByField, that.sortByField)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(sortOrder).append(dataField).append(sortByField)
                .toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("sortOrder", sortOrder)
                .append("dataField", dataField).append("sortByField", sortByField).toString();
    }
}
