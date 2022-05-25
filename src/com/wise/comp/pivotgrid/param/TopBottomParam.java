package com.wise.comp.pivotgrid.param;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TopBottomParam {

    private String dataFieldName;
    private String dataUniName;
    private String applyFieldName;
    private String applyUniName;
    private String topBottomType;
    private int topBottomCount;
    private boolean inPercent;
    private boolean showOthers;
    
    public TopBottomParam() {
    }

    public TopBottomParam(final String dataFieldName, final String applyFieldName,
            final String topBottomType, final int topBottomCount, final boolean inPercent,
            final boolean showOthers) {
        this.dataFieldName = dataFieldName;
        this.applyFieldName = applyFieldName;
        this.topBottomType = topBottomType;
        this.topBottomCount = topBottomCount;
        this.inPercent = inPercent;
        this.showOthers = showOthers;
    }

    @JsonProperty("DATA_FLD_NM")
    public String getDataFieldName() {
        return dataFieldName;
    }

    public void setDataFieldName(String dataFieldName) {
        this.dataFieldName = dataFieldName;
    }
    
    @JsonProperty("DATA_UNI_NM")
    public String getDatauniName() {
        return dataUniName;
    }

    public void setDatauniName(String dataUniName) {
        this.dataUniName = dataUniName;
    }
    
    @JsonProperty("APPLY_FLD_NM")
    public String getApplyFieldName() {
        return applyFieldName;
    }

    public void setApplyFieldName(String applyFieldName) {
        this.applyFieldName = applyFieldName;
    }
    
    @JsonProperty("APPLY_UNI_NM")
    public String getApplyUniName() {
        return applyUniName;
    }

    public void setApplyUniName(String applyUniName) {
        this.applyUniName = applyUniName;
    }
    
    @JsonProperty("TOPBOTTOM_TYPE")
    public String getTopBottomType() {
        return topBottomType;
    }

    public void setTopBottomType(String topBottomType) {
        this.topBottomType = topBottomType;
    }

    @JsonProperty("TOPBOTTOM_CNT")
    public int getTopBottomCount() {
        return topBottomCount;
    }

    public void setTopBottomCount(int topBottomCount) {
        this.topBottomCount = topBottomCount;
    }

    @JsonProperty("PERCENT")
    public boolean isInPercent() {
        return inPercent;
    }

    public void setInPercent(boolean inPercent) {
        this.inPercent = inPercent;
    }

    @JsonProperty("SHOW_OTHERS")
    public boolean isShowOthers() {
        return showOthers;
    }

    public void setShowOthers(boolean showOthers) {
        this.showOthers = showOthers;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof TopBottomParam)) {
            return false;
        }

        final TopBottomParam that = (TopBottomParam) o;

        if (!StringUtils.equals(dataFieldName, that.dataFieldName)) {
            return false;
        }

        if (!StringUtils.equals(applyFieldName, that.applyFieldName)) {
            return false;
        }

        if (!StringUtils.equals(topBottomType, that.topBottomType)) {
            return false;
        }

        if (topBottomCount != that.topBottomCount) {
            return false;
        }

        if (inPercent != that.inPercent) {
            return false;
        }

        if (showOthers != that.showOthers) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(dataFieldName).append(applyFieldName)
                .append(topBottomType).append(topBottomCount).append(inPercent).append(showOthers)
                .toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("dataFieldName", dataFieldName)
                .append("applyFieldName", applyFieldName).append("topBottomType", topBottomType)
                .append("topBottomCount", topBottomCount).append("inPercent", inPercent)
                .append("showOthers", showOthers).toString();
    }
}
