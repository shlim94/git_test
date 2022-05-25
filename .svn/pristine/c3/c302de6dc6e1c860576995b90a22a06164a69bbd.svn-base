package com.wise.comp.pivotgrid.param;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import com.wise.comp.model.SummaryType;

public class SummaryParam {

    private String selector;
    private SummaryType summaryType = SummaryType.SUM;
    private String precision;
    private String precisionOption;

    public SummaryParam() {

    }

    public SummaryParam(final String selector, final SummaryType summaryType, final String precision, final String precisionOption) {
        this.selector = selector;
        this.summaryType = summaryType;
        this.precision = precision;
        this.precisionOption = precisionOption;
    }

    public String getSelector() {
        return selector;
    }

    public void setSelector(String selector) {
        this.selector = selector;
    }

    public SummaryType getSummaryType() {
        return summaryType;
    }

    public void setSummaryType(SummaryType summaryType) {
        this.summaryType = summaryType;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SummaryParam)) {
            return false;
        }

        final SummaryParam that = (SummaryParam) o;

        if (!StringUtils.equals(selector, that.selector)) {
            return false;
        }

        if (summaryType != that.summaryType) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(selector).append(summaryType).append(precision).append(precisionOption).toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("selector", selector)
                .append("summaryType", summaryType).append("precision", precision).append("precisionOption", precisionOption).toString();
    }

	public String getPrecision() {
		return precision;
	}

	public void setPrecision(String precision) {
		this.precision = precision;
	}

	public String getPrecisionOption() {
		return precisionOption;
	}

	public void setPrecisionOption(String precisionOption) {
		this.precisionOption = precisionOption;
	}

}
