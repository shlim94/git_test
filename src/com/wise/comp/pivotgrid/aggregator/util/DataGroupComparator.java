package com.wise.comp.pivotgrid.aggregator.util;

import java.math.BigDecimal;
import java.util.Comparator;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import com.wise.common.util.StringCompareUtils;
import com.wise.comp.model.DataGroup;

public class DataGroupComparator implements Comparator<DataGroup> {

    private final int sortByMeasure;

    private final int sortOrder;

    public DataGroupComparator(final int sortByMeasure, final int sortOrder) {
        this.sortByMeasure = sortByMeasure;
        this.sortOrder = sortOrder;
    }

    @Override
    public int compare(DataGroup a, DataGroup b) {
        int result = 0;

        if (sortByMeasure == -1) {
            // 차원 정렬
            String keyA = a.getKey();
            String keyB = b.getKey();

            result = StringCompareUtils.compare(keyA, keyB);
        }
        else {
        	//측정값 정렬
        	//정렬기준 항목에 문자열이 끼여있을 경우 string비교
        	String tempAstr = null;
        	String tempBstr = null;

        	if(a.getSummaryValues().get(sortByMeasure).getTextValue() != null) {
        		tempAstr = a.getSummaryValues().get(sortByMeasure).getTextValue();
        	}
        	if(b.getSummaryValues().get(sortByMeasure).getTextValue() != null) {
        		tempBstr = b.getSummaryValues().get(sortByMeasure).getTextValue();
        	}
        	
        	if(tempAstr != null && tempBstr != null) {
        		result = StringCompareUtils.compare(tempAstr, tempBstr);
        	}else if(tempAstr != null) {
        		result = StringCompareUtils.compare(tempAstr, b.getSummaryValues().get(sortByMeasure).getRepresentingValue().toString());
        	}else if(tempBstr != null) {
        		result = StringCompareUtils.compare(a.getSummaryValues().get(sortByMeasure).getRepresentingValue().toString(), tempBstr);
        	}else {
        		BigDecimal tempA = a.getSummaryValues().get(sortByMeasure).getRepresentingValue();
                BigDecimal tempB = b.getSummaryValues().get(sortByMeasure).getRepresentingValue();

                result = tempA.compareTo(tempB);
        	}
        }

        return result * sortOrder;
    }


    @Override
    public boolean equals(Object o) {
        if (!(o instanceof DataGroupComparator)) {
            return false;
        }

        final DataGroupComparator that = (DataGroupComparator) o;

        return sortByMeasure == that.sortByMeasure && sortOrder == that.sortOrder;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(sortByMeasure).append(sortOrder).toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("sortByMeasure", sortByMeasure)
                .append("sortOrder", sortOrder).toString();
    }
}
