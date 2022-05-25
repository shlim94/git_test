package com.wise.comp.pivotmatrix;

import java.math.BigDecimal;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import com.wise.common.util.StringCompareUtils;
import com.wise.common.util.WINumberUtils;

public class SummaryDimensionComparator implements Comparator<SummaryDimension> {
	
	private final Map<String, String> valuesMap;
	
	private final boolean descending;
	
	public SummaryDimensionComparator(final Map<String, String> valuesMap, final boolean descending) {
		this.valuesMap = new HashMap<>();
		if (valuesMap != null) {
			this.valuesMap.putAll(valuesMap);
		}
		this.descending = descending;
	}

	@Override
	public int compare(SummaryDimension dim1, SummaryDimension dim2) {
		int result = 0;
		
		final String key1 = dim1.getKey();
		final String key2 = dim2.getKey();
		final String value1 = StringUtils.defaultString(StringUtils.defaultIfEmpty(valuesMap.get(key1), key1));
		final String value2 = StringUtils.defaultString(StringUtils.defaultIfEmpty(valuesMap.get(key2), key2));
		
//		final boolean allNumbers = WINumberUtils.isNumber(value1) && WINumberUtils.isNumber(value2);
//		
//		if (allNumbers) {
//			final BigDecimal num1 = new BigDecimal(value1);
//			final BigDecimal num2 = new BigDecimal(value2);
//			result = num1.compareTo(num2);
//		}
//		else {
			result = StringCompareUtils.compare(value1, value2);
//		}
		
		return descending ? -result : result;
	}
}
