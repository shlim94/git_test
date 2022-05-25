package com.wise.comp.model;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * 그룹별 총 써머리 데이터 집합.
 * <P>
 * 이는 최상위 컨테이너로서, 하위 그룹들을 포함한다. 이 클래스의 인스턴스는 결과 총 써머리 데이터 집합으로 사용된다.
 * <P>
 * 이 모델은 DevExpress Pivot Grid가 요구하는 JSON 모델과 동일한 방식이다.
 * <P>
 * 참고자료: <a href=
 * "https://js.devexpress.com/Documentation/18_2/Guide/Widgets/PivotGrid/Use_CustomStore/">https://js.devexpress.com/Documentation/18_2/Guide/Widgets/PivotGrid/Use_CustomStore/</a>
 */
public class DataAggregation extends AbstractSummaryContainer<DataAggregation> {

    private Paging paging = new Paging();
    private boolean pagingApplied;

    private Map<String, Map<String, String>> columnSortValuesMap;
    
    public DataAggregation() {
        super();
    }

    public Paging getPaging() {
        return paging;
    }

    public void setPaging(final Paging paging) {
        this.paging = paging;
    }

    public boolean isPagingApplied() {
        return pagingApplied;
    }

    public void setPagingApplied(boolean pagingApplied) {
        this.pagingApplied = pagingApplied;
    }

    public Map<String, Map<String, String>> getColumnSortValuesMap() {
    	if (columnSortValuesMap == null) {
    		return Collections.emptyMap();
    	}
    	
    	return Collections.unmodifiableMap(columnSortValuesMap);
    }
    
    public void addColumnSortValue(final String columnName, final String originValue, final String sortByValue) {
    	if (columnSortValuesMap == null) {
    		columnSortValuesMap = new HashMap<>();
    	}
    	
    	Map<String, String> sortValuesMap = columnSortValuesMap.get(columnName);
    	if (sortValuesMap == null) {
    		sortValuesMap = new HashMap<>();
    		columnSortValuesMap.put(columnName, sortValuesMap);
    	}
    	
    	sortValuesMap.put(originValue, sortByValue != null ? sortByValue : originValue);
    }
    
    @Override
    public boolean equals(final Object o) {
        if (!(o instanceof DataAggregation)) {
            return false;
        }

        if (!super.equals(o)) {
            return false;
        }

        final DataAggregation that = (DataAggregation) o;

        if (!Objects.equals(paging, that.paging)) {
            return false;
        }

        if (pagingApplied != that.pagingApplied) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().appendSuper(super.hashCode()).append(paging)
                .append(pagingApplied).toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).appendSuper(super.toString()).append("paging", paging)
                .append("pagingApplied", pagingApplied).toString();
    }
}
