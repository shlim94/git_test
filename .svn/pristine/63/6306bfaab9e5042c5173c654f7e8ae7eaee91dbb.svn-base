package com.wise.comp.pivotgrid.aggregator;

import java.lang.ref.WeakReference;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.wise.common.util.ServiceTimeoutUtils;
import com.wise.common.util.StringCompareUtils;
import com.wise.common.util.WINumberUtils;
import com.wise.comp.model.AbstractSummaryContainer;
import com.wise.comp.model.DataAggregation;
import com.wise.comp.model.DataFrame;
import com.wise.comp.model.DataGroup;
import com.wise.comp.model.DataRow;
import com.wise.comp.model.SummaryContainer;
import com.wise.comp.model.SummaryType;
import com.wise.comp.model.SummaryValue;
import com.wise.comp.pivotgrid.aggregator.util.DataGroupComparator;
import com.wise.comp.pivotgrid.param.FilterParam;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.PagingParam;
import com.wise.comp.pivotgrid.param.SortInfoParam;
import com.wise.comp.pivotgrid.param.SummaryParam;
import com.wise.comp.pivotgrid.param.TopBottomParam;
import com.wise.comp.pivotgrid.param.UdfGroupParam;
import com.wise.comp.pivotgrid.util.DataAggregationUtils;
import com.wise.ds.repository.controller.ReportController;

@Service
public class DataAggregator {
	private static final Logger logger = LoggerFactory.getLogger(ReportController.class);
	
	private static final BigDecimal ZERO_VALUE = BigDecimal.valueOf(0);
	
	private static final BigDecimal ONE_VALUE = BigDecimal.valueOf(1);

    private static final BigDecimal MAX_VALUE = new BigDecimal("9223372036854775807");

    private static final String WISE_NULL_FIELD = "WISE_NULL_FIELD";
    
    private static int counter = 0;

    @Autowired
    private ExpressionEngine expressionEngine;

    public ExpressionEngine getExpressionEngine() {
        return expressionEngine;
    }

    public void setExpressionEngine(ExpressionEngine expressionEngine) {
        this.expressionEngine = expressionEngine;
    }
    public WeakReference<DataAggregation> createDataAggregation(final DataFrame dataFrame,
            final FilterParam rootFilter, final List<UdfGroupParam> udfGroupParams,
            final List<GroupParam> groupParams, final List<SummaryParam> groupSummaryParams,
            final List<SummaryParam> totalSummaryParams, final PagingParam pagingParam,
            final List<SortInfoParam> sortInfoParams, final TopBottomParam topBottomParam) throws Exception {
    	return createDataAggregation(dataFrame, rootFilter, udfGroupParams, groupParams, groupSummaryParams, totalSummaryParams, pagingParam, sortInfoParams, topBottomParam, false);
    }

    public WeakReference<DataAggregation> createDataAggregation(final DataFrame dataFrame,
            final FilterParam rootFilter, final List<UdfGroupParam> udfGroupParams,
            final List<GroupParam> groupParams, final List<SummaryParam> groupSummaryParams,
            final List<SummaryParam> totalSummaryParams, final PagingParam pagingParam,
            final List<SortInfoParam> sortInfoParams, final TopBottomParam topBottomParam, final boolean skipSorting)
            throws Exception {
    	WeakReference<DataAggregation> dataAggregation = new WeakReference<DataAggregation>(new DataAggregation());
        final boolean hasSortInfoParams = sortInfoParams != null && !sortInfoParams.isEmpty();

        boolean fullPagingMode = false;
        boolean pagingRelevantViewMode = false;
        List<GroupParam> effectivePagingRowGroupParams = Collections.emptyList();

        if (pagingParam != null) {
            final int pageRowGroupCount = pagingParam.getRowGroupCount();
            effectivePagingRowGroupParams = getPagingRowGroupParamsInGroupParams(pagingParam, groupParams);
            final int effectivePagingRowGroupCount = effectivePagingRowGroupParams.size();

            if (effectivePagingRowGroupCount > 0) {
                fullPagingMode = effectivePagingRowGroupCount == pageRowGroupCount;
                pagingRelevantViewMode = effectivePagingRowGroupCount < pageRowGroupCount;
            }
        }

        WeakReference<DataAggregation> pageAggregation = !fullPagingMode && pagingRelevantViewMode
                ? new WeakReference<DataAggregation>(new DataAggregation()) : null;
        
        long startMili = System.currentTimeMillis();
		long checkMili = 0;
		double checkMin = 0;
		int localCounter = 0;
        for (Iterator<DataRow> it = dataFrame.iterator(); it.hasNext();) {
            final DataRow row = it.next();

            if (rootFilter != null && !isIncludedByRootFilter(row, rootFilter)) {
                continue;
            }

            if (udfGroupParams != null && !udfGroupParams.isEmpty()) {
                resolveCustomColumnsInDataRow(row, udfGroupParams);
            }

            updateSummaryContainerSummary(dataAggregation.get(), row, totalSummaryParams);

            contributeDataRowToDataAggregationOnEachGroup(row, dataAggregation.get(), groupParams,
                    groupSummaryParams);

            if(hasSortInfoParams) {
            	addColumnSortValues(row, dataAggregation.get(), sortInfoParams);
            }
            

            if (pageAggregation != null) {
            	updateSummaryContainerSummary(pageAggregation.get(), row, totalSummaryParams);
            	
                contributeDataRowToDataAggregationOnEachGroup(row, pageAggregation.get(),
                        pagingParam.getRowGroupParams(), groupSummaryParams);
            }
            
            if(localCounter % 200 == 0) {
            	ServiceTimeoutUtils.checkServiceTimeout();
            }
            localCounter++;
        }
        
        checkMili = System.currentTimeMillis();
        checkMin = (checkMili - (double) startMili) / 1000;
        System.out.println("Datarow to DataAggregation : " + checkMin + "초");
        
        
        startMili = System.currentTimeMillis();
		checkMili = 0;
		checkMin = 0;
        if (topBottomParam != null && !topBottomParam.getDataFieldName().equalsIgnoreCase("")) {
        	topBottomDataAggregation(dataAggregation.get(), topBottomParam, groupSummaryParams);
        	
        	if (pageAggregation != null) {
        		topBottomDataAggregation(pageAggregation.get(), topBottomParam, groupSummaryParams);
        	}
        }else {
        	if (hasSortInfoParams && !skipSorting) {
        		counter = 0;
                sortDataAggregation(dataAggregation.get(), sortInfoParams);

                if (pageAggregation != null) {
                	counter = 0;
                    sortDataAggregation(pageAggregation.get(), sortInfoParams);
                }
            }
        }

        if (udfGroupParams != null && !udfGroupParams.isEmpty()) {
            recalculateUdfSummaryValues(dataAggregation.get(), udfGroupParams);
        }
        
        startMili = System.currentTimeMillis();
		checkMili = 0;
		checkMin = 0;
        if (fullPagingMode) {
            DataAggregationUtils.markPaginatedSummaryContainersVisible(dataAggregation.get(), pagingParam);
            dataAggregation.get().setPagingApplied(true);
        }
        else if (pagingRelevantViewMode) {
            DataAggregationUtils.markPaginatedSummaryContainersVisible(pageAggregation.get(), pagingParam);
            pageAggregation.get().setPagingApplied(true);

            DataAggregationUtils.resetContainersVisibility(dataAggregation.get(), true);
            DataAggregationUtils.markRelevantSummaryContainersVisible(dataAggregation.get(),
                    pageAggregation.get(), pagingParam.getRowGroupParams(), 0);
            dataAggregation.get().setPagingApplied(true);
        }

        return dataAggregation;
    }

    private void resolveCustomColumnsInDataRow(final DataRow row,
            final List<UdfGroupParam> udfGroupParams) {
        for (UdfGroupParam udfGroupParam : udfGroupParams) {
            final String name = udfGroupParam.getName();
            final String expression = udfGroupParam.getExpression();

            if (StringUtils.isBlank(name) || StringUtils.isBlank(expression)) {
                break;
            }

            final List<String> selectors = udfGroupParam.getSelectors();
            final List<String> groupIntervals = udfGroupParam.getGroupIntervals();

            final int selectorCount = selectors.size();
            final int groupIntervalCount = groupIntervals.size();

            Map<String, Object> context = null;

            if (selectorCount > 0) {
                context = new HashMap<>();

                for (int i = 0; i < selectorCount; i++) {
                    final String selector = selectors.get(i);
                    final String groupInterval = i < groupIntervalCount ? groupIntervals.get(i) : null;
                    final String value = row.getStringValue(selector, groupInterval);

                    if (value != null) {
                        context.put(selector, WINumberUtils.isNumber(value) ? new BigDecimal(value) : value);
                    }
                }
            }

            final Object ret = expressionEngine.evaluate(context, expression, null);
            row.setCustomColumnValue(name, ret != null ? ret : "");
        }
    }
    
    private void addColumnSortValues(final DataRow row, final DataAggregation dataAggregation,
    		final List<SortInfoParam> sortInfoParams) {
    	for (SortInfoParam sortInfoParam : sortInfoParams) {
    		final String dataField = sortInfoParam.getDataField();
    		final String sortByField = sortInfoParam.getSortByField();
    		
    		final String dataFieldValue = row.getStringValue(dataField);
    		
    		if (StringUtils.isNotEmpty(dataFieldValue)) {
    			final String sortByFieldValue = StringUtils.isEmpty(sortByField) ? dataFieldValue
    					: row.getStringValue(sortByField);
    			dataAggregation.addColumnSortValue(dataField, dataFieldValue,
    					sortByFieldValue);
    		}
    	}
    }

    private void contributeDataRowToDataAggregationOnEachGroup(final DataRow row,
            final DataAggregation dataAggregation, final List<GroupParam> groupParams,
            List<SummaryParam> groupSummaryParams) {
        AbstractSummaryContainer<?> parentGroup = dataAggregation;

        for (GroupParam groupParam : groupParams) {
            parentGroup.setChildDataGroupKey(groupParam.getKey());

            final String columnName = groupParam.getSelector();
            final String dateInterval = groupParam.getGroupInterval();
            final String key = row.getStringValue(columnName, dateInterval);

            DataGroup childDataGroup = parentGroup.getChildDataGroup(key);
            if (childDataGroup == null) {
                childDataGroup = parentGroup.addChildDataGroup(key);
            }

            if (!groupSummaryParams.isEmpty()) {
                updateSummaryContainerSummary(childDataGroup, row, groupSummaryParams);
            }

            parentGroup = childDataGroup;
        }
    }

    private <T> void updateSummaryContainerSummary(final SummaryContainer<T> summaryContainer,
            final DataRow dataRow, final List<SummaryParam> summaryParams) {
        final int size = summaryParams != null ? summaryParams.size() : 0;

        if (size == 0) {
            return;
        }

        int localCounter = 0;
        if (summaryContainer.getSummaryValues() == null) {
            for (int i = 0; i < size; i++) {
                final SummaryParam summaryParam = summaryParams.get(i);
                final String fieldName = summaryParam.getSelector();
                final SummaryType summaryType = summaryParam.getSummaryType();
                final String precision = summaryParam.getPrecision();
                final String precisionOption = summaryParam.getPrecisionOption();

                if (SummaryType.MIN == summaryParam.getSummaryType()) {
                    summaryContainer.addSummaryValue(new SummaryValue(fieldName, summaryType, MAX_VALUE,  precision, precisionOption));
                }
                else {
                    summaryContainer.addSummaryValue(new SummaryValue(fieldName, summaryType, null ,precision, precisionOption));
                }
                
                if(localCounter % 200 == 0) {
                	ServiceTimeoutUtils.checkServiceTimeout();
                }
                localCounter++;
            }
        }

        final List<SummaryValue> groupSummaryValues = summaryContainer.getSummaryValues();
        localCounter = 0;
        for (int i = 0; i < size; i++) {
            final SummaryParam groupSummaryParam = summaryParams.get(i);
            final String summaryColumnName = groupSummaryParam.getSelector();
            
            if (dataRow.isString(summaryColumnName)) {
            	String newValue = dataRow.getStringValue(summaryColumnName);
            	
            	if(newValue == null) {
            		newValue = "0";
            	}
            	
            	final SummaryValue summaryValue = groupSummaryValues.get(i);
            	if (summaryValue.getTextValue() == null && !WINumberUtils.isNumber(newValue)) {
            		summaryValue.setTextValue(newValue);
        		}
            	if(summaryValue.getTextValue() != null) {
            		if(StringCompareUtils.compare(summaryValue.getTextValue(), newValue) == -1) {
            			summaryValue.setTextValue(newValue);
            		}
            	}
            } else {
                final SummaryValue summaryValue = groupSummaryValues.get(i);
                summaryValue.incrementCount();

                final BigDecimal curValue = summaryValue.getValue();
                BigDecimal newValue;
                switch (groupSummaryParam.getSummaryType()) {
                case SUM:
                case AVERAGE:
                case AVG:
                case CUSTOM:
                    newValue = dataRow.getBigDecimalValue(summaryColumnName);
                    if (newValue == null) {
                    	newValue = ZERO_VALUE;
                    }
                    summaryValue.addSum(newValue);
                    break;
                case COUNTDISTINCT:
                	newValue = dataRow.getBigDecimalValue(summaryColumnName);
                    if (newValue == null) {
                    	newValue = ONE_VALUE;
                    }
                    summaryValue.addDistinctValue(newValue);
                    break;
                case MIN:
                	newValue = dataRow.getBigDecimalValue(summaryColumnName);
                    if (newValue == null) {
                    	newValue = MAX_VALUE;
                    }
                    summaryValue.setValue((curValue != null ? curValue : MAX_VALUE).min(newValue));
                    break;
                case MAX:
                	newValue = dataRow.getBigDecimalValue(summaryColumnName);
                    if (newValue == null) {
                    	newValue = ZERO_VALUE;
                    }
                    summaryValue.setValue((curValue != null ? curValue : ZERO_VALUE).max(newValue));
                    break;
                default:
                    break;
                }
            }
            
            if(localCounter % 200 == 0) {
            	ServiceTimeoutUtils.checkServiceTimeout();
            }
            localCounter++;
        }
    }

    private boolean isIncludedByRootFilter(final DataRow row, final FilterParam rootFilter) {
        final FilterParam firstChild = rootFilter.getFirstChild();

        if (firstChild == null) {
            return true;
        }
        
       return isIncludedByRootFilterLoop(row,rootFilter);
    }
    
    private boolean isIncludedByRootFilterLoop(final DataRow row, final FilterParam rootFilter) {
        
        
        boolean isIncludedByRootFilter = false;
        
        for( int i = 0; i < rootFilter.getChildCount(); i++) {
        	FilterParam rootFilterChild = rootFilter.getChildren().get(i);
        	
        	if (rootFilterChild.hasChild()) {
        		isIncludedByRootFilter =  isIncludedByContainerFilter(row, rootFilterChild);
            }
            else {
            	isIncludedByRootFilter =  isIncludedByLeafFilter(row, rootFilterChild);
            }
        	
        	if(isIncludedByRootFilter) {
        		break;
        	}
        }

        return isIncludedByRootFilter;
    }

    private boolean isIncludedByContainerFilter(final DataRow row,
            final FilterParam containerFilter) {
        if (containerFilter.getChildCount() < 2) {
            return false;
        }

        final String operator = containerFilter.getOperator();
        final FilterParam childFilter1 = containerFilter.getChildren().get(0);
        final FilterParam childFilter2 = containerFilter.getChildren().get(1);

        if ("and".equals(operator)) {
            return (childFilter1.hasChild() ? isIncludedByContainerFilter(row, childFilter1)
                    : isIncludedByLeafFilter(row, childFilter1))
                    && (childFilter2.hasChild() ? isIncludedByContainerFilter(row, childFilter2)
                            : isIncludedByLeafFilter(row, childFilter2));
        }

        if ("or".equals(operator)) {
            return (childFilter1.hasChild() ? isIncludedByContainerFilter(row, childFilter1)
                    : isIncludedByLeafFilter(row, childFilter1))
                    || (childFilter2.hasChild() ? isIncludedByContainerFilter(row, childFilter2)
                            : isIncludedByLeafFilter(row, childFilter2));
        }

        return true;
    }

    private boolean isIncludedByLeafFilter(final DataRow row, final FilterParam leafFilter) {
        final String operator = leafFilter.getOperator();
        final String[] selectorTokens = StringUtils.split(leafFilter.getSelector(), ".", 2);
        final String columnName = selectorTokens[0];
        final String dateInterval = selectorTokens.length > 1 ? selectorTokens[1] : null;
        final String comparingValue = leafFilter.getComparingValue();

        final String rowValue = row.getStringValue(columnName, dateInterval);

        if ("=".equals(operator)) {
            if (!Objects.equals(comparingValue, rowValue)) {
                return false;
            }
        }
        else if ("<".equals(operator)) {
            if (comparingValue.compareTo(rowValue) <= 0) {
                return false;
            }
        }
        else if (">".equals(operator)) {
            if (comparingValue.compareTo(rowValue) >= 0) {
                return false;
            }
        }
        else if ("<=".equals(operator)) {
            if (comparingValue.compareTo(rowValue) < 0) {
                return false;
            }
        }
        else if (">=".equals(operator)) {
            if (comparingValue.compareTo(rowValue) > 0) {
                return false;
            }
        }

        return true;
    }

    private List<GroupParam> getPagingRowGroupParamsInGroupParams(final PagingParam pagingParam,
            final List<GroupParam> groupParams) {
        final List<GroupParam> pageRowGroupParams = new ArrayList<>();

        final int pageRowGroupCount = pagingParam.getRowGroupCount();
        final int groupCount = groupParams.size();
        final List<GroupParam> rowGroupParams = pagingParam.getRowGroupParams();

        for (int i = 0; i < Math.min(pageRowGroupCount, groupCount); i++) {
            final GroupParam rowGroupParam = rowGroupParams.get(i);
            final GroupParam groupParam = groupParams.get(i);

            if (StringUtils.equals(rowGroupParam.getKey(), groupParam.getKey())) {
                pageRowGroupParams.add(rowGroupParam);
            }
        }

        return pageRowGroupParams;
    }

    private void sortDataAggregation(final DataAggregation dataAggregation,
            final List<SortInfoParam> sortInfoParams) {
    	if(dataAggregation.getChildDataGroupKey() != null) {
    		sortDataGroups(dataAggregation.getChildDataGroupKey().split(":")[0], dataAggregation,
                    sortInfoParams);
    	}
    }

    private <T> void sortDataGroups(final String groupKey,
            AbstractSummaryContainer<T> dataAggregation, final List<SortInfoParam> sortInfoParams) {
        String sortByField = WISE_NULL_FIELD;
        int tempSortOrder = 1;

        final List<DataGroup> dataGroups = dataAggregation.getChildDataGroups();

        // 정렬 기준 컬럼 선정
        for (int i = 0; i < sortInfoParams.size(); i++) {
            if (groupKey.equals(sortInfoParams.get(i).getDataField())) {
                sortByField = sortInfoParams.get(i).getSortByField();

                if ("desc".equals(sortInfoParams.get(i).getSortOrder())) {
                    tempSortOrder = -1;
                }
            }
        }

        final DataGroup firstDataGroup = dataGroups.get(0);
        final List<SummaryValue> summaryValues = firstDataGroup.getSummaryValues();
        int sortByMeasure = -1;

        final int summaryValueCount = summaryValues != null ? summaryValues.size() : 0;

        for (int i = 0; i < summaryValueCount; i++) {
            if (sortByField.equals(summaryValues.get(i).getFieldName())) {
                sortByMeasure = i;
                break;
            }
        }

        final int sortOrder = tempSortOrder;

        final Comparator<DataGroup> dataGroupComparator = new DataGroupComparator(sortByMeasure,
                sortOrder);

        dataAggregation.sortChildDataGroups(dataGroupComparator);

        // 자식 sort
        if (dataGroups.get(0).getChildDataGroups() != null
                && dataGroups.get(0).getChildDataGroups().size() > 0) {
            for (int i = 0; i < dataGroups.size(); i++) {
            	if(dataGroups.get(i).getChildDataGroupKey() != null) {
            		sortDataGroups(dataGroups.get(i).getChildDataGroupKey().split(":")[0],
                            dataGroups.get(i), sortInfoParams);
            	}
            	if(counter % 200 == 0) {
                	ServiceTimeoutUtils.checkServiceTimeout();
                }
            	counter++;
            }
        }
    }
    
    private void topBottomDataAggregation(final DataAggregation dataAggregation,
            final TopBottomParam topBottomParam, final List<SummaryParam> groupSummaryParams) {
    	topBottomDataGroup(dataAggregation, topBottomParam, groupSummaryParams);
    }
    
	private <T> void topBottomDataGroup(AbstractSummaryContainer<T> dataAggregation, 
			final TopBottomParam topBottomParam, final List<SummaryParam> summaryParams) {
		final String groupKey = StringUtils.substringBefore(dataAggregation.getChildDataGroupKey(), ":");
    	String sortByField = WISE_NULL_FIELD;
    	int tempSortOrder = -1;
    	
    	List<DataGroup> dataGroups = dataAggregation.getChildDataGroups(); 
    	List<DataGroup> dataGroupOthers = null;
    	
    	if(StringUtils.equals(groupKey, topBottomParam.getApplyFieldName())) {
			sortByField = topBottomParam.getDataFieldName();
			if("Bottom".equals(topBottomParam.getTopBottomType())) {
				tempSortOrder = 1;
			}
		}
    	
    	//TopBottom 기준 컬럼
    	 final DataGroup firstDataGroup = dataGroups.get(0);
         final List<SummaryValue> summaryValues = firstDataGroup.getSummaryValues();
         int sortByMeasure = -1;

         final int summaryValueCount = summaryValues != null ? summaryValues.size() : 0;

         for (int i = 0; i < summaryValueCount; i++) {
             if (sortByField.equals(summaryValues.get(i).getFieldName())) {
                 sortByMeasure = i;
                 break;
             }
         }

         final int sortOrder = tempSortOrder;
    	
    	/*큰 순서대로 정렬후 top 설정*/
		final Comparator<DataGroup> dataGroupComparator = new DataGroupComparator(sortByMeasure,
            sortOrder);
    	
    	dataAggregation.sortChildDataGroups(dataGroupComparator);
    	
    	
    	
    	int dGroupSize = dataGroups.size();
    	int TopBottomCount = topBottomParam.getTopBottomCount() == 0 ? dGroupSize : topBottomParam.getTopBottomCount();
    	
    	
    	if(topBottomParam.isInPercent()) {
    		TopBottomCount = (int) Math.ceil((dGroupSize*TopBottomCount)/100);
    	}
    	
    	if(TopBottomCount >= dGroupSize) {
    		dataGroups = new LinkedList<>(dataGroups.subList(0, dGroupSize));
    		
    	}else {
    		if(topBottomParam.isShowOthers()) {
    			
    			final DataGroup summaryContainer = new DataGroup("기타");
    			
    			dataGroupOthers = dataGroups.subList(TopBottomCount, dGroupSize);
    			dataGroups = new LinkedList<>(dataGroups.subList(0, TopBottomCount));
    			int size = dataGroupOthers.size();
    			int sizeSummury = summaryParams.size();
    			
    			final SummaryParam groupSummaryParam = summaryParams.get(sortByMeasure);
    			
    			
    			if (summaryContainer.getSummaryValues() == null) {
    	            for (int i = 0; i < sizeSummury; i++) {
    	                final SummaryParam summaryParam = summaryParams.get(i);
    	                final String fieldName = summaryParam.getSelector();
    	                final SummaryType summaryType = summaryParam.getSummaryType();
    	                final String precision = summaryParam.getPrecision();
    	                final String precisionOption = summaryParam.getPrecisionOption();

    	                if (SummaryType.MIN == summaryParam.getSummaryType()) {
    	                    summaryContainer.addSummaryValue(new SummaryValue(fieldName, summaryType, MAX_VALUE, precision, precisionOption));
    	                }
    	                else {
    	                    summaryContainer.addSummaryValue(new SummaryValue(fieldName, summaryType, null , precision, precisionOption));
    	                }
    	            }
    	        }
    			
    			final List<SummaryValue> groupSummaryValues = summaryContainer.getSummaryValues();
    			 
    			for (int i = 0; i < size; i++) {
    				for(int j  = 0 ; j < sizeSummury; j ++) {
    					final SummaryValue summaryValue = groupSummaryValues.get(j);
	    	            summaryValue.incrementCount();

	    	            final BigDecimal curValue = summaryValue.getValue();
	    	            BigDecimal newValue;
        	            switch (groupSummaryParam.getSummaryType()) {
        	            case SUM:
        	            case AVERAGE:
        	            case AVG:
        	            case CUSTOM:
        	            	newValue = dataGroupOthers.get(i).getSummaryValues().get(j).getRepresentingValue();
        	            	if (newValue == null) {
        	            		newValue = ZERO_VALUE;
        	            	}
        	                summaryValue.addSum(newValue);
        	                break;
        	            case COUNTDISTINCT:
        	            	newValue = dataGroupOthers.get(i).getSummaryValues().get(j).getRepresentingValue();
        	            	if (newValue == null) {
        	            		newValue = ONE_VALUE;
        	            	}
        	                summaryValue.addDistinctValue(newValue);
        	                break;
        	            case MIN:
        	            	newValue = dataGroupOthers.get(i).getSummaryValues().get(j).getRepresentingValue();
        	            	if (newValue == null) {
        	            		newValue = MAX_VALUE;
        	            	}
        	                summaryValue.setValue((curValue != null ? curValue : MAX_VALUE).min(newValue));
        	                break;
        	            case MAX:
        	            	newValue = dataGroupOthers.get(i).getSummaryValues().get(j).getRepresentingValue();
        	            	if (newValue == null) {
        	            		newValue = ZERO_VALUE;
        	            	}
        	                summaryValue.setValue((curValue != null ? curValue : ZERO_VALUE).max(newValue));
        	                break;
        	            default:
        	                break;
        	            }
    				}
    	        }
    			
    			summaryContainer.setKey("기타");
    			summaryContainer.setIsOtherData(true);
    			summaryContainer.setDepth(dataGroupOthers.get(0).getDepth());
    			summaryContainer.setParent(dataAggregation);
    			dataGroups.add(summaryContainer);
    		}else {
    			
    			dataGroups = dataGroups.subList(0, TopBottomCount);
    		}
    		
    	}
    	
    	dataAggregation.setChildDataGroups(dataGroups);
		
		// 자식 sort
        if (dataGroups.get(0).getChildDataGroups() != null
                && dataGroups.get(0).getChildDataGroups().size() > 0) {
            for (int i = 0; i < dataGroups.size(); i++) {
            	if(!dataGroups.get(i).getIsOtherData()) {
            		topBottomDataGroup(dataGroups.get(i), topBottomParam,summaryParams );
            	}
            }
        }
    }

    void recalculateUdfSummaryValues(final AbstractSummaryContainer<?> summaryContainer,
            final List<UdfGroupParam> udfGroupParams) {
        final List<DataGroup> childDataGroups = summaryContainer.getChildDataGroups();

        final Map<String, SummaryValue> summaryValuesMap = new HashMap<>();
        final List<SummaryValue> summaryValues = summaryContainer.getSummaryValues();
        
        if (summaryValues != null && !summaryValues.isEmpty()) {
        	// foreach지만 null이면 에러남
        	for (SummaryValue summaryValue : summaryValues) {
                summaryValuesMap.put(summaryValue.getFieldName(), summaryValue);
            }
        	
            for (UdfGroupParam udfGroupParam : udfGroupParams) {
                final SummaryValue selfSummaryValue = summaryValuesMap.get(udfGroupParam.getName());

                if (selfSummaryValue == null) {
                    continue;
                }

                final String name = udfGroupParam.getName();
                final String expression = udfGroupParam.getExpression();

                if (StringUtils.isBlank(name) || StringUtils.isBlank(expression)) {
                    break;
                }

                 Map<String, Object> context = null;

                context = new HashMap<>();

                for (SummaryValue summaryValue : summaryValues) {
                    context.put(summaryValue.getFieldName(), summaryValue.getRepresentingValue());
                }

                final Object ret = expressionEngine.evaluate(context, expression, null);
                BigDecimal numValue = null;

                if (ret instanceof BigDecimal) {
                    numValue = (BigDecimal) ret;
                }
                else if (ret instanceof Number) {
                    numValue = new BigDecimal(ret.toString());
                }

                if (numValue != null) {
                    switch (selfSummaryValue.getSummaryType()) {
                    case MIN:
                    case MAX:
                        selfSummaryValue.setValue(numValue);
                        break;
                    case SUM:
                    case CUSTOM:
                        selfSummaryValue.setSum(numValue);
                        selfSummaryValue.setValue(numValue);
                        break;
                    case COUNT:
                        selfSummaryValue.setCount(numValue.longValue());
                        break;
                    default:
                        break;
                    }
                }
            }
        }


        if (childDataGroups != null && !childDataGroups.isEmpty()) {
            for (DataGroup childDataGroup : childDataGroups) {
                recalculateUdfSummaryValues(childDataGroup, udfGroupParams);
            }
        }
    }
}
