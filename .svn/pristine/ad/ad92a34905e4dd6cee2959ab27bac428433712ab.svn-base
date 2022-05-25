package com.wise.comp.pivotmatrix.impl;

import java.lang.ref.WeakReference;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wise.comp.model.AbstractSummaryContainer;
import com.wise.comp.model.DataAggregation;
import com.wise.comp.model.DataGroup;
import com.wise.comp.model.Paging;
import com.wise.comp.model.SummaryType;
import com.wise.comp.model.SummaryValue;
import com.wise.comp.pivotgrid.aggregator.ExpressionEngine;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.SortInfoParam;
import com.wise.comp.pivotgrid.param.SummaryParam;
import com.wise.comp.pivotgrid.param.UdfGroupParam;
import com.wise.comp.pivotmatrix.SummaryCell;
import com.wise.comp.pivotmatrix.SummaryDimension;
import com.wise.comp.pivotmatrix.SummaryDimensionComparator;
import com.wise.comp.pivotmatrix.SummaryMatrix;
import com.wise.comp.pivotmatrix.SummaryMatrixFactory;

public class DefaultSummaryFactoryImpl extends SummaryMatrixFactory {

    private static Logger log = LoggerFactory.getLogger(DefaultSummaryFactoryImpl.class);

    private static final BigDecimal ZERO_VALUE = BigDecimal.valueOf(0);

    private static final BigDecimal MAX_VALUE = new BigDecimal("9223372036854775807");

    public DefaultSummaryFactoryImpl() {
    	super();
    }

    @Override
    public WeakReference<SummaryMatrix> doSlicePageSummaryMatrix(final SummaryMatrix matrix,
            final Paging paging) {
        final int rowDimensionMaxDepth = matrix.getRowGroupParams().size();

        if (paging.getOffset() < 0 || paging.getLimit() <= 0) {
            return createEmptyPageSummaryMatrix(matrix);
        }

        final int distinctRows = matrix.getRows();

        final List<Integer> pageableRowIndices = new LinkedList<>();

        for (int i = 0; i < distinctRows; i++) {
            pageableRowIndices.add(i);
        }

        insertAncestorRowIndicesForPaging(pageableRowIndices, matrix, paging.getLimit(),
                rowDimensionMaxDepth);

        final int pageableTotalRows = pageableRowIndices.size();

        final int beginIndex = paging.getOffset();
        final int endIndex = Math.min(pageableTotalRows, beginIndex + paging.getLimit());

        final List<Integer> pagedRowIndices = pageableRowIndices.subList(beginIndex, endIndex);
        final int count = pagedRowIndices.size();

        paging.setTotal(pageableTotalRows);
        paging.setDistinctTotal(distinctRows);
        paging.setCount(count);

        if (beginIndex >= pageableTotalRows || count <= 0) {
            return createEmptyPageSummaryMatrix(matrix);
        }

        final WeakReference<SummaryMatrix> sliced = new WeakReference<SummaryMatrix>(matrix.sliceRows(pagedRowIndices));
        ((DefaultSummaryMatrixImpl) sliced.get()).setCacheKey(matrix.getCacheKey());
        
        return sliced;
    }

    private void insertAncestorRowIndicesForPaging(final List<Integer> pageRowIndices,
            final SummaryMatrix matrix, final int pageSize, final int rowDimensionMaxDepth) {
        if (pageSize < rowDimensionMaxDepth + 1) {
            // If pageSize is smaller than group dimension count including the root,
            // then it's dangerous to continue due to potential infinite loop. So stop here then.
            return;
        }

        final SummaryDimension[] flattendedRowDimensions = matrix.getRowFlattendSummaryDimensions();

        int offset = 0;

        while (offset < pageRowIndices.size()) {
            final SummaryDimension rowDimension = flattendedRowDimensions[pageRowIndices.get(offset)];
            SummaryDimension parentRowDimension = findParentSummaryDimension(matrix, flattendedRowDimensions, rowDimension);

            while (parentRowDimension != null) {
                final int parentRowIndex = matrix
                        .getRowIndexByDimensionPath(parentRowDimension.getPath());

                if (parentRowIndex >= 0) {
                    pageRowIndices.add(offset, parentRowIndex);
                    parentRowDimension = findParentSummaryDimension(matrix, flattendedRowDimensions, parentRowDimension);
                }
            }

            offset += pageSize;
        }
    }

    @Override
    public WeakReference<SummaryMatrix> doCreateEmptyPageSummaryMatrix(final SummaryMatrix matrix) {
        final SummaryDimensionImpl rowDimension = new SummaryDimensionImpl();
        return new WeakReference<SummaryMatrix>(new DefaultSummaryMatrixImpl(matrix.getRowGroupParams(), matrix.getColGroupParams(),
                matrix.getSummaryParams(), rowDimension, matrix.getColSummaryDimension()));
    }

    @Override
    public WeakReference<SummaryMatrix> doCreateSummaryMatrixFromFullyExpandedDataAggregation(
            final DataAggregation dataAggregation, final String cacheKey, final List<GroupParam> rowGroupParams,
            final List<GroupParam> colGroupParams, final List<SummaryParam> summaryParams,
            final List<SortInfoParam> sortInfoParams, final List<UdfGroupParam> udfGroupParams) {
        final int rowDimensionMaxDepth = rowGroupParams.size();
        final SummaryDimensionImpl rowDimension = new SummaryDimensionImpl();
        final SummaryDimensionImpl colDimension = new SummaryDimensionImpl();

        final List<DataGroup> childGroups = dataAggregation.getChildDataGroups();
        final int childCount = childGroups != null ? childGroups.size() : 0;

        if (childCount > 0) {
            for (DataGroup dataGroup : childGroups) {
                fillRowAndColSummaryDimensions(dataGroup, rowDimensionMaxDepth, rowDimension,
                        colDimension);
            }
            
            final Map<String, SortInfoParam> sortInfoParamsMap = new HashMap<>();
            if (sortInfoParams != null) {
            	for (SortInfoParam sortInfoParam : sortInfoParams) {
            		sortInfoParamsMap.put(sortInfoParam.getDataField(), sortInfoParam);
            	}
            }
            
            if(!sortInfoParamsMap.isEmpty()) {
            	sortSummaryDimensions(colDimension, sortInfoParamsMap,
                		dataAggregation.getColumnSortValuesMap());
            	sortSummaryDimensions(rowDimension, sortInfoParamsMap,
                		dataAggregation.getColumnSortValuesMap());
            }
            
        }

        final DefaultSummaryMatrixImpl matrix = new DefaultSummaryMatrixImpl(rowGroupParams,
                colGroupParams, summaryParams, rowDimension, colDimension);

        fillSummaryValuesOfDataGroups(matrix, dataAggregation, rowDimensionMaxDepth);

        calculateEmptyParentSummaryCells(matrix, udfGroupParams);

        matrix.setCacheKey(cacheKey);

        return new WeakReference<SummaryMatrix>(matrix);
    }
    
    private void sortSummaryDimensions(final SummaryDimensionImpl dimension,
    		final Map<String, SortInfoParam> sortInfoParamsMap,
    		final Map<String, Map<String, String>> columnSortValues) {
    	if (!dimension.hasChild()) {
    		return;
    	}
    	
    	final String childColumnName = StringUtils.substringBefore(dimension.getChildDataGroupKey(), ":");
    	
    	final SortInfoParam sortInfoParam = sortInfoParamsMap.get(childColumnName);
    	
    	if (sortInfoParam != null) {
    		final boolean descending = "desc".equals(sortInfoParam.getSortOrder());
    		final Map<String, String> columnValuesMap = columnSortValues.get(childColumnName);
    		final Comparator<SummaryDimension> comparator = new SummaryDimensionComparator(
    				columnValuesMap, descending);
    		dimension.sortChildSummaryDimensions(comparator);
    	}
    	
    	for (SummaryDimension childDimension : dimension.getChildren()) {
    		sortSummaryDimensions((SummaryDimensionImpl) childDimension, sortInfoParamsMap, columnSortValues);
    	}
    }

    private void fillRowAndColSummaryDimensions(final DataGroup baseGroup,
            final int rowDimensionMaxDepth, final SummaryDimensionImpl baseRowDimension,
            final SummaryDimension baseColDimension) {
        final int curDepth = baseGroup.getDepth();
        final List<DataGroup> childGroups = baseGroup.getChildDataGroups();
        final int childCount = childGroups != null ? childGroups.size() : 0;

        final AbstractSummaryContainer<?> parent = baseGroup.getParent();
        final String childDataGroupKey = parent != null ? parent.getChildDataGroupKey() : null;
        
        SummaryDimensionImpl childDimension;

        if (curDepth <= rowDimensionMaxDepth) {
        	baseRowDimension.setChildDataGroupKey(childDataGroupKey);
        	
            childDimension = (SummaryDimensionImpl) baseRowDimension.getChild(baseGroup.getKey());

            if (childDimension == null) {
                childDimension = (SummaryDimensionImpl) ((SummaryDimensionImpl) baseRowDimension)
                        .addChild(new SummaryDimensionImpl(baseGroup.getKey()));
            }

            if (childGroups != null && !childGroups.isEmpty()) {
                for (DataGroup childDataGroup : childGroups) {
                    fillRowAndColSummaryDimensions(childDataGroup, rowDimensionMaxDepth,
                            childDimension, baseColDimension);
                }
            }
        }
        else {
        	((SummaryDimensionImpl) baseColDimension).setChildDataGroupKey(childDataGroupKey);
        	
            childDimension = (SummaryDimensionImpl) baseColDimension.getChild(baseGroup.getKey());

            if (childDimension == null) {
                childDimension = (SummaryDimensionImpl) ((SummaryDimensionImpl) baseColDimension)
                        .addChild(new SummaryDimensionImpl(baseGroup.getKey()));
            }

            if (childCount > 0) {
                for (DataGroup childDataGroup : childGroups) {
                    fillRowAndColSummaryDimensions(childDataGroup, rowDimensionMaxDepth,
                            baseRowDimension, childDimension);
                }
            }
        }
    }

    private void fillSummaryValuesOfDataGroups(final DefaultSummaryMatrixImpl matrix,
            final AbstractSummaryContainer<?> baseContainer, final int rowDimensionMaxDepth) {
        final List<DataGroup> childGroups = baseContainer.getChildDataGroups();
        final int childCount = childGroups != null ? childGroups.size() : 0;

        if (childCount > 0) {
            for (DataGroup childDataGroup : childGroups) {
                fillSummaryValuesOfDataGroups(matrix, childDataGroup, rowDimensionMaxDepth);
            }
        }

        final Pair<Integer, Integer> pair = findRowColIndexPair(baseContainer, matrix,
                rowDimensionMaxDepth);

        if (pair != null) {
            final List<SummaryValue> summaryValues = baseContainer.getSummaryValues();
            final SummaryCell[][] summaryCells = matrix.getSummaryCells();
            ((SummaryCellImpl) summaryCells[pair.getLeft()][pair.getRight()]).addSummaryValues(summaryValues);
        }
    }
    
    private SummaryDimension findParentSummaryDimension(final SummaryMatrix matrix, final SummaryDimension[] flattendedRowDimensions, final SummaryDimension dimension) {
    	SummaryDimension parentDimension = dimension.getParent();
    	
    	if(parentDimension == null) {
    		final String parentPath = dimension.getParentPath();
    		if(parentPath != null) {
    			final int parentRowIndex = matrix.getRowIndexByDimensionPath(parentPath);
    			if (parentRowIndex >= 0) {
    				parentDimension = flattendedRowDimensions[parentRowIndex];
    			}
    		}
    	}
    	
    	return parentDimension;
    }

    private void calculateEmptyParentSummaryCells(final SummaryMatrix matrix, final List<UdfGroupParam> udfGroupParams) {
        final List<SummaryParam> summaryParams = matrix.getSummaryParams();
        SummaryDimension[] rowFlattendSummaryDimensions = matrix.getRowFlattendSummaryDimensions();
        SummaryDimension[] colFlattendSummaryDimensions = matrix.getColFlattendSummaryDimensions();
        final SummaryCell[][] summaryCells = matrix.getSummaryCells();
        final boolean hasUdfParams = udfGroupParams != null&& !udfGroupParams.isEmpty();
        

        for (int i = matrix.getRows() - 1; i >= 0; i--) {
        	SummaryDimension rowDimension = rowFlattendSummaryDimensions[i];
        	
            for (int j = matrix.getCols() - 1; j >= 0; j--) {
            	SummaryDimension colDimension = colFlattendSummaryDimensions[j];
                final SummaryCellImpl cell = (SummaryCellImpl) summaryCells[i][j];

                if (!cell.hasSummaryValue()) {
                    final List<Integer> colChildIndices = cell.getColChildCellIndices();
                    final int colChildrenRowIndex = cell.getColChildrenRowIndex();

                    if (colChildIndices != null && !colChildIndices.isEmpty()) {
                        SummaryCellImpl[] childCells = new SummaryCellImpl[colChildIndices.size()];
                        int k = 0;
                        for (Integer index : colChildIndices) {
                            childCells[k++] = (SummaryCellImpl) summaryCells[colChildrenRowIndex][index];
                        }
                        final List<SummaryValue> summaryValues = aggregateSummaryValuesOfCells(
                                childCells, 0, childCells.length, summaryParams);
                        if (summaryValues != null) {
                            cell.addSummaryValues(summaryValues);
                        }
                    }
                }

                if (!cell.hasSummaryValue()) {
                    final List<Integer> rowChildIndices = cell.getRowChildCellIndices();
                    final int rowChildrenColIndex = cell.getRowChildrenColIndex();

                    if (rowChildIndices != null && !rowChildIndices.isEmpty()) {
                        SummaryCell[] childCells = new SummaryCell[rowChildIndices.size()];
                        int k = 0;
                        for (Integer index : rowChildIndices) {
                            childCells[k++] = summaryCells[index][rowChildrenColIndex];
                        }
                        final List<SummaryValue> summaryValues = aggregateSummaryValuesOfCells(
                                childCells, 0, childCells.length, summaryParams);
                        if (summaryValues != null) {
                            cell.addSummaryValues(summaryValues);
                        }
                    }
                }
                
                if(hasUdfParams) {
	                if((rowDimension.hasChild() || colDimension.hasChild())) {
	                	recalculateUdfSummaryValues(cell, udfGroupParams);
	                }
                }
            }
        }
    }
    
    void recalculateUdfSummaryValues(final SummaryCell cell,
            final List<UdfGroupParam> udfGroupParams) {
    	final ExpressionEngine expressionEngine = ExpressionEngine.getCurrentExpressionEngine();

        final Map<String, SummaryValue> summaryValuesMap = new HashMap<>();
        final List<SummaryValue> summaryValues = cell.getSummaryValues();
        
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
    }

    List<SummaryValue> aggregateSummaryValuesOfCells(final SummaryCell[] summaryCells,
            final int beginIndex, final int endIndex, final List<SummaryParam> summaryParams) {
        final int length = endIndex - beginIndex;

        if (length <= 0) {
            return null;
        }

        if (length == 1) {
            return cloneSummaryValueList(summaryCells[0].getSummaryValues());
        }

        final List<SummaryValue> aggregate = new ArrayList<>();
        final int summaryParamCount = summaryParams.size();

        for (int i = 0; i < summaryParamCount; i++) {
            final SummaryParam summaryParam = summaryParams.get(i);
            final String fieldName = summaryParam.getSelector();
            final SummaryType summaryType = summaryParam.getSummaryType();
            final String precision = summaryParam.getPrecision();
            final String precisionOption = summaryParam.getPrecisionOption();
            final SummaryValue summaryValue;
            
            if (SummaryType.MIN == summaryParam.getSummaryType()) {
                summaryValue = new SummaryValue(fieldName, summaryType, MAX_VALUE, precision, precisionOption);
            }
            else {
                summaryValue = new SummaryValue(fieldName, summaryType, ZERO_VALUE , precision , precisionOption);
                summaryValue.setSum(ZERO_VALUE);
            }
            aggregate.add(summaryValue);
        }

        int effectiveCellCount = 0;

        for (int i = beginIndex; i < endIndex; i++) {
            final SummaryCell cell = summaryCells[i];

            if (cell == null || !cell.hasSummaryValue()) {
                continue;
            }

            final List<SummaryValue> summaryValues = cell.getSummaryValues();
            SummaryMatrixUtils.aggregateSummaryValueListTo(aggregate, summaryValues);
            ++effectiveCellCount;
        }

        if (effectiveCellCount == 0) {
            return null;
        }

        return aggregate;
    }

    private List<SummaryValue> cloneSummaryValueList(final List<SummaryValue> sourceList) {
        final List<SummaryValue> clone = new ArrayList<>();
        for (SummaryValue summaryValue : sourceList) {
            clone.add((SummaryValue) summaryValue.clone());
        }
        return clone;
    }

    private Pair<Integer, Integer> findRowColIndexPair(
            final AbstractSummaryContainer<?> container, final DefaultSummaryMatrixImpl matrix,
            final int rowDimensionMaxDepth) {
        final String path = container.getPath();
        final String rowPath;
        final String colPath;
        final int offset = StringUtils.ordinalIndexOf(path, SummaryDimensionImpl.PATH_DELIMITER,
                rowDimensionMaxDepth + 1);

        if (offset == -1) {
            rowPath = path;
            colPath = "";
        }
        else {
            rowPath = path.substring(0, offset);
            colPath = path.substring(offset);
        }

        final int rowIndex = matrix.getRowIndexByDimensionPath(rowPath);
        final int colIndex = matrix.getColIndexByDimensionPath(colPath);

        if (rowIndex < 0 || colIndex < 0) {
            return null;
        }

        return Pair.of(rowIndex, colIndex);
    }
}
