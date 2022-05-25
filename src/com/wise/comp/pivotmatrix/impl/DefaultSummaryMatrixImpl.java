package com.wise.comp.pivotmatrix.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.SummaryParam;
import com.wise.comp.pivotmatrix.SummaryCell;
import com.wise.comp.pivotmatrix.SummaryDimension;
import com.wise.comp.pivotmatrix.SummaryMatrix;

public class DefaultSummaryMatrixImpl implements SummaryMatrix {

    private static Logger log = LoggerFactory.getLogger(DefaultSummaryMatrixImpl.class);

    private List<GroupParam> rowGroupParams;
    private List<GroupParam> colGroupParams;
    private List<SummaryParam> summaryParams;

    private SummaryDimension rowSummaryDimension;
    private SummaryDimension colSummaryDimension;
    private SummaryDimension[] rowFlattenedSummaryDimensions;
    private SummaryDimension[] colFlattenedSummaryDimensions;
    private Map<String, Pair<Integer, SummaryDimension>> rowSummaryDimensionPathMap = new HashMap<>();
    private Map<String, Pair<Integer, SummaryDimension>> colSummaryDimensionPathMap = new HashMap<>();

    private int rows;
    private int cols;
    SummaryCellImpl[][] summaryCells;
    private String cacheKey;
    
    private Map<String, String> attributes;

    private DefaultSummaryMatrixImpl() {
    }

    public DefaultSummaryMatrixImpl(final List<GroupParam> rowGroupParams,
            final List<GroupParam> colGroupParams, final List<SummaryParam> summaryParams,
            final SummaryDimension rowSummaryDimension,
            final SummaryDimension colSummaryDimension) {
        this.rowGroupParams = new ArrayList<>();
        if (rowGroupParams != null) {
            this.rowGroupParams.addAll(rowGroupParams);
        }
        this.colGroupParams = new ArrayList<>();
        if (colGroupParams != null) {
            this.colGroupParams.addAll(colGroupParams);
        }
        this.summaryParams = new ArrayList<>();
        if (summaryParams != null) {
            this.summaryParams.addAll(summaryParams);
        }

        this.rowSummaryDimension = rowSummaryDimension;
        this.colSummaryDimension = colSummaryDimension;

        final List<SummaryDimension> flattendList = new LinkedList<>();
        fillSummaryDimensionsToList(flattendList, rowSummaryDimension, rowSummaryDimensionPathMap);
        rowFlattenedSummaryDimensions = flattendList
                .toArray(new SummaryDimension[flattendList.size()]);

        flattendList.clear();
        fillSummaryDimensionsToList(flattendList, colSummaryDimension, colSummaryDimensionPathMap);
        colFlattenedSummaryDimensions = flattendList
                .toArray(new SummaryDimension[flattendList.size()]);

        initSummaryCells();
    }

    private void initSummaryCells() {
        rows = rowFlattenedSummaryDimensions.length;
        cols = colFlattenedSummaryDimensions.length;

        summaryCells = new SummaryCellImpl[rows][cols];

        final SummaryCellImpl rootCell = new SummaryCellImpl();
        summaryCells[0][0] = rootCell;

        for (int i = 0; i < rows; i++) {
            final SummaryCellImpl cell = new SummaryCellImpl();

            final List<Integer> indices = new LinkedList<>();
            for (int index = 1; index < cols; index++) {
                SummaryDimension dimension = colFlattenedSummaryDimensions[index];
                if (dimension.getDepth() == 1) {
                    indices.add(index);
                }
                cell.setColChildCellIndices(indices);
                cell.setColChildrenRowIndex(i);
            }

            summaryCells[i][0] = cell;
        }

        for (int j = 1; j < cols; j++) {
            final SummaryCellImpl cell = new SummaryCellImpl();

            final List<Integer> indices = new LinkedList<>();
            for (int index = 1; index < rows; index++) {
                SummaryDimension dimension = rowFlattenedSummaryDimensions[index];
                if (dimension.getDepth() == 1) {
                    indices.add(index);
                }
                cell.setRowChildCellIndices(indices);
                cell.setRowChildrenColIndex(j);
            }

            summaryCells[0][j] = cell;
        }

        for (int i = 1; i < rows; i++) {
            final SummaryDimension rowDimension = rowFlattenedSummaryDimensions[i];

            for (int j = 1; j < cols; j++) {
                final SummaryCellImpl cell = new SummaryCellImpl();
                summaryCells[i][j] = cell;

                final SummaryDimension colDimension = colFlattenedSummaryDimensions[j];

                if (colDimension.hasChild()) {
                    final List<Integer> indices = new LinkedList<>();
                    final int childDepth = colDimension.getDepth() + 1;
                    for (int index = j + 1; index < cols; index++) {
                        SummaryDimension childDimension = colFlattenedSummaryDimensions[index];
                        if (childDimension.getDepth() < childDepth) {
                            break;
                        }else if(childDimension.getDepth() == childDepth) {
                        	indices.add(index);
                        }
                        indices.add(index);
                    }
                    cell.setColChildCellIndices(indices);
                    cell.setColChildrenRowIndex(i);
                }

                if (rowDimension.hasChild()) {
                    final List<Integer> indices = new LinkedList<>();
                    final int childDepth = rowDimension.getDepth() + 1;
                    for (int index = i + 1; index < rows; index++) {
                        SummaryDimension childDimension = rowFlattenedSummaryDimensions[index];
                        if (childDimension.getDepth() < childDepth) {
                            break;
                        }else if(childDimension.getDepth() == childDepth) {
                        	indices.add(index);
                        }
                    }
                    cell.setRowChildCellIndices(indices);
                    cell.setRowChildrenColIndex(j);
                }
            }
        }
    }

    @Override
    public List<GroupParam> getRowGroupParams() {
        return rowGroupParams != null ? Collections.unmodifiableList(rowGroupParams)
                : Collections.emptyList();
    }

    @Override
    public List<GroupParam> getColGroupParams() {
        return colGroupParams != null ? Collections.unmodifiableList(colGroupParams)
                : Collections.emptyList();
    }

    @Override
    public List<SummaryParam> getSummaryParams() {
        return summaryParams != null ? Collections.unmodifiableList(summaryParams)
                : Collections.emptyList();
    }

    public SummaryDimension getRowSummaryDimension() {
        return rowSummaryDimension;
    }

    public SummaryDimension getColSummaryDimension() {
        return colSummaryDimension;
    }

    @Override
    public SummaryDimension[] getRowFlattendSummaryDimensions() {
    	return rowFlattenedSummaryDimensions;
    }

    @Override
    public SummaryDimension[] getColFlattendSummaryDimensions() {
    	return colFlattenedSummaryDimensions;
    }

    @Override
    public int getRows() {
        return rows;
    }

    @Override
    public int getCols() {
        return cols;
    }

    @Override
    @JsonProperty("cells")
    public SummaryCell[][] getSummaryCells() {
        return summaryCells;
    }

    void setSummaryCells(SummaryCellImpl[][] summaryCells) {
        this.summaryCells = summaryCells;
    }

    public int getRowIndexByDimensionPath(final String path) {
        final Pair<Integer, SummaryDimension> pair = rowSummaryDimensionPathMap.get(path);
        return pair != null ? pair.getLeft() : -1;
    }

    public int getColIndexByDimensionPath(final String path) {
        final Pair<Integer, SummaryDimension> pair = colSummaryDimensionPathMap.get(path);
        return pair != null ? pair.getLeft() : -1;
    }

    public SummaryCell[] getColumnSummaryCells(final int colIndex, final int rowBeginIndex,
            final int maxLength) {
        final int rowEndIndex = Math.min(rowBeginIndex + maxLength, rows);
        final SummaryCell[] cells = new SummaryCell[rowEndIndex - rowBeginIndex];

        for (int i = rowBeginIndex; i < rowEndIndex; i++) {
            cells[i - rowBeginIndex] = summaryCells[i][colIndex];
        }

        return cells;
    }

    public SummaryMatrix sliceRows(final List<Integer> rowIndices) {
        final DefaultSummaryMatrixImpl sliced = new DefaultSummaryMatrixImpl();

        sliced.rowGroupParams = new ArrayList<>();
        if (rowGroupParams != null) {
            sliced.rowGroupParams.addAll(rowGroupParams);
        }

        sliced.colGroupParams = new ArrayList<>();
        if (colGroupParams != null) {
            sliced.colGroupParams.addAll(colGroupParams);
        }

        sliced.summaryParams = new ArrayList<>();
        if (summaryParams != null) {
            sliced.summaryParams.addAll(summaryParams);
        }

        sliced.rowSummaryDimension = rowSummaryDimension;
        sliced.colSummaryDimension = colSummaryDimension;

        sliced.rows = rowIndices.size();
        sliced.cols = cols;

        sliced.summaryCells = new SummaryCellImpl[rowIndices.size()][cols];

        sliced.rowFlattenedSummaryDimensions = new SummaryDimension[rowIndices.size()];
        int i = 0;
        for (int rowIndex : rowIndices) {
            sliced.rowFlattenedSummaryDimensions[i] = rowFlattenedSummaryDimensions[rowIndex];
            System.arraycopy(summaryCells[rowIndex], 0, sliced.summaryCells[i], 0, cols);
            ++i;
        }

        sliced.colFlattenedSummaryDimensions = new SummaryDimension[cols];
        if (cols > 0) {
            System.arraycopy(colFlattenedSummaryDimensions, 0, sliced.colFlattenedSummaryDimensions,
                    0, cols);
        }

        sliced.rowSummaryDimensionPathMap = rowSummaryDimensionPathMap;
        sliced.colSummaryDimensionPathMap = colSummaryDimensionPathMap;

        return sliced;
    }

    private void fillSummaryDimensionsToList(final List<SummaryDimension> list,
            final SummaryDimension base,
            final Map<String, Pair<Integer, SummaryDimension>> summaryDimensionPathMap) {
        list.add(base);
        summaryDimensionPathMap.put(base.getPath(), Pair.of(list.size() - 1, base));

        if (base.hasChild()) {
            for (SummaryDimension child : base.getChildren()) {
                fillSummaryDimensionsToList(list, child, summaryDimensionPathMap);
            }
        }
    }

	public String getCacheKey() {
		return cacheKey;
	}

	void setCacheKey(String cacheKey) {
		this.cacheKey = cacheKey;
	}

	@Override
	public Map<String, String> getAttributes() {
		return attributes != null ? Collections.unmodifiableMap(attributes) : Collections.emptyMap();
	}

	@Override
	public void setAttributes(Map<String, String> attributes) {
		if (attributes == null) {
			this.attributes = null;
		}
		else {
			this.attributes = new HashMap<>(attributes);
		}
	}
    
    @Override
    public String getAttribute(final String name) {
    	return attributes != null ? attributes.get(name) : null;
    }

    @Override
    public void setAttribute(final String name, final String value) {
    	if (attributes == null) {
    		attributes = new HashMap<>();
    	}
    	attributes.put(name, value);
    }
}
