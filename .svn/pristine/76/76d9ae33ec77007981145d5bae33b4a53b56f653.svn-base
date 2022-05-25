package com.wise.comp.pivotmatrix;

import java.util.List;
import java.util.Map;

import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.SummaryParam;

public interface SummaryMatrix {

    public SummaryDimension[] getRowFlattendSummaryDimensions();

    public SummaryDimension[] getColFlattendSummaryDimensions();

    public int getRows();

    public int getCols();

    public SummaryCell[][] getSummaryCells();

    public SummaryDimension getRowSummaryDimension();

    public SummaryDimension getColSummaryDimension();

    public int getRowIndexByDimensionPath(final String path);

    public int getColIndexByDimensionPath(final String path);

    public SummaryMatrix sliceRows(final List<Integer> pageRowIndices);

    public List<GroupParam> getRowGroupParams();

    public List<GroupParam> getColGroupParams();

    public List<SummaryParam> getSummaryParams();

    public String getCacheKey();

    public String getAttribute(final String name);
    
    public void setAttribute(final String name, final String value);
    
    public Map<String, String> getAttributes();

    public void setAttributes(final Map<String, String> attributes);

}
