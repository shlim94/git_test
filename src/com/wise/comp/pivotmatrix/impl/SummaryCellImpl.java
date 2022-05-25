package com.wise.comp.pivotmatrix.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.wise.comp.model.SummaryValue;
import com.wise.comp.pivotmatrix.SummaryCell;

public class SummaryCellImpl implements SummaryCell {

    private final List<SummaryValue> summaryValues;

    private final List<SummaryValue> unmodifiableSummaryValues;

    private List<Integer> rowChildCellIndices;
    private int rowChildrenColIndex;

    private List<Integer> colChildCellIndices;
    private int colChildrenRowIndex;

	public SummaryCellImpl() {
		this.summaryValues = new ArrayList<>();
		unmodifiableSummaryValues = Collections.unmodifiableList(summaryValues);
	}

	public SummaryCellImpl(final List<SummaryValue> summaryValues) {
		this.summaryValues = summaryValues != null ? new ArrayList<>(summaryValues) : new ArrayList<>();;
		unmodifiableSummaryValues = Collections.unmodifiableList(summaryValues);
	}

    @Override
    public boolean hasSummaryValue() {
        return !summaryValues.isEmpty();
    }

    SummaryCell addSummaryValue(final SummaryValue summaryValue) {
        summaryValues.add(summaryValue);
        return this;
    }

    SummaryCell addSummaryValues(final Collection<SummaryValue> summaryValues) {
        if (summaryValues != null && !summaryValues.isEmpty()) {
            this.summaryValues.addAll(summaryValues);
        }

        return this;
    }

    @JsonProperty(value = "vs")
    @Override
    public List<SummaryValue> getSummaryValues() {
        return unmodifiableSummaryValues;
    }

    @JsonIgnore
    @Override
    public List<Integer> getRowChildCellIndices() {
        return rowChildCellIndices;
    }

    void setRowChildCellIndices(List<Integer> rowChildCellIndices) {
        this.rowChildCellIndices = rowChildCellIndices;
    }

    @JsonIgnore
    @Override
    public List<Integer> getColChildCellIndices() {
        return colChildCellIndices;
    }

    void setColChildCellIndices(List<Integer> colChildCellIndices) {
        this.colChildCellIndices = colChildCellIndices;
    }

    @JsonIgnore
    @Override
    public int getRowChildrenColIndex() {
        return rowChildrenColIndex;
    }

    void setRowChildrenColIndex(int rowChildrenColIndex) {
        this.rowChildrenColIndex = rowChildrenColIndex;
    }

    @JsonIgnore
    @Override
    public int getColChildrenRowIndex() {
        return colChildrenRowIndex;
    }

    void setColChildrenRowIndex(int colChildrenRowIndex) {
        this.colChildrenRowIndex = colChildrenRowIndex;
    }
}
