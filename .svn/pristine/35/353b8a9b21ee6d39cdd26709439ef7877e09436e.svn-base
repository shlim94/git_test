package com.wise.comp.pivotmatrix;

import java.lang.ref.WeakReference;
import java.util.List;

import com.wise.comp.model.DataAggregation;
import com.wise.comp.model.Paging;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.SortInfoParam;
import com.wise.comp.pivotgrid.param.SummaryParam;
import com.wise.comp.pivotgrid.param.UdfGroupParam;
import com.wise.comp.pivotmatrix.impl.DefaultSummaryFactoryImpl;

public abstract class SummaryMatrixFactory {

	private static SummaryMatrixFactory theFactory = new DefaultSummaryFactoryImpl();

	protected SummaryMatrixFactory() {
	}

	public static WeakReference<SummaryMatrix> slicePageSummaryMatrix(final SummaryMatrix matrix, final Paging paging) {
		return theFactory.doSlicePageSummaryMatrix(matrix, paging);
	}

	public static WeakReference<SummaryMatrix> createEmptyPageSummaryMatrix(final SummaryMatrix matrix) {
		return theFactory.doCreateEmptyPageSummaryMatrix(matrix);
	}

	public static WeakReference<SummaryMatrix> createSummaryMatrixFromFullyExpandedDataAggregation(
			final DataAggregation dataAggregation, final String cacheKey, final List<GroupParam> rowGroupParams,
			final List<GroupParam> colGroupParams, final List<SummaryParam> summaryParams,
			final List<SortInfoParam> sortInfoParams, final List<UdfGroupParam> udfGroupParams) {
		return theFactory.doCreateSummaryMatrixFromFullyExpandedDataAggregation(dataAggregation, cacheKey,
				rowGroupParams, colGroupParams, summaryParams, sortInfoParams, udfGroupParams);
	}

	abstract public WeakReference<SummaryMatrix> doSlicePageSummaryMatrix(final SummaryMatrix matrix, final Paging paging);

	abstract public WeakReference<SummaryMatrix> doCreateEmptyPageSummaryMatrix(final SummaryMatrix matrix);

	abstract public WeakReference<SummaryMatrix> doCreateSummaryMatrixFromFullyExpandedDataAggregation(
			final DataAggregation dataAggregation, final String cacheKey, final List<GroupParam> rowGroupParams,
			final List<GroupParam> colGroupParams, final List<SummaryParam> summaryParams,
			final List<SortInfoParam> sortInfoParams, final List<UdfGroupParam> udfGroupParams);
}
