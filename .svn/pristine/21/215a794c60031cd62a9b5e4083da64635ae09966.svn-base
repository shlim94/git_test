package com.wise.comp.pivotmatrix;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.bouncycastle.util.encoders.Base64;
import org.jfree.util.Log;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.wise.common.diagnos.WDC;
import com.wise.common.diagnos.WdcTask;
import com.wise.common.file.CacheFileWritingTaskExecutorService;
import com.wise.common.file.SummaryMatrixFileWriterService;
import com.wise.common.util.CloseableList;
import com.wise.common.util.QueryExecutor;
import com.wise.common.util.ServiceTimeoutUtils;
import com.wise.comp.impl.json.JSONArrayDataFrame;
import com.wise.comp.model.DataAggregation;
import com.wise.comp.model.DataFrame;
import com.wise.comp.pivotgrid.aggregator.DataAggregator;
import com.wise.comp.pivotgrid.param.FilterParam;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.PagingParam;
import com.wise.comp.pivotgrid.param.SortInfoParam;
import com.wise.comp.pivotgrid.param.SummaryParam;
import com.wise.comp.pivotgrid.param.TopBottomParam;
import com.wise.comp.pivotgrid.param.UdfGroupParam;
import com.wise.comp.pivotgrid.util.ParamUtils;
import com.wise.comp.pivotmatrix.impl.SummaryMatrixUtils;
import com.wise.ds.repository.controller.ReportController;
import com.wise.ds.repository.service.DataSetService;
import com.wise.ds.repository.service.ReportService;
import com.wise.ds.repository.service.impl.QueryResultCacheManager;

import net.sf.json.JSONObject;

@Service
public class SummaryMatrixProvider {
	private static final Logger logger = LoggerFactory.getLogger(ReportController.class);

	@Resource(name = "reportService")
    private ReportService reportService;
	
	@Resource(name = "dataSetService")
    private DataSetService dataSetServiceImpl;
	
	@Autowired
    private ObjectMapper objectMapper;
	
	@Autowired
    private DataAggregator dataAggregator;
	
	@Autowired
    private QueryResultCacheManager queryResultCacheManager;
    
    @Autowired
    private SummaryMatrixFileWriterService summaryMatrixFileWriterService;
    
    @Autowired
    private CacheFileWritingTaskExecutorService cacheFileWritingTaskExecutorService;
    
	public WeakReference<SummaryMatrix> getPivotSummaryMatrix(final HttpServletRequest request,
		final Map<String, Object> allParameters, final PagingParam pagingParam, final QueryExecutor executor) throws Exception {
		final String sqlLikeOption = allParameters.get("sqlLikeOption").toString();
		final String filter = allParameters.get("filter").toString();
		final String udfGroups = allParameters.get("udfGroups").toString();
		final String group = allParameters.get("group").toString();
		final String groupSummary = allParameters.get("groupSummary").toString();
		final String totalSummary = allParameters.get("totalSummary").toString();
		final String sortInfo = allParameters.get("sortInfo").toString();
		final String topBottom = allParameters.get("topBottom").toString();
		final String useWithQueryParam = allParameters.containsKey("useWithQuery")? allParameters.get("useWithQuery").toString() : "Y";
		
		final boolean useWithQuery = useWithQueryParam.equals("Y")? true : false;

		final String argsInfo = new StringBuilder(1024).append(sqlLikeOption).append(':').append(filter).append(':')
				.append(udfGroups).append(':').append(group).append(':').append(groupSummary).append(':')
				.append(totalSummary).append(':').append(sortInfo).append(':').append(topBottom).append(':')
				.append(useWithQuery).append(':').toString();

		final String cacheKey = DigestUtils.sha256Hex(argsInfo);

		final WeakReference<SummaryMatrix> cachedSummaryMatrix = getPivotSummaryMatrixFromCache(cacheKey, pagingParam);

		if (cachedSummaryMatrix != null && cachedSummaryMatrix.get() != null) {
			return cachedSummaryMatrix;
		}
		
		ServiceTimeoutUtils.checkServiceTimeout();
		
		final ArrayNode filterParamsNode = StringUtils.isNotBlank(filter) ? (ArrayNode) objectMapper.readTree(filter)
				: null;
		final FilterParam rootFilter = ParamUtils.toFilterParam(filterParamsNode);

		final ArrayNode udfGroupParamsNode = StringUtils.isNotBlank(udfGroups)
				? (ArrayNode) objectMapper.readTree(udfGroups)
				: null;
		final List<UdfGroupParam> udfGroupParams = ParamUtils.toUdfGroupParams(objectMapper, udfGroupParamsNode);

		final ArrayNode groupParamsNode = StringUtils.isNotBlank(group) ? (ArrayNode) objectMapper.readTree(group)
				: null;
		final List<GroupParam> groupParams = ParamUtils.toGroupParams(objectMapper, groupParamsNode);
		final int groupParamCount = groupParams.size();

		final ArrayNode groupSummaryParamsNode = StringUtils.isNotBlank(groupSummary)
				? (ArrayNode) objectMapper.readTree(groupSummary)
				: null;
		final List<SummaryParam> groupSummaryParams = ParamUtils.toSummaryParams(objectMapper, groupSummaryParamsNode);

		final ArrayNode totalSummaryParamsNode = StringUtils.isNotBlank(totalSummary)
				? (ArrayNode) objectMapper.readTree(totalSummary)
				: null;
		final List<SummaryParam> totalSummaryParams = ParamUtils.toSummaryParams(objectMapper, totalSummaryParamsNode);

		final ArrayNode sortInfoParamsNode = StringUtils.isNotBlank(sortInfo)
				? (ArrayNode) objectMapper.readTree(sortInfo)
				: null;
		final List<SortInfoParam> sortInfoParams = ParamUtils.toSortInfoParams(objectMapper, sortInfoParamsNode);

		final ObjectNode topBottomParamNode = StringUtils.isNotBlank(topBottom)
				? (ObjectNode) objectMapper.readTree(topBottom)
				: null;
		final TopBottomParam topBottomParam = ParamUtils.toTopBottomParam(objectMapper, topBottomParamNode);

		final List<GroupParam> rowGroupParams = pagingParam.getRowGroupParams();
		final int rowGroupParamCount = rowGroupParams.size();
		final List<GroupParam> colGroupParams = new ArrayList<>();

		boolean isFullyExpandedGroups = true;

		for (int i = 0; i < groupParamCount; i++) {
			final GroupParam groupParam = groupParams.get(i);
			if (i < rowGroupParamCount) {
				final GroupParam rowGroupParam = rowGroupParams.get(i);
				if (groupParam.getKey() != null && !StringUtils.equals(groupParam.getKey(), rowGroupParam.getKey())) {
					isFullyExpandedGroups = false;
					break;
				}
			} else {
				colGroupParams.add(groupParam);
			}
		}

		if (!isFullyExpandedGroups) {
			return null;
		}
		
		final CloseableList<JSONObject> dataArray;
		
		try(WdcTask task = WDC.getCurrentTask().startSubtask("summaryMatrixProivder.executeSqlLike")){
			dataArray = executor.execute(sqlLikeOption, useWithQuery);
		}
		
		ServiceTimeoutUtils.checkServiceTimeout();
		
		final List<String> colNames = dataArray != null && dataArray.size() > 0
				? new ArrayList<>(dataArray.get(0).keySet())
				: Collections.emptyList();

		final DataFrame dataFrame = new JSONArrayDataFrame(dataArray, colNames.toArray(new String[colNames.size()]));
		
		final WeakReference<DataAggregation> aggregation;
		
		try(WdcTask task = WDC.getCurrentTask().startSubtask("summaryMatrixProivder.createDataAggregation")){
			aggregation = dataAggregator.createDataAggregation(dataFrame, rootFilter, udfGroupParams,
				groupParams, groupSummaryParams, totalSummaryParams, null, sortInfoParams, topBottomParam, true);
		}

		ServiceTimeoutUtils.checkServiceTimeout();
		
		final WeakReference<SummaryMatrix> matrix;
		
		try(WdcTask task = WDC.getCurrentTask().startSubtask("summaryMatrixProivder.createSummaryMatrix")){
			matrix = SummaryMatrixFactory.createSummaryMatrixFromFullyExpandedDataAggregation(
				aggregation.get(), cacheKey, rowGroupParams, colGroupParams, groupSummaryParams, sortInfoParams, udfGroupParams);
			task.setAttribute("rows", matrix.get().getRows());
			task.setAttribute("rowGroups", matrix.get().getRowGroupParams());
		}
		
		ServiceTimeoutUtils.checkServiceTimeout();
		
		if (matrix.get() != null) {
			final String sql = (String) dataArray.getAttribute("sql");
			if (sql != null) {
				matrix.get().setAttribute("sql", new String(Base64.encode(sql.getBytes())));
			}
			putPivotSummaryMatrixToCache(cacheKey, matrix.get(), pagingParam);
		}

		return matrix;
	}

	public WeakReference<SummaryMatrix> getPivotSummaryMatrixFromCache(final String cacheKey, final PagingParam pagingParam) {
		WeakReference<SummaryMatrix> matrix = null;

		final int beginIndex = pagingParam.getOffset();
		final int endIndex = beginIndex + pagingParam.getLimit();
		final int rowCountInPart1 = summaryMatrixFileWriterService.getRowCountInPart1();
		final boolean part2FileRequired = endIndex >= rowCountInPart1;

		try {
			if (!part2FileRequired) {
				matrix = new WeakReference<SummaryMatrix>((SummaryMatrix) queryResultCacheManager.getSummaryMatrixCache(cacheKey));
			}

			if (matrix != null) {
				return matrix;
			}

			final String relDirPath = DateFormatUtils.format(new Date(), "yyyyMMdd");
			final File cacheFilePart1 = summaryMatrixFileWriterService.getSummaryMatrixFile(cacheKey, relDirPath);

			SummaryMatrix mainMatrix = null;

			if (cacheFilePart1 != null && cacheFilePart1.isFile()) {
				mainMatrix = readSummaryMatrixFromFile(cacheFilePart1);
				queryResultCacheManager.putSummaryMatrixCache(cacheKey, mainMatrix);

				if (!part2FileRequired) {
					matrix = new WeakReference<SummaryMatrix>(mainMatrix);
				}
				else {
					final SummaryMatrix mergeableMatrix = readSummaryMatrixFromFile(cacheFilePart1);
					final File cacheFilePart2 = summaryMatrixFileWriterService.getSummaryMatrixFileForPart2(cacheKey, relDirPath);
					
					SummaryCell[][] extraCells = null;

					if (cacheFilePart2 != null && cacheFilePart2.isFile()) {
						try {
							extraCells = readSummaryCellsFromFile(cacheFilePart2, mergeableMatrix.getCols());
						} catch (Exception ex) {
							logger.error("Failed to read extraCells from part2 file.", ex);
						}
					}
					
					if (extraCells != null) {
						final SummaryCell[][] originalCells = mergeableMatrix.getSummaryCells();
	
						final int maxRows = rowCountInPart1 + extraCells.length;
	
						for (int i = rowCountInPart1; i < maxRows; i++) {
							final SummaryCell[] originalCellRow = originalCells[i];
							final SummaryCell[] extraCellRow = extraCells[i - rowCountInPart1];
							System.arraycopy(extraCellRow, 0, originalCellRow, 0, extraCellRow.length);
						}
					}

					matrix = new WeakReference<SummaryMatrix>(mergeableMatrix);
				}
			}
		} catch (Exception e) {
			logger.error("Faile dto get summary matrix from the cache.", e);
		}

		return matrix;
	}

	private SummaryMatrix readSummaryMatrixFromFile(final File file) throws IOException {
		try (FileInputStream fis = new FileInputStream(file);
				InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
				BufferedReader br = new BufferedReader(isr)) {
			final JsonNode matrixNode = objectMapper.readTree(br);
			return SummaryMatrixUtils.readSummaryMatrixFromJson(objectMapper, matrixNode);
		}
	}

	private SummaryCell[][] readSummaryCellsFromFile(final File file, final int cols) throws IOException {
		try (FileInputStream fis = new FileInputStream(file);
				BufferedInputStream bis = new BufferedInputStream(fis)) {
			return AvroSummaryMatrixUtils.deserializeSummaryCellRowsFromAvroData(bis);
		}
	}

	private void putPivotSummaryMatrixToCache(final String cacheKey, final SummaryMatrix matrix, final PagingParam pagingParam) {
		final int beginIndex = pagingParam.getOffset();
		final int endIndex = beginIndex + pagingParam.getLimit();
		final int rowCountInPart1 = summaryMatrixFileWriterService.getRowCountInPart1();
		final boolean part2FileRequired = endIndex >= rowCountInPart1;

		try {
			if (!part2FileRequired) {
				queryResultCacheManager.putSummaryMatrixCache(cacheKey, matrix);
			}

			final String relDirPath = DateFormatUtils.format(new Date(), "yyyyMMdd");
			final File cacheFile = summaryMatrixFileWriterService.getSummaryMatrixFile(cacheKey, relDirPath);

			if (cacheFile == null || !cacheFile.isFile()) {
				cacheFileWritingTaskExecutorService.execute(new Runnable() {
					@Override
					public void run() {
						try {
							if(cacheFile == null || !cacheFile.isFile()) {
								summaryMatrixFileWriterService.writeSummaryMatrix(cacheKey, relDirPath, matrix);
							}
						} catch (Exception e) {
							logger.error("Failed to save summary matrix to the cache file.", e);
						}
					}
				});
				
			}
		}catch (Exception e) {
			logger.error("Failed to submit the task to cache summary matrix to the cache file.", e);
		}
	}
	
}
