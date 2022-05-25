package com.wise.comp.pivotgrid.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.wise.comp.model.SummaryType;
import com.wise.comp.pivotgrid.param.FilterParam;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.PagingParam;
import com.wise.comp.pivotgrid.param.SortInfoParam;
import com.wise.comp.pivotgrid.param.SummaryParam;
import com.wise.comp.pivotgrid.param.TopBottomParam;
import com.wise.comp.pivotgrid.param.UdfGroupParam;

public final class ParamUtils {

    private static Logger log = LoggerFactory.getLogger(ParamUtils.class);

    private static final int DEFAULT_PAGE_LIMIT = 50;

    private ParamUtils() {

    }

    public static FilterParam toFilterParam(final ArrayNode filterParamsNode) {
        final int size = filterParamsNode != null ? filterParamsNode.size() : 0;
        final String operator = size > 1 ? filterParamsNode.get(1).asText() : null;
        final FilterParam rootFilter;

        if ("and".equals(operator) || "or".equals(operator)) {
            rootFilter = new FilterParam(operator);
//            final ArrayNode firstFilterNodeWrapper = (ArrayNode) filterParamsNode.get(0);
//            final ArrayNode secondFilterNodeWrapper = (ArrayNode) filterParamsNode.get(2);
//            addChildFilterParam(rootFilter, unwrapDoubleArrayNode(firstFilterNodeWrapper));
//            addChildFilterParam(rootFilter, unwrapDoubleArrayNode(secondFilterNodeWrapper));
            
            for (int i = 0; i < size; i++) {
            	if((i % 2) == 0) {
            		addChildFilterParam(rootFilter, unwrapDoubleArrayNode((ArrayNode) filterParamsNode.get(i)));
            	}
            }
        }
        else {
            rootFilter = new FilterParam();

            for (int i = 0; i < size; i++) {
                addChildFilterParam(rootFilter, (ArrayNode) filterParamsNode.get(i));
            }
        }

        return rootFilter;
    }

    private static ArrayNode unwrapDoubleArrayNode(final ArrayNode arrayNode) {
        final int size = arrayNode.size();
        if (size == 1) {
            final JsonNode innerNode = arrayNode.get(0);
            if (innerNode.isArray()) {
                return (ArrayNode) innerNode;
            }
        }
        return arrayNode;
    }

    private static void addChildFilterParam(final FilterParam filterParam,
            final ArrayNode childFilterParamNode) {
        final int size = childFilterParamNode != null ? childFilterParamNode.size() : 0;
        final String operator = size > 1 ? childFilterParamNode.get(1).asText() : null;

        if (StringUtils.isBlank(operator)) {
            return;
        }

        if ("and".equals(operator) || "or".equals(operator)) {
            final FilterParam childFilter = filterParam.addChild(operator, null, null);
            addChildFilterParam(childFilter, (ArrayNode) childFilterParamNode.get(0));
            addChildFilterParam(childFilter, (ArrayNode) childFilterParamNode.get(2));
        }
        else {
            final String selector = childFilterParamNode.get(0).asText();
            final String comparingValue = childFilterParamNode.get(2).asText();
            filterParam.addChild(operator, selector, comparingValue);
        }
    }

    public static List<GroupParam> toGroupParams(final ObjectMapper objectMapper,
            final ArrayNode groupParamsNode) {
        if (groupParamsNode == null) {
            return Collections.emptyList();
        }

        final List<GroupParam> params = new ArrayList<>();
        final int size = groupParamsNode != null ? groupParamsNode.size() : 0;

        for (int i = 0; i < size; i++) {
            params.add(toGroupParam(objectMapper, groupParamsNode.get(i)));
        }

        return params;
    }

    public static GroupParam toGroupParam(final ObjectMapper objectMapper,
            final JsonNode groupParamNode) {
        return objectMapper.convertValue(groupParamNode, GroupParam.class);
    }

    public static List<SummaryParam> toSummaryParams(final ObjectMapper objectMapper,
            final ArrayNode summaryParamsNode) {
        if (summaryParamsNode == null) {
            return Collections.emptyList();
        }

        final List<SummaryParam> params = new ArrayList<>();
        final int size = summaryParamsNode != null ? summaryParamsNode.size() : 0;

        for (int i = 0; i < size; i++) {
            params.add(toSummaryParam(objectMapper, summaryParamsNode.get(i)));
        }

        return params;
    }

    public static SummaryParam toSummaryParam(final ObjectMapper objectMapper,
            final JsonNode summaryParamNode) {
        final SummaryParam summaryParam = new SummaryParam();

        final String selector = summaryParamNode.has("selector")
                ? summaryParamNode.get("selector").asText() : "temp";

        if (StringUtils.isBlank(selector)) {
            throw new IllegalArgumentException("Blank selector for the summary param.");
        }

        summaryParam.setSelector(selector);

        final String summaryTypeName = summaryParamNode.has("summaryType")
                ? summaryParamNode.get("summaryType").asText() : null;

        if (StringUtils.isNotBlank(summaryTypeName)) {
            final SummaryType summaryType = SummaryType
                    .valueOf(StringUtils.upperCase(summaryTypeName));

            if (summaryType == null) {
                log.error("No summaryType registered by the name, '{}'.", summaryTypeName);
            }
            else {
                summaryParam.setSummaryType(summaryType);
            }
        }
        
        final String precision = summaryParamNode.has("precision")
                ? summaryParamNode.get("precision").asText() : "0";

        if (StringUtils.isBlank(precision)) {
            throw new IllegalArgumentException("Blank selector for the precision param.");
        }
        
        summaryParam.setPrecision(precision);
        
        final String precisionOption = summaryParamNode.has("precisionOption")
                ? summaryParamNode.get("precisionOption").asText() : "반올림";

        if (StringUtils.isBlank(precisionOption)) {
            throw new IllegalArgumentException("Blank selector for the precision param.");
        }
        
        summaryParam.setPrecisionOption(precisionOption);

        return summaryParam;
    }

    public static PagingParam toPagingParam(final ObjectMapper objectMapper,
            final ObjectNode pagingParamNode) {
        if (pagingParamNode == null) {
            return null;
        }

        final PagingParam pagingParam = new PagingParam();

        if (pagingParamNode.has("offset")) {
            pagingParam.setOffset(pagingParamNode.get("offset").asInt());
        }

        if (pagingParamNode.has("limit")) {
            pagingParam.setLimit(pagingParamNode.get("limit").asInt());
        }

        if (pagingParamNode.has("rowGroups")) {
            final ArrayNode rowGroupsArrayNode = (ArrayNode) pagingParamNode.get("rowGroups");
            final int arrSize = rowGroupsArrayNode.size();

            for (int i = 0; i < arrSize; i++) {
                pagingParam.addRowGroupParam(toGroupParam(objectMapper, rowGroupsArrayNode.get(i)));
            }
        }

        if (pagingParam.getOffset() < 0) {
        	pagingParam.setOffset(0);
        }

        if (pagingParam.getLimit() <= 0) {
        	pagingParam.setLimit(DEFAULT_PAGE_LIMIT);
        }

        return pagingParam;
    }

    public static List<UdfGroupParam> toUdfGroupParams(final ObjectMapper objectMapper,
            final ArrayNode udfGroupParamsNode) {
        if (udfGroupParamsNode == null) {
            return Collections.emptyList();
        }

        final List<UdfGroupParam> params = new ArrayList<>();
        final int size = udfGroupParamsNode != null ? udfGroupParamsNode.size() : 0;

        for (int i = 0; i < size; i++) {
            params.add(toUdfGroupParam(objectMapper, udfGroupParamsNode.get(i)));
        }

        return params;
    }

    public static UdfGroupParam toUdfGroupParam(final ObjectMapper objectMapper,
            final JsonNode udfGroupParamNode) {
        final UdfGroupParam udfGroupParam = objectMapper.convertValue(udfGroupParamNode,
                UdfGroupParam.class);

        final List<String> selectors = udfGroupParam.getSelectors();
        final List<String> groupIntervals = udfGroupParam.getGroupIntervals();

        if (groupIntervals.size() < selectors.size()) {
            final List<String> newGroupIntervals = new ArrayList<>(groupIntervals);
            for (int i = groupIntervals.size(); i < selectors.size(); i++) {
                newGroupIntervals.add("");
            }
            udfGroupParam.setGroupIntervals(newGroupIntervals);
        }

        return udfGroupParam;
    }

    public static List<SortInfoParam> toSortInfoParams(final ObjectMapper objectMapper,
            final ArrayNode sortInfoParamsNode) {
        if (sortInfoParamsNode == null) {
            return Collections.emptyList();
        }

        final List<SortInfoParam> params = new ArrayList<>();
        final int size = sortInfoParamsNode != null ? sortInfoParamsNode.size() : 0;

        for (int i = 0; i < size; i++) {
            params.add(toSortInfoParam(objectMapper, sortInfoParamsNode.get(i)));
        }

        return params;
    }

    public static SortInfoParam toSortInfoParam(final ObjectMapper objectMapper,
            final JsonNode sortInfoParamNode) {
        return objectMapper.convertValue(sortInfoParamNode, SortInfoParam.class);
    }

    public static TopBottomParam toTopBottomParam(final ObjectMapper objectMapper,
            final JsonNode topBottomParamNode) {
        return objectMapper.convertValue(topBottomParamNode, TopBottomParam.class);
    }
}
