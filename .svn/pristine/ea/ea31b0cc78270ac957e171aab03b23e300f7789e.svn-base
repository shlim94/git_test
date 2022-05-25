package com.wise.comp.pivotmatrix.impl;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.wise.comp.model.Paging;
import com.wise.comp.model.SummaryValue;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.SummaryParam;
import com.wise.comp.pivotmatrix.SummaryCell;
import com.wise.comp.pivotmatrix.SummaryDimension;
import com.wise.comp.pivotmatrix.SummaryMatrix;

public final class SummaryMatrixUtils {

    private static Logger log = LoggerFactory.getLogger(SummaryMatrixUtils.class);

    private SummaryMatrixUtils() {
    }

    public static void aggregateSummaryValueListTo(final List<SummaryValue> target,
            final List<SummaryValue> source) {
        final int targetSize = target != null ? target.size() : 0;
        final int sourceSize = source != null ? source.size() : 0;
        final int size = Math.min(targetSize, sourceSize);

        for (int i = 0; i < size; i++) {
            SummaryValue targetSummaryValue = target.get(i);
            SummaryValue sourceSummaryValue = source.get(i);
            aggregateSummaryValueTo(targetSummaryValue, sourceSummaryValue);
            target.set(i, targetSummaryValue);
        }
    }

    public static void aggregateSummaryValueTo(final SummaryValue target,
            final SummaryValue source) {
        switch (target.getSummaryType()) {
        case SUM:
        case CUSTOM:
            target.setCount(target.getCount() + source.getCount());
            if (target.getSum() != null && source.getSum() != null) {
                target.addSum(source.getSum());
            }
            if (target.getValue() != null && source.getValue() != null) {
                target.setValue(target.getValue().add(source.getValue()));
            }
            break;
        case AVERAGE:
        case AVG:
            target.setCount(target.getCount() + source.getCount());
            if (target.getSum() != null && source.getSum() != null) {
                target.addSum(source.getSum());
            }
            
            if(target.getPrecision() == null) {
            	target.setPrecision("0");
            }
            
            if (target.getSum() != null && target.getCount() > 0) {
            	if(target.getPrecisionOption() != null) {
            		if("올림".equalsIgnoreCase(target.getPrecisionOption())) {
            			target.setValue(target.getSum().divide(BigDecimal.valueOf(target.getCount()), Integer.parseInt(target.getPrecision()), RoundingMode.CEILING));
            		}else if("내림".equalsIgnoreCase(target.getPrecisionOption())) {
            			target.setValue(target.getSum().divide(BigDecimal.valueOf(target.getCount()), Integer.parseInt(target.getPrecision()), RoundingMode.DOWN));
            		} else {
            			target.setValue(target.getSum().divide(BigDecimal.valueOf(target.getCount()), Integer.parseInt(target.getPrecision()), RoundingMode.HALF_UP));
            		}
                }else {
                	target.setValue(target.getSum().divide(BigDecimal.valueOf(target.getCount()), Integer.parseInt(target.getPrecision()), RoundingMode.HALF_UP));
                }
                
            }
            break;
        case COUNT:
        	target.setCount(target.getCount() + source.getCount());
        	break;
        case COUNTDISTINCT:
            final Set<BigDecimal> sourceDistinctValues = source.getDistinctValues();
            if (sourceDistinctValues != null) {
                for(BigDecimal value : sourceDistinctValues) {
                	target.addDistinctValue(value);
                }
            }
            break;
        case MIN:
            if (target.getValue() != null && source.getValue() != null) {
                target.setValue(target.getValue().min(source.getValue()));
            }
            break;
        case MAX:
            if (target.getValue() != null && source.getValue() != null) {
                target.setValue(target.getValue().max(source.getValue()));
            }
            break;
        default:
            break;
        }
    }

    public static void writeSummaryMatrixToJson(final JsonGenerator gen, final Paging paging,
            final SummaryMatrix matrix) throws IOException {
    	writeSummaryMatrixToJson(gen, paging, matrix, 0, -1);
    }

	public static void writeSummaryMatrixToJson(final JsonGenerator gen, final Paging paging,
			final SummaryMatrix matrix, final int beginCellRowIndex, final int maxCellRows) throws IOException {
		gen.writeStartObject();

		gen.writeFieldName("meta");

        gen.writeStartObject();
        gen.writeStringField("cacheKey", matrix.getCacheKey());
        gen.writeObjectField("rowGroupParams", matrix.getRowGroupParams());
        gen.writeObjectField("colGroupParams", matrix.getColGroupParams());
        gen.writeObjectField("summaryParams", matrix.getSummaryParams());
        gen.writeObjectField("attributes", matrix.getAttributes());
        
        if(paging == null) {
            gen.writeFieldName("rowSummaryDimension");
            writeSummaryDimensionToJson(gen, matrix.getRowSummaryDimension(), true);
            gen.writeFieldName("colSummaryDimension");
            writeSummaryDimensionToJson(gen, matrix.getColSummaryDimension(), true);
        }
        
        gen.writeFieldName("rowFlattendSummaryDimensions");
        SummaryDimension[] summaryDimensions = matrix.getRowFlattendSummaryDimensions();
        gen.writeStartArray();
        if (summaryDimensions != null) {
            for (SummaryDimension summaryDimension : summaryDimensions) {
                writeSummaryDimensionToJson(gen, summaryDimension, false);
            }
        }
        gen.writeEndArray();

        gen.writeFieldName("colFlattendSummaryDimensions");
        summaryDimensions = matrix.getColFlattendSummaryDimensions();
        gen.writeStartArray();
        if (summaryDimensions != null) {
            for (SummaryDimension summaryDimension : summaryDimensions) {
                writeSummaryDimensionToJson(gen, summaryDimension, false);
            }
        }
        gen.writeEndArray();

        gen.writeEndObject();

        if (paging != null && paging.getOffset() >= 0 && paging.getLimit() > 0) {
            gen.writeFieldName("paging");
            gen.writeStartObject();
            gen.writeNumberField("offset", paging.getOffset());
            gen.writeNumberField("limit", paging.getLimit());
            gen.writeNumberField("count", paging.getCount());
            gen.writeNumberField("total", paging.getTotal());
            gen.writeNumberField("distinctTotal", paging.getDistinctTotal());
            gen.writeEndObject();
        }

        gen.writeFieldName("matrix");
        gen.writeStartObject();
        gen.writeNumberField("rows", matrix.getRows());
        gen.writeNumberField("cols", matrix.getCols());

        gen.writeFieldName("cells");
        writeSummaryCellsToJson(gen, matrix.getSummaryCells(), beginCellRowIndex, maxCellRows);

        gen.writeEndObject();

        gen.writeEndObject();
    }

	public static void writeSummaryCellsToJson(final JsonGenerator gen, final SummaryCell[][] cells) throws IOException {
		writeSummaryCellsToJson(gen, cells, 0);
	}

	public static void writeSummaryCellsToJson(final JsonGenerator gen, final SummaryCell[][] cells,
			final int beginCellRowIndex) throws IOException {
		writeSummaryCellsToJson(gen, cells, beginCellRowIndex, -1);
	}

	public static void writeSummaryCellsToJson(final JsonGenerator gen, final SummaryCell[][] cells,
			final int beginCellRowIndex, final int maxCellRows) throws IOException {
		gen.writeStartArray();

		final int endIndex = Math.min(cells.length,
				beginCellRowIndex + (maxCellRows >= 0 ? maxCellRows : cells.length));
		
		for (int i = beginCellRowIndex; i < endIndex; i++) {
			gen.writeStartArray();
			
			final int cols = cells[i].length;
			for (int j = 0; j < cols; j++) {
				gen.writeObject(cells[i][j]);
			}
			
			gen.writeEndArray();
		}

		gen.writeEndArray();
	}

    private static void writeSummaryDimensionToJson(final JsonGenerator gen,
            final SummaryDimension summaryDimension, final boolean includeChildren)
            throws IOException {
        gen.writeStartObject();
        gen.writeStringField("key", summaryDimension.getKey());
        gen.writeStringField("path", summaryDimension.getPath());
        gen.writeStringField("parentPath", summaryDimension.getParentPath());
        gen.writeNumberField("depth", summaryDimension.getDepth());

        if (includeChildren) {
            gen.writeObjectField("children", summaryDimension.getChildren());
        }

        gen.writeEndObject();
    }

    public static SummaryMatrix readSummaryMatrixFromJson(final ObjectMapper objectMapper,
            JsonNode rootNode) throws IOException {
        List<GroupParam> rowGroupParams = null;
        List<GroupParam> colGroupParams = null;
        List<SummaryParam> summaryParams = null;
        SummaryDimensionImpl rowSummaryDimension = null;
        SummaryDimensionImpl colSummaryDimension = null;
        Map<String, String> attributes = new HashMap<>();

        final JsonNode metaNode = rootNode.get("meta");
        rowGroupParams = readGroupParamsFromJsonNode(objectMapper, metaNode.get("rowGroupParams"));
        colGroupParams = readGroupParamsFromJsonNode(objectMapper, metaNode.get("colGroupParams"));
        summaryParams = readSummaryParamsFromJsonNode(objectMapper, metaNode.get("summaryParams"));
        rowSummaryDimension = readSummaryDimension(metaNode.get("rowSummaryDimension"));
        colSummaryDimension = readSummaryDimension(metaNode.get("colSummaryDimension"));
		final ObjectNode attrsNode = objectMapper.treeToValue(metaNode.get("attributes"), ObjectNode.class);
		if (attrsNode != null) {
			for (Iterator<String> it = attrsNode.fieldNames(); it.hasNext(); ) {
				final String attrName = it.next();
				final JsonNode attrValueNode = attrsNode.get(attrName);
				attributes.put(attrName, attrValueNode.asText());
			}
		}

        final DefaultSummaryMatrixImpl matrix = new DefaultSummaryMatrixImpl(rowGroupParams,
                colGroupParams, summaryParams, rowSummaryDimension, colSummaryDimension);

        matrix.setAttributes(attributes);
        
        final JsonNode cacheKeyNode = metaNode.get("cacheKey");
        matrix.setCacheKey(cacheKeyNode != null ? cacheKeyNode.asText() : null);

        final JsonNode matrixNode = rootNode.get("matrix");
        final int rows = matrixNode.get("rows").asInt();
        final int cols = matrixNode.get("cols").asInt();
        final SummaryCellImpl[][] summaryCells = readSummaryCellsFromJson(objectMapper, rows, cols,
                (ArrayNode) matrixNode.get("cells"));
        matrix.setSummaryCells(summaryCells);

        return matrix;
    }

    private static SummaryDimensionImpl readSummaryDimension(final JsonNode dimensionNode) {
    	if (dimensionNode == null || !dimensionNode.isObject()) {
    		return null;
    	}

    	final String childDataGroupKey = dimensionNode.has("dimensionNode") ? dimensionNode.get("dimensionNode").asText() : null;
    	final String key = dimensionNode.has("key") ? dimensionNode.get("key").asText() : null;
    	final int depth = dimensionNode.has("depth") ? dimensionNode.get("depth").asInt() : 0;
    	final String path = dimensionNode.has("path") ? dimensionNode.get("path").asText() : "";
    	final String parentPath = dimensionNode.has("parentPath") ? dimensionNode.get("parentPath").asText() : null;

    	final SummaryDimensionImpl dimension = new SummaryDimensionImpl(key);
    	dimension.setChildDataGroupKey(childDataGroupKey);
    	dimension.setDepth(depth);
    	dimension.setPath(path);
    	dimension.setParentPath(parentPath);

    	if (dimensionNode.has("children")) {
    		final JsonNode childrenNode = dimensionNode.get("children");
    		if (childrenNode.isArray()) {
	    		final ArrayNode childArrayNode = (ArrayNode) dimensionNode.get("children");
	    		for (JsonNode childNode : childArrayNode) {
	    			final SummaryDimensionImpl childDimension = readSummaryDimension((ObjectNode) childNode);
	    			dimension.addChild(childDimension);
	    		}
    		}
    	}

    	return dimension;
    }

    private static List<GroupParam> readGroupParamsFromJsonNode(final ObjectMapper objectMapper,
            final JsonNode jsonNode) throws IOException {
        final List<GroupParam> groupParams = new ArrayList<>();

        if (jsonNode != null && jsonNode.isArray()) {
            final ArrayNode arrayNode = (ArrayNode) jsonNode;
            for (JsonNode itemNode : arrayNode) {
                if (itemNode.isObject()) {
                    final GroupParam groupParam = objectMapper.treeToValue(itemNode,
                            GroupParam.class);
                    groupParams.add(groupParam);
                }
            }
        }

        return groupParams;
    }

    private static List<SummaryParam> readSummaryParamsFromJsonNode(final ObjectMapper objectMapper,
            final JsonNode jsonNode) throws IOException {
        final List<SummaryParam> summaryParams = new ArrayList<>();

        if (jsonNode != null && jsonNode.isArray()) {
            final ArrayNode arrayNode = (ArrayNode) jsonNode;
            for (JsonNode itemNode : arrayNode) {
                if (itemNode.isObject()) {
                    final SummaryParam summaryParam = objectMapper.treeToValue(itemNode,
                            SummaryParam.class);
                    summaryParams.add(summaryParam);
                }
            }
        }

        return summaryParams;
    }

    public static SummaryCellImpl[][] readSummaryCellsFromJson(final ObjectMapper objectMapper, final int rows,
            final int cols, final ArrayNode arrayNode) throws IOException {
    	final int effectiveRows = rows >= 0 ? rows : arrayNode.size();
        final SummaryCellImpl[][] cells = new SummaryCellImpl[effectiveRows][cols];

        int r = 0;
        for (JsonNode rowNode : arrayNode) {
            final ArrayNode rowArrayNode = (ArrayNode) rowNode;
            int c = 0;
            for (JsonNode itemNode : rowArrayNode) {
                final SummaryCellImpl cell = new SummaryCellImpl();
                final ArrayNode summaryValuesNode = (ArrayNode) itemNode.get("vs");
                for (JsonNode summaryValueNode : summaryValuesNode) {
                    final SummaryValue summaryValue = objectMapper.treeToValue(summaryValueNode,
                            SummaryValue.class);
                    cell.addSummaryValue(summaryValue);
                }
                cells[r][c] = cell;
                c++;
            }
            r++;
        }

        return cells;
    }
}
