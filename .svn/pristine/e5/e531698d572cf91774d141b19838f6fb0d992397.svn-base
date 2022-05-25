package com.wise.comp.pivotgrid.util;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import com.wise.comp.model.AbstractSummaryContainer;
import com.wise.comp.model.DataAggregation;
import com.wise.comp.model.DataGroup;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.PagingParam;

public final class DataAggregationUtils {

    public DataAggregationUtils() {
    }

    public static void resetContainersVisibility(final AbstractSummaryContainer<?> base,
            final boolean visible) {
        base.setVisible(visible);
        final List<DataGroup> childDataGroups = base.getChildDataGroups();
        if (childDataGroups != null) {
            for (DataGroup childDataGroup : childDataGroups) {
                resetContainersVisibility(childDataGroup, visible);
            }
        }
    }

    public static void markRelevantSummaryContainersVisible(
            final AbstractSummaryContainer<?> parentDataGroup,
            final AbstractSummaryContainer<?> parentPageGroup,
            final List<GroupParam> rowGroupParams, final int rowGroupParamIndex) {
        final GroupParam rowGroupParam = rowGroupParamIndex <= rowGroupParams.size() - 1
                ? rowGroupParams.get(rowGroupParamIndex) : null;

        if (!StringUtils.equals(rowGroupParam.getKey(), parentDataGroup.getChildDataGroupKey())|| !StringUtils.equals(rowGroupParam.getKey(),parentPageGroup.getChildDataGroupKey())) {
            return;
        }

        final List<DataGroup> childPageGroups = parentPageGroup.getChildDataGroups(true);
        final int childPageGroupCount = childPageGroups != null ? childPageGroups.size() : 0;

        final List<DataGroup> childDataGroups = parentDataGroup.getChildDataGroups();
        final int childDataGroupCount = childDataGroups != null ? childDataGroups.size() : 0;

        final Set<String> pageGroupKeyValues = childPageGroups.stream().map((g) -> g.getKey())
                .collect(Collectors.toSet());

        for (int i = 0; i < childDataGroupCount; i++) {
            final DataGroup childDataGroup = childDataGroups.get(i);
            final String childDataGroupKey = childDataGroup.getKey();

            if (!pageGroupKeyValues.contains(childDataGroupKey)) {
                childDataGroup.setVisible(false);
                
                if(childDataGroup.getChildDataGroups() != null) {
                	markRelevantSummaryContainersVisibleChild(childDataGroup);
                }
            }
            else {
            	
            	DataGroup childPageGroup = (i <= childPageGroupCount - 1)
                        ? childPageGroups.get(i) : null;
            	
            	for(int j = 0; j < childPageGroups.size(); j ++) {
            		if(childDataGroupKey.equals(childPageGroups.get(j).getKey())){
            			childPageGroup = childPageGroups.get(j);
            		}
            	}
                
                if (childPageGroup != null) {
                    markRelevantSummaryContainersVisible(childDataGroup, childPageGroup,
                            rowGroupParams, rowGroupParamIndex + 1);
                }
            }
        }
    }
    
    private static void markRelevantSummaryContainersVisibleChild(DataGroup parentDataGroup) {
		// TODO Auto-generated method stub
    	final List<DataGroup> containerChildDataGroups = parentDataGroup.getChildDataGroups();
        final int childDataGroupCount = containerChildDataGroups != null ? containerChildDataGroups.size() : 0;
        
        for (int i = 0; i < childDataGroupCount; i++) {
            final DataGroup childDataGroup = containerChildDataGroups.get(i);

            childDataGroup.setVisible(false);
                
            if(childDataGroup.getChildDataGroups() != null) {
            	markRelevantSummaryContainersVisibleChild(childDataGroup);
            }
        }
	}
    public static void markPaginatedSummaryContainersVisible(final DataAggregation dataAggregation,
            final PagingParam pagingParam) {
        final int offset = pagingParam.getOffset();
        final int limit = pagingParam.getLimit();
        final List<GroupParam> rowGroupParams = pagingParam.getRowGroupParams();
        final int maxDepth = rowGroupParams.size();

        final List<AbstractSummaryContainer<?>> list = new LinkedList<>();

        fillSummaryContainersToFlatList(list, dataAggregation, maxDepth, true);
        final int distinctTotal = list.size();
        dataAggregation.getPaging().setDistinctTotal(distinctTotal);

        insertAncestorsForPaging(list, limit, maxDepth);
        final int total = list.size();
        dataAggregation.getPaging().setTotal(total);

        if (offset >= total) {
            return;
        }

        dataAggregation.getPaging().setOffset(offset);
        dataAggregation.getPaging().setLimit(limit);

        final int endIndex = Math.min(offset + limit, total);
        final List<AbstractSummaryContainer<?>> pagedList = list.subList(offset, endIndex);
        final int pageRowCount = Math.min(limit, pagedList.size());
        dataAggregation.getPaging().setCount(pageRowCount);

        int i = 0;
        for (AbstractSummaryContainer<?> container : pagedList) {
            if (container.getDepth() == maxDepth) {
                resetContainersVisibility(container, true);
            }
            else {
                container.setVisible(true);
            }
        }
    }

    public static void insertAncestorsForPaging(final List<AbstractSummaryContainer<?>> list,
            final int pageSize, final int maxDepth) {
        if (pageSize < maxDepth + 1) {
            // If pageSize is smaller than group dimension count including the root,
            // then it's dangerous to continue due to potential infinite loop. So stop here then.
            return;
        }

        int offset = 0;

        while (offset < list.size()) {
            final AbstractSummaryContainer<?> firstContainerInPage = list.get(offset);
            AbstractSummaryContainer<?> parent = firstContainerInPage.getParent();

            while (parent != null) {
                list.add(offset, parent);
                parent = parent.getParent();
            }

            offset += pageSize;
        }
    }

    public static void fillSummaryContainersToFlatList(final List<AbstractSummaryContainer<?>> list,
            final AbstractSummaryContainer<?> base, final int maxDepth, final boolean parentFirst) {
        if (base.getDepth() > maxDepth) {
            return;
        }

        if (parentFirst) {
            list.add(base);
        }

        final List<DataGroup> childDataGroups = base.getChildDataGroups();
        if (childDataGroups != null) {
            for (DataGroup childDataGroup : childDataGroups) {
                fillSummaryContainersToFlatList(list, childDataGroup, maxDepth, parentFirst);
            }
        }

        if (!parentFirst) {
            list.add(base);
        }
    }
}
