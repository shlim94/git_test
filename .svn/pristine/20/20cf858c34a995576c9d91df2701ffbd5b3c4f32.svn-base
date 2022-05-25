package com.wise.comp.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.wise.comp.pivotmatrix.SummaryDimension;

abstract public class AbstractSummaryContainer<T> implements SummaryContainer<T> {

    private static Logger log = LoggerFactory.getLogger(AbstractSummaryContainer.class);

    private String key;

    private List<SummaryValue> summaryValues;

    private AbstractSummaryContainer<?> parent;
    private int depth;

    private String childDataGroupKey;

    private List<DataGroup> childDataGroups;
    private List<DataGroup> unmodifiableChildDataGroups;
    private Map<String, DataGroup> childDataGroupsMap;

    private boolean visible;
    private boolean isOtherData;
    
    private String path = "";

    public AbstractSummaryContainer() {
        this(null);
    }

    public AbstractSummaryContainer(final String key) {
        this.key = key;
    }

    @Override
    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    @SuppressWarnings("unchecked")
    @Override
    public T addSummaryValue(final SummaryValue summaryValue) {
        if (summaryValues == null) {
            summaryValues = new ArrayList<>();
        }
        summaryValues.add(summaryValue);
        return (T) this;
    }

    @Override
    public List<SummaryValue> getSummaryValues() {
        return summaryValues;
    }

    @JsonIgnore
    public AbstractSummaryContainer<?> getParent() {
        return parent;
    }

    public void setParent(AbstractSummaryContainer<?> parent) {
        this.parent = parent;
    }

    public int getDepth() {
        return depth;
    }

    public void setDepth(int depth) {
        this.depth = depth;
    }

    public String getChildDataGroupKey() {
        return childDataGroupKey;
    }

    public void setChildDataGroupKey(String childDataGroupKey) {
        this.childDataGroupKey = childDataGroupKey;
    }

    public void sortChildDataGroups(final Comparator<DataGroup> comparator) {
        if (childDataGroups != null) {
            try {
                Collections.sort(childDataGroups, comparator);
            }
            catch (Exception e) {
                final Object childDataGroupsInfo = childDataGroups.stream().map(
                        (dataGroup) -> new Object[] { dataGroup.getKey(), dataGroup.getSummaryValues() })
                        .toArray();
                log.error("Failed to sort child data groups using comparator: " + comparator
                        + ". childDataGroupsInfo: {}", childDataGroupsInfo, e);
            }
        }
    }

    public DataGroup addChildDataGroup(final String key) {
        final DataGroup childDataGroup = new DataGroup(key);
        addChildDataGroup(childDataGroup);
        return childDataGroup;
    }

    public void addChildDataGroup(final DataGroup childDataGroup) {
        if (childDataGroups == null) {
            childDataGroups = new LinkedList<>();
            unmodifiableChildDataGroups = Collections.unmodifiableList(childDataGroups);
            childDataGroupsMap = new HashMap<>();
        }

        childDataGroups.add(childDataGroup);
        childDataGroupsMap.put(childDataGroup.getKey(), childDataGroup);
        childDataGroup.setDepth(depth + 1);
        childDataGroup.setPath(path + SummaryDimension.PATH_DELIMITER + childDataGroup.getKey());
        childDataGroup.setParent(this);
    }

    public DataGroup getChildDataGroup(final String key) {
        return childDataGroupsMap != null ? childDataGroupsMap.get(key) : null;
    }

    public List<DataGroup> getChildDataGroups() {
        return getChildDataGroups(false);
    }

    public void setChildDataGroups(final List<DataGroup> childDataGroups) {
        if (childDataGroups == null) {
            this.childDataGroups = null;
            unmodifiableChildDataGroups = null;
            childDataGroupsMap = null;
            return;
        }

        this.childDataGroups = new LinkedList<>(childDataGroups);
        unmodifiableChildDataGroups = Collections.unmodifiableList(this.childDataGroups);
        childDataGroupsMap = new HashMap<>();

        for (DataGroup childDataGroup : childDataGroups) {
            childDataGroupsMap.put(childDataGroup.getKey(), childDataGroup);
        }
    }

    public List<DataGroup> getChildDataGroups(final boolean visibleOnly) {
        if (!visibleOnly || unmodifiableChildDataGroups == null) {
            return unmodifiableChildDataGroups;
        }

        return unmodifiableChildDataGroups.stream().filter((dataGroup) -> dataGroup.isVisible())
                .collect(Collectors.toList());
    }

    public boolean isVisible() {
        return visible;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
    }
    
    public boolean getIsOtherData() {
    	return isOtherData;
    }
    
    public void setIsOtherData(boolean isOtherData) {
    	this.isOtherData = isOtherData;
    }
    
    public String getPath() {
        return path;
    }

    public void setPath(final String path) {
        this.path = path;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof AbstractSummaryContainer)) {
            return false;
        }

        final AbstractSummaryContainer<?> that = (AbstractSummaryContainer<?>) o;

        if (!StringUtils.equals(key, that.key)) {
            return false;
        }

        if (!Objects.equals(summaryValues, that.summaryValues)) {
            return false;
        }

        if (depth != that.depth) {
            return false;
        }

        if (visible != that.visible) {
            return false;
        }

        if (!StringUtils.equals(childDataGroupKey, that.childDataGroupKey)) {
            return false;
        }

        if (!Objects.equals(childDataGroups, that.childDataGroups)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(key).append(summaryValues).append(depth)
                .append(childDataGroupKey).append(childDataGroups).append(visible).toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("key", key).append("summaryValues", summaryValues)
                .append("depth", depth).append("childDataGroupKey", childDataGroupKey)
                .append("childDataGroups", childDataGroups)
                .append("visible", visible).toString();
    }
}
