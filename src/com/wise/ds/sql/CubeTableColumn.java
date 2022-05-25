package com.wise.ds.sql;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class CubeTableColumn {
    private int dsViewId;
    private String cubeId;
    private String columnType;
    private String logicalTableName;
    private String logicalColumnName;
    private String columnCaption;
    private String aggregationType;
    private String displayType; // 일반컬럼: null, 계산컬럼:CUSTOM, 계층컬럼:LEVEL, 스노우플레이크 컬럼:SF, 폴더컬럼:not null
    private String expression;
    private String physicalTableName;
    private String physicalColumnName;
    private String physicalColumnKey;
    private String dataType;
    private String dataLength;
    private String primaryKeyYN;
    private String visible;
    
    /* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
    private String orderByCaption;
    private String uniqueName;

    private String levelLogicalColumnName;
    private String levelColumnCaption;
    private int level;
    private String orderBy;
    /* DOGFOOT ktkang 주제영역 필터 유형 추가  20200806 */
    private int dateKey;
    private int noLoading;
    
    private List<CubeTableColumn> levelChildren;

    public CubeTableColumn() {
        this.levelChildren = new ArrayList<CubeTableColumn>();
    }

    public void addLevelChild(CubeTableColumn levelChild) {
        this.levelChildren.add(levelChild);
        Collections.sort(this.levelChildren, new Comparator<CubeTableColumn>() {
            @Override
            public int compare(CubeTableColumn arg0, CubeTableColumn arg1) {
                return arg0.getLevel() < arg1.getLevel() ? -1 : arg0.getLevel() > arg1.getLevel() ? 1:0;
            }
        });
    }

    public List<CubeTableColumn> getLevelChildren() {
        return levelChildren;
    }

    

	public String getPhysicalColumnKey() {
		return physicalColumnKey;
	}

	public void setPhysicalColumnKey(String physicalColumnKey) {
		this.physicalColumnKey = physicalColumnKey;
	}

	public String getOrderBy() {
		return orderBy;
	}

	public void setOrderBy(String orderBy) {
		this.orderBy = orderBy;
	}

	public int getDsViewId() {
        return dsViewId;
    }

    public void setDsViewId(int dsViewId) {
        this.dsViewId = dsViewId;
    }

    public String getCubeId() {
        return cubeId;
    }

    public void setCubeId(String cubeId) {
        this.cubeId = cubeId;
    }

    public String getLogicalTableName() {
        return logicalTableName;
    }

    public void setLogicalTableName(String logicalTableName) {
        this.logicalTableName = logicalTableName;
    }

    public String getLogicalColumnName() {
        return logicalColumnName;
    }

    public void setLogicalColumnName(String logicalColumnName) {
        this.logicalColumnName = logicalColumnName;
    }

    public String getColumnCaption() {
        return columnCaption;
    }

    public void setColumnCaption(String columnCaption) {
        this.columnCaption = columnCaption;
    }

    public String getAggregationType() {
        return aggregationType;
    }

    public void setAggregationType(String aggregationType) {
        this.aggregationType = aggregationType;
    }

    public String getDisplayType() {
        return displayType;
    }

    public void setDisplayType(String displayType) {
        this.displayType = displayType;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }

    public String getPhysicalTableName() {
        return physicalTableName;
    }

    public void setPhysicalTableName(String physicalTableName) {
        this.physicalTableName = physicalTableName;
    }

    public String getPhysicalColumnName() {
        return physicalColumnName;
    }

    public void setPhysicalColumnName(String physicalColumnName) {
        this.physicalColumnName = physicalColumnName;
    }

    public String getDataType() {
        return dataType;
    }

    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    public String getDataLength() {
        return dataLength;
    }

    public void setDataLength(String dataLength) {
        this.dataLength = dataLength;
    }

    public String getPrimaryKeyYN() {
        return primaryKeyYN;
    }

    public void setPrimaryKeyYN(String primaryKeyYN) {
        this.primaryKeyYN = primaryKeyYN;
    }

    public String getVisible() {
        return visible;
    }

    public void setVisible(String visible) {
        this.visible = visible;
    }

    public String getLevelLogicalColumnName() {
        return levelLogicalColumnName;
    }

    public void setLevelLogicalColumnName(String levelLogicalColumnName) {
        this.levelLogicalColumnName = levelLogicalColumnName;
    }

    public String getLevelColumnCaption() {
        return levelColumnCaption;
    }

    public void setLevelColumnCaption(String levelColumnCaption) {
        this.levelColumnCaption = levelColumnCaption;
    }

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

	public String getColumnType() {
        return columnType;
    }

    public void setColumnType(String columnType) {
        this.columnType = columnType;
    }
    /* DOGFOOT ktkang 주제영역 필터 유형 추가  20200806 */
    public int getDateKey() {
        return dateKey;
    }

    public void setDateKey(int dateKey) {
        this.dateKey = dateKey;
    }
    
    public int getNoLoading() {
        return noLoading;
    }

    public void setNoLoading(int noLoading) {
        this.noLoading = noLoading;
    }
    
    /* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
    public String getOrderByCaption() {
        return orderByCaption;
    }

    public void setOrderByCaption(String orderByCaption) {
        this.orderByCaption = orderByCaption;
    }
    
    public String getUniqueName() {
        return uniqueName;
    }

    public void setUniqueName(String uniqueName) {
        this.uniqueName = uniqueName;
    }

    @Override
    public String toString() {
        return "CubeTableColumn [dsViewId=" + dsViewId + ", cubeId=" + cubeId + ", columnType=" + columnType + ", logicalTableName="
                + logicalTableName + ", logicalColumnName=" + logicalColumnName + ", columnCaption=" + columnCaption + ", aggregationType="
                + aggregationType + ", displayType=" + displayType + ", expression=" + expression + ", physicalTableName=" + physicalTableName
                + ", physicalColumnName=" + physicalColumnName + ", dataType=" + dataType + ", dataLength=" + dataLength + ", primaryKeyYN="
                + primaryKeyYN + ", visible=" + visible + ", levelLogicalColumnName=" + levelLogicalColumnName + ", levelColumnCaption="
                + levelColumnCaption + ", level=" + level + ", levelChildren=" + levelChildren + "]";
    }

}
