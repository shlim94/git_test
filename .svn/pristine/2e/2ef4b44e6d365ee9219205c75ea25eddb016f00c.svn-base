package com.wise.ds.repository;

import java.util.ArrayList;
import java.util.List;

public class CubeTableVO {
    private String type;
    private int cubeId;
    private String uniqueName;
    private String logicalName;
    private String physicalName;
    private int visible;
    private int order;
    private int dsViewId;
    private List<CubeTableColumnVO> columns;
    
    public CubeTableVO() {
        this.columns = new ArrayList<CubeTableColumnVO>();
    }
    
    public CubeTableVO(int cubeId) {
    	this();
    	this.cubeId = cubeId;
    }
    
    public CubeTableVO(int cubeId, int dsViewId) {
    	this();
    	this.cubeId = cubeId;
    	this.dsViewId = dsViewId;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public int getCubeId() {
        return cubeId;
    }

    public void setCubeId(int cubeId) {
        this.cubeId = cubeId;
    }

    public String getUniqueName() {
        return uniqueName;
    }

    public void setUniqueName(String uniqueName) {
        this.uniqueName = uniqueName;
    }

    public String getLogicalName() {
        return logicalName;
    }

    public void setLogicalName(String logicalName) {
        this.logicalName = logicalName;
    }

    public String getPhysicalName() {
        return physicalName;
    }

    public void setPhysicalName(String physicalName) {
        this.physicalName = physicalName;
    }

    public int getVisible() {
        return visible;
    }

    public void setVisible(int visible) {
        this.visible = visible;
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        this.order = order;
    }
    
    public int getDsViewId() {
        return dsViewId;
    }

    public void setDsViewId(int dsViewId) {
        this.dsViewId = dsViewId;
    }
    
    public List<CubeTableColumnVO> getColumns() {
        return columns;
    }

    public void setColumns(List<CubeTableColumnVO> columns) {
        this.columns = columns;
    }
    public void addColumn(CubeTableColumnVO cubeTableColumn) {
        this.columns.add(cubeTableColumn);
    }
    @Override
    public String toString() {
        return "CubeTableVO [type=" + type + ", cubeId=" + cubeId + ", uniqueName=" + uniqueName + ", logicalName=" + logicalName + ", physicalName="
                + physicalName + ", visible=" + visible + ", order=" + order + ", dsViewId=" + dsViewId + ", columns=" + columns + "]";
    }

}
