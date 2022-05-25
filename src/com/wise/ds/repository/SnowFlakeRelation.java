package com.wise.ds.repository;

import java.util.ArrayList;
import java.util.List;

public class SnowFlakeRelation {
//    private int cubeId;
    private String tableCaption;
//    private String tableName;
//    private String dimUniqueName;
//    private String dimCaption;
    private String keyTableName;
    private String parentTableName;
    private String parentTableCaption;
    
    private List<SnowFlakeRelation> parents;
    
    public SnowFlakeRelation() {
        this.parents = new ArrayList<SnowFlakeRelation>();
    }

//    public int getCubeId() {
//        return cubeId;
//    }
//
//    public void setCubeId(int cubeId) {
//        this.cubeId = cubeId;
//    }

    public String getTableCaption() {
        return tableCaption;
    }

    public void setTableCaption(String tableCaption) {
        this.tableCaption = tableCaption;
    }

//    public String getTableName() {
//        return tableName;
//    }
//
//    public void setTableName(String tableName) {
//        this.tableName = tableName;
//    }
//
//    public String getDimUniqueName() {
//        return dimUniqueName;
//    }
//
//    public void setDimUniqueName(String dimUniqueName) {
//        this.dimUniqueName = dimUniqueName;
//    }
//
//    public String getDimCaption() {
//        return dimCaption;
//    }
//
//    public void setDimCaption(String dimCaption) {
//        this.dimCaption = dimCaption;
//    }

    public String getKeyTableName() {
        return keyTableName;
    }

    public void setKeyTableName(String keyTableName) {
        this.keyTableName = keyTableName;
    }

    public String getParentTableName() {
        return parentTableName;
    }

    public void setParentTableName(String parentTableName) {
        this.parentTableName = parentTableName;
    }
    
    public List<SnowFlakeRelation> getParents() {
        return parents;
    }

    public void setParents(List<SnowFlakeRelation> parents) {
        this.parents = parents;
    }
    
    public void addParent(SnowFlakeRelation parent) {
        this.parents.add(parent);
    }

    public String getParentTableCaption() {
        return parentTableCaption == null ? this.parentTableName : this.parentTableCaption;
    }

    public void setParentTableCaption(String parentTableCaption) {
        this.parentTableCaption = parentTableCaption;
    }

    @Override
    public String toString() {
        return "SnowFlakeRelation [tableCaption=" + tableCaption + ", keyTableName=" + keyTableName + ", parentTableName=" + parentTableName
                + ", parentTableCaption=" + parentTableCaption + ", parents=" + parents + "]";
    }

}
