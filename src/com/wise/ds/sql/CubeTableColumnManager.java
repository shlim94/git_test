package com.wise.ds.sql;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CubeTableColumnManager {
    private List<CubeTableColumn> columns;
    private List<CubeTableColumn> levelInfomations;
    
    private Map<String,List<CubeTableColumn>> logicalTables;
    private Map<String,List<CubeTableColumn>> physicalTables;
    
    private List<CubeTable> dsViewTableMaster;

    public CubeTableColumnManager(List<CubeTableColumn> columns, List<CubeTableColumn> levelInfomatinos) {
        this.logicalTables = new HashMap<String,List<CubeTableColumn>>();
        this.physicalTables = new HashMap<String,List<CubeTableColumn>>();
        
        this.columns = columns;
        this.levelInfomations = levelInfomatinos;
        
        CubeTableColumn c;
        for (CubeTableColumn levelChild : this.levelInfomations) {
            c = null;
            for (CubeTableColumn column : this.columns) {
                if (column.getLogicalColumnName() != null 
                        && column.getLogicalColumnName().equals(levelChild.getLogicalColumnName())) {
                    c = column;
                    break;
                }
            }
            
            if (c == null) {
                c = new CubeTableColumn();
                c.setLogicalTableName(levelChild.getLogicalTableName());
                c.setLogicalColumnName(levelChild.getLogicalColumnName());
                c.setDisplayType("LEVEL");
                c.setColumnType("dimension");
                this.columns.add(c);
            }
            
            c.addLevelChild(levelChild);
        }
        
        String tableName;
        List<CubeTableColumn> lt;
        for (CubeTableColumn column : columns) {
            if (column.getLogicalTableName() != null) {
                tableName = column.getLogicalTableName();
                if (this.logicalTables.containsKey(tableName)) {
                    lt = this.logicalTables.get(tableName);
                }
                else {
                    lt = new ArrayList<CubeTableColumn>();
                    this.logicalTables.put(tableName, lt);
                }
                lt.add(column);
            }
        }
        
        List<CubeTableColumn> pt;
        for (CubeTableColumn column : columns) {
            if (column.getPhysicalTableName() != null) {
                tableName = column.getPhysicalTableName();
                if (this.physicalTables.containsKey(tableName)) {
                    pt = this.physicalTables.get(tableName);
                }
                else {
                    pt = new ArrayList<CubeTableColumn>();
                    this.physicalTables.put(tableName, pt);
                }
                pt.add(column);
            }
        }
    }

    public List<CubeTableColumn> getColumns() {
        return columns;
    }

    public Map<String, List<CubeTableColumn>> getTables() {
        return physicalTables;
    }

    public Map<String, List<CubeTableColumn>> getLogicalTables() {
        return logicalTables;
    }

    public Map<String, List<CubeTableColumn>> getPhysicalTables() {
        return physicalTables;
    }

    public CubeTableColumn findColumnByLogicalColumnName(String logicalColumnName) {
        CubeTableColumn ret = null;
        for (CubeTableColumn column : this.columns) {
            if (column.getLogicalColumnName() != null && column.getLogicalColumnName().equals(logicalColumnName)) {
                ret = column;
                break;
            }
        }
        return ret;
    }
    public CubeTableColumn findColumnByPhysicalColumnName(String physicalColumnName) {
        CubeTableColumn ret = null;
        for (CubeTableColumn column : this.columns) {
            if (column.getPhysicalColumnName().equals(physicalColumnName)) {
                ret = column;
                break;
            }
        }
        return ret;
    }
    
    public List<CubeTable> getDsViewTableMaster() {
        return dsViewTableMaster;
    }

    public void setDsViewTableMaster(List<CubeTable> dsViewTableMaster) {
        this.dsViewTableMaster = dsViewTableMaster;
    }

    @Override
    public String toString() {
        return "CubeTableColumnManager [logicalTables=" + logicalTables + ", physicalTables=" + physicalTables + "]";
    }
}
