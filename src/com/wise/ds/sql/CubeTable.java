package com.wise.ds.sql;

import java.util.ArrayList;
import java.util.List;

public class CubeTable {
    public String name;
    public String alias;
    public List<CubeTableColumn> colums;

    public CubeTable() {
        this.colums = new ArrayList<CubeTableColumn>();
    }

    public CubeTable(String name, String alias) {
        this();
        this.name = name;
        this.alias = alias;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public List<CubeTableColumn> getColums() {
        return colums;
    }

    public void setColums(List<CubeTableColumn> colums) {
        this.colums = colums;
    }

    public void addColumn(CubeTableColumn column) {
        this.colums.add(column);
    }

    @Override
    public String toString() {
        return "CubeTable [name=" + name + ", alias=" + alias + ", colums=" + colums + "]";
    }

}
