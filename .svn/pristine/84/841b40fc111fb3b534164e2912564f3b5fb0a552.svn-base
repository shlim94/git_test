package com.wise.ds.sql;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import com.wise.common.util.CoreUtils;
import com.wise.ds.repository.CubeTableColumnVO;
import com.wise.ds.repository.CubeTableConstraintVO;
import com.wise.ds.repository.SnowFlakeRelation;

public class CubeTableRelationFinder {
	private List<CubeTableConstraintVO> cubeConstraints;
	private List<CubeTableConstraintVO> viewConstraints;
	
	private List<SnowFlakeRelation> snowFlakeRelations;
	
	private CubeTableColumnManager columnManager;
	
	public CubeTableRelationFinder() {
	    this.snowFlakeRelations = new ArrayList<SnowFlakeRelation>();
	}
	
	public void plotSnowFlakeRelations(Map<String, CubeTable> facts) {
	    Map<String, HashSet<String>> relationDimensionsWithFact = new HashMap<String,HashSet<String>>();
	    
        List<CubeTableConstraintVO> viewConstraints = this.getViewConstraints();
//        System.out.println("viewConstraints] " + viewConstraints);
        
        CubeTable factTable;
        Object[] keyset0 = facts.keySet().toArray();
        for (Object key : keyset0) {
            factTable = facts.get(key);
//            System.out.println("factTable>> " + factTable);
            
            HashSet<String> dimensions = new HashSet<String>();
            
            for (CubeTableConstraintVO viewConstraint : viewConstraints) {
                if (viewConstraint.getFkTableName().equals(factTable.getName())) {
                    if (!dimensions.contains(viewConstraint.getPkTableName())) {
                        dimensions.add(viewConstraint.getPkTableName());
                    }
                }
            }
            
            relationDimensionsWithFact.put(factTable.getName(), dimensions);
        }
        
        Object[] keyset1 = relationDimensionsWithFact.keySet().toArray();
        for (Object fact : keyset1) {
            HashSet<String> relationDimensions = relationDimensionsWithFact.get(fact);
            
            for (String dimension : relationDimensions) {
                this.plotHierarchyDimensionRelation(dimension);
            }
        }
        
        // for debuging
        for (SnowFlakeRelation sfr : this.snowFlakeRelations) {
//            System.out.println("temp sfr#0] " + sfr);
        }
    }
	
	private void plotHierarchyDimensionRelation(String fkTableName) {
	    List<CubeTableConstraintVO> viewConstraints = this.getViewConstraints();
	    
	    List<String> subRelationDimensions = new ArrayList<String>();
	    for (CubeTableConstraintVO viewConstraint : viewConstraints) {
	        if (viewConstraint.getFkTableName().equals(fkTableName)
	                && !viewConstraint.getPkTableName().equals(fkTableName)) {
	            subRelationDimensions.add(viewConstraint.getPkTableName());
	        }
	    }
	    
	    for (String dimension : subRelationDimensions) {
	        SnowFlakeRelation sfr = new SnowFlakeRelation();
	        sfr.setKeyTableName(dimension);
	        sfr.setTableCaption(this.getDsViewTableCaption(dimension));
	        sfr.setParentTableName(fkTableName);
	        sfr.setParentTableCaption(this.getDsViewTableCaption(fkTableName));
	        this.snowFlakeRelations.add(sfr);
	        
	        this.plotHierarchyDimensionRelation(dimension);
	    }
	}
	
	private String getDsViewTableCaption(String physicalTableName) {
	    String tableCaption = null;
	    for (CubeTable table : this.columnManager.getDsViewTableMaster()) {
	        if (table.getName().equals(physicalTableName)) {
	            tableCaption = table.getAlias();
	            break;
	        }
	    }
	    return tableCaption;
	}
	
	public List<CubeTableConstraintVO> findCubeConstraint(String factLogicalTableName, String dimensionLogicalTableName) {
        List<CubeTableConstraintVO> constraint = new ArrayList<CubeTableConstraintVO>();
        for (CubeTableConstraintVO constraint0 : this.cubeConstraints) {
            if ((factLogicalTableName.equals(constraint0.getMeasureTableName()) 
                    && dimensionLogicalTableName.equals(constraint0.getDimensionLogicalTableName()))) {
                constraint.add(constraint0);
                break;
            }
        }
        return constraint;
    }
    
	public List<CubeTableConstraintVO> findViewConstraint(String parentTableName, String childTableName) {
        List<CubeTableConstraintVO> constraint = new ArrayList<CubeTableConstraintVO>();
        for (CubeTableConstraintVO constraint0 : this.viewConstraints) {
            if (constraint0.getFkTableName().equals(childTableName)
                    && constraint0.getPkTableName().equals(parentTableName)) {
                constraint.add(constraint0);
                break;
            }
        }
        return constraint;
    }
    
	public SnowFlakeRelation findSnowFlakeRelationByPhysicalTableName(String physicalTableName) {
        SnowFlakeRelation relation = null;
        for (SnowFlakeRelation relation0 : this.snowFlakeRelations) {
            if (CoreUtils.ifNull(relation0.getKeyTableName()).equals(physicalTableName)) {
                relation = relation0;
                break;
            }
        }
        return relation;
    }
	
	public List<CubeTableConstraintVO> getCubeConstraints() {
		return cubeConstraints;
	}

	public void setCubeConstraints(List<CubeTableConstraintVO> cubeConstraints) {
		this.cubeConstraints = cubeConstraints;
	}

	public List<CubeTableConstraintVO> getViewConstraints() {
		return viewConstraints;
	}

	public void setViewConstraints(List<CubeTableConstraintVO> viewConstraints) {
		this.viewConstraints = viewConstraints;
	}

	public List<SnowFlakeRelation> getSnowFlakeRelations() {
		return snowFlakeRelations;
	}

	private SnowFlakeRelation getParentRelation(SnowFlakeRelation child) {
        SnowFlakeRelation ret = null;
        if (!child.getKeyTableName().equalsIgnoreCase(child.getParentTableName())) {
            for (SnowFlakeRelation parent : this.snowFlakeRelations) {
                if (child.getParentTableName().equals(parent.getKeyTableName())) {
                    ret = parent;
                    break;
                }
            }
        }
        return ret;
    }

    /*public void setSnowFlakeRelations(List<SnowFlakeRelation> snowFlakeRelations) {
        this.snowFlakeRelations = snowFlakeRelations;

         setting child relation 
        List<SnowFlakeRelation> temp = new ArrayList<SnowFlakeRelation>();
        for (SnowFlakeRelation relation : this.snowFlakeRelations) {
            if (!relation.getKeyTableName().equalsIgnoreCase(relation.getParentTableName())) {
                temp.add(relation);
            }
        }

        SnowFlakeRelation parent;
        SnowFlakeRelation co;
        for (SnowFlakeRelation child : temp) {
            co = child;
            for (boolean checker = true; checker;) {
                parent = this.getParentRelation(co);
                if (parent != null) {
                    child.addParent(parent);
                    co = parent;
                } else {
                    checker = false;
                }
            }
        }

        temp = null;
    }*/
    public void setSnowFlakeRelations(JSONArray measures) {
        Map<String, CubeTable> facts = new HashMap<String, CubeTable>();
        
        JSONObject col;
        String logicalColumnName;
        CubeTableColumn cubeColumn;
        for (int index = 0; index < measures.size(); index++) {
            col = measures.getJSONObject(index);
            
            logicalColumnName = new CubeTableColumnVO(col).getUniqueName();
            cubeColumn = this.columnManager.findColumnByLogicalColumnName(logicalColumnName);
            
            if (cubeColumn == null) continue;
            
            String tableName = cubeColumn.getPhysicalTableName();
            String alias = cubeColumn.getLogicalTableName();
            
            if (!facts.containsKey(alias)) {
                CubeTable table = new CubeTable(tableName, alias);
                facts.put(alias, table);
            }
        }
        
        this.plotSnowFlakeRelations(facts);

        /* setting child relation */
        List<SnowFlakeRelation> temp = new ArrayList<SnowFlakeRelation>();
        for (SnowFlakeRelation relation : this.snowFlakeRelations) {
            if (!relation.getKeyTableName().equalsIgnoreCase(relation.getParentTableName())) {
                temp.add(relation);
            }
        }

        SnowFlakeRelation parent;
        SnowFlakeRelation co;
        for (SnowFlakeRelation child : temp) {
            co = child;
            for (boolean checker = true; checker;) {
                parent = this.getParentRelation(co);
                if (parent != null) {
                    child.addParent(parent);
                    co = parent;
                } else {
                    checker = false;
                }
            }
        }
        
        temp = null;
        
     // for debuging
        for (SnowFlakeRelation sfr : this.snowFlakeRelations) {
//            System.out.println("temp sfr#2] " + sfr);
        }
    }

    public CubeTableColumnManager getColumnManager() {
        return columnManager;
    }

    public void setColumnManager(CubeTableColumnManager columnManager) {
        this.columnManager = columnManager;
    }

}
