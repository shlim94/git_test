package com.wise.ds.repository;

import java.util.ArrayList;
import java.util.List;

import net.sf.json.JSONObject;

import com.wise.common.util.CoreUtils;

public class CubeTableColumnVO {
    private String uniqueName;
    private int cubeId;
    private String tableName; // logical table name
    private String captionName;
    private String physicalTableName;
    private String physicalColumnName;
    private String physicalColumnId;
    private String HIE_HIE_UNI_NM;
    private String summaryType;
    private String format;
    private String folder;
    private int visible;
    private String expression;
    private String type; // measure or dimension
    private String orderBy; // measure or dimension
    private String dataType;
    private String logicalTableName; //측정값 컬럼의 테이블 caption
    private String logicalColumnName; //측정값 컬럼의 컬럼 caption
    private int ordinal;
    
    private boolean isFolderType = false; // 폴더에 속한 컬럼인지 여부
    private boolean isSnowFlakeType = false; // 스노우플레이크 여부
    private boolean isLevelType = false; // 계층형컬럼 여부
    private boolean isLevelLeafType = false; // 계층형자식 여부
    
    private String hieFolderName; // fieldType(level, custom)으로 변경
    
    private List<String> levelChildren;
    
    
    public String getOrderBy() {
		return orderBy;
	}

	public void setOrderBy(String orderBy) {
		this.orderBy = orderBy;
	}

	public String getPhysicalColumnId() {
		return physicalColumnId;
	}

	public void setPhysicalColumnId(String physicalColumnId) {
		this.physicalColumnId = physicalColumnId;
	}

	public CubeTableColumnVO() {
        this.levelChildren = new ArrayList<String>();
    }
    
    public CubeTableColumnVO(String uid) {
        this();
        this.uniqueName = uid;
    }
    
    public CubeTableColumnVO(JSONObject col) {
        this();
        if (col.containsKey("uid")) this.uniqueName = col.getString("uid");
    }

    public int getCubeId() {
        return cubeId;
    }

    public void setCubeId(int cubeId) {
        this.cubeId = cubeId;
    }

    public String getTableName() {
        return tableName;
    }

    public void setTableName(String tableName) {
        this.tableName = tableName;
    }

    public String getUniqueName() {
        return uniqueName;
    }

    public void setUniqueName(String uniqueName) {
        this.uniqueName = uniqueName;
//        if (CoreUtils.ifNull(this.uniqueName).indexOf("HieLvl") > -1) {
//            this.isLevelType = true;
//        }
    }

    public String getCaptionName() {
        return captionName;
    }

    public void setCaptionName(String captionName) {
        this.captionName = captionName;
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

    public String getSummaryType() {
        return summaryType;
    }

    public void setSummaryType(String summaryType) {
        this.summaryType = summaryType;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public int getVisible() {
        return visible;
    }

    public void setVisible(int visible) {
        this.visible = visible;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getHieFolderName() {
        return hieFolderName;
    }

    public void setHieFolderName(String hieFolderName) {
        this.hieFolderName = hieFolderName;
        
        if (hieFolderName != null) {
            if ("SF".equals(this.hieFolderName)) {
                this.isSnowFlakeType = true;
            }
            else if ("LEVEL".equals(this.hieFolderName)) {
                this.isLevelType = true;
            }
            else if ("LEVEL_LEAF".equals(this.hieFolderName)) {
                this.isLevelLeafType = true;
            }
            else {
                this.isFolderType = true;
            }
        }
    }
    
    public int getOrdinal() {
        return ordinal;
    }

    public void setOrdinal(int ordinal) {
        this.ordinal = ordinal;
    }

    public boolean getIsLevelType() {
        return this.isLevelType;
    }
    
    public boolean getIsFolderType() {
        return isFolderType;
    }

    public boolean getIsSnowFlakeType() {
        return isSnowFlakeType;
    }

    public List<String> getLevelChildren() {
        return levelChildren;
    }

    public void setLevelChildren(List<String> levelChildren) {
        this.levelChildren = levelChildren;
    }
    public void addLevelChild(String logicalColumnName) {
        this.levelChildren.add(logicalColumnName);
    }

    public boolean getIsLevelLeafType() {
        return isLevelLeafType;
    }
    
    public String getDataType() {
		return dataType;
	}

	public void setDataType(String dataType) {
		this.dataType = dataType;
	}
	
	public String getFolder() {
		return folder;
	}

	public void setFolder(String folder) {
		this.folder = folder;
	}
	
	public String getHIE_HIE_UNI_NM() {
		return HIE_HIE_UNI_NM;
	}

	public void setHIE_HIE_UNI_NM(String hIE_HIE_UNI_NM) {
		HIE_HIE_UNI_NM = hIE_HIE_UNI_NM;
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

	@Override
    public String toString() {
        return "CubeTableColumnVO [uniqueName=" + uniqueName + ", cubeId=" + cubeId + ", tableName=" + tableName + ", captionName=" + captionName
                + ", physicalTableName=" + physicalTableName + ", physicalColumnName=" + physicalColumnName + ", summaryType=" + summaryType
                + ", format=" + format + ", visible=" + visible + ", expression=" + expression + ", type=" + type + ", isFolderType=" + isFolderType
                + ", isSnowFlakeType=" + isSnowFlakeType + ", isLevelType=" + isLevelType + ", isLevelLeafType=" + isLevelLeafType
                + ", hieFolderName=" + hieFolderName + ", levelChildren=" + levelChildren + "]";
    }
}
