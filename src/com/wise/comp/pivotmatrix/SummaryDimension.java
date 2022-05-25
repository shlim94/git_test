package com.wise.comp.pivotmatrix;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;

public interface SummaryDimension {

    public static final String PATH_DELIMITER = "~|_";

    public String getChildDataGroupKey();

	public String getKey();

    public boolean hasChild();

    public SummaryDimension getChild(final String key);

    public List<SummaryDimension> getChildren();

;    @JsonIgnore
    public int getChildCount();

    @JsonIgnore
    public SummaryDimension getParent();
    
	public int getDepth();

    public String getPath();

;	public String getParentPath();;

    @JsonIgnore
    public Map<String, Object> getAttributes();
    
	public Object getAttribute(final String name);
	
	public void setAttribute(final String name, final Object value);
}
