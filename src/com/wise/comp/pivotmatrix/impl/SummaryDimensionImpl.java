package com.wise.comp.pivotmatrix.impl;

import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.wise.comp.pivotmatrix.SummaryDimension;

public class SummaryDimensionImpl implements SummaryDimension {

	private static Logger log = LoggerFactory.getLogger(SummaryDimensionImpl.class);
	
    private String childDataGroupKey;
    private String key;

    private List<SummaryDimension> children;
    private List<SummaryDimension> unmodifiableChildren;
    private Map<String, SummaryDimension> childMapByKey;

    private SummaryDimension parent;
    private int depth;

    private String path = "";
    private String parentPath;

    private Map<String, Object> attributes;
    
    public SummaryDimensionImpl() {
        this.key = null;
    }

    public SummaryDimensionImpl(final String key) {
        this.key = key;
    }

    @Override
    public String getChildDataGroupKey() {
		return childDataGroupKey;
	}

	void setChildDataGroupKey(String childDataGroupKey) {
		this.childDataGroupKey = childDataGroupKey;
	}

    @Override
	public String getKey() {
        return key;
    }

    void setKey(String key) {
        this.key = key;
    }

    @Override
    public boolean hasChild() {
        return children != null && !children.isEmpty();
    }

    @Override
    public SummaryDimension getChild(final String key) {
        if (childMapByKey != null) {
            return childMapByKey.get(key);
        }

        return null;
    }

    SummaryDimension addChild(final SummaryDimensionImpl child) {
        if (children == null) {
            children = new LinkedList<>();
            unmodifiableChildren = Collections.unmodifiableList(children);
            childMapByKey = new HashMap<>();
        }

        final boolean added = children.add(child);

        if (!added) {
            throw new IllegalStateException("Child not added!");
        }

        childMapByKey.put(child.getKey(), child);

        child.setParent(this);
        child.depth = depth + 1;
        child.path = path + PATH_DELIMITER + child.getKey();

        return child;
    }

    @Override
    public List<SummaryDimension> getChildren() {
        return unmodifiableChildren;
    }

    public void setChildren(List<SummaryDimension> children) {
        if (this.children == null) {
            this.children = new LinkedList<>();
            unmodifiableChildren = Collections.unmodifiableList(this.children);
            childMapByKey = new HashMap<>();
        }

        if (children != null) {
            for (SummaryDimension child : children) {
                this.children.add(child);
                childMapByKey.put(child.getKey(), child);
            }
        }
    }

    @JsonIgnore
    @Override
    public int getChildCount() {
        return unmodifiableChildren != null ? unmodifiableChildren.size() : 0;
    }

    @JsonIgnore
    @Override
    public SummaryDimension getParent() {
        return parent;
    }
    
    void setParent(SummaryDimension parent) {
		this.parent = parent;
		this.parentPath = parent == null? null : parent.getPath();
	}

    @Override
	public int getDepth() {
        return depth;
    }

    void setDepth(int depth) {
        this.depth = depth;
    }

    @Override
    public String getPath() {
        return path;
    }

    void setPath(String path) {
        this.path = path;
    }

    @Override
	public String getParentPath() {
		return parentPath;
	}

	void setParentPath(String parentPath) {
		this.parentPath = parentPath;
	}
    
    void sortChildSummaryDimensions(final Comparator<SummaryDimension> comparator) {
    	if (children != null) {
    		try {
    			Collections.sort(children, comparator);
    		}
    		catch (Exception e) {
    			log.error("Failed to sort child summary dimensions using comparator: " + comparator
    					+ ". children: {}", children, e);
    		}
    	}
    }

    @JsonIgnore
    @Override
    public Map<String, Object> getAttributes() {
    	if(attributes == null) {
    		return Collections.emptyMap();
    	}
    	
    	return Collections.unmodifiableMap(attributes);
    }
    
    @Override
	public Object getAttribute(final String name) {
		return attributes != null ? attributes.get(name) : null;
	}
	
    @Override
	public void setAttribute(final String name, final Object value) {
		if(attributes == null) {
			attributes = new HashMap<>();
		}
		
		attributes.put(name, value);
	}
	
	void removeAttribute(final String name) {
		if(attributes != null) {
			attributes.remove(name);
		}
	}
}
