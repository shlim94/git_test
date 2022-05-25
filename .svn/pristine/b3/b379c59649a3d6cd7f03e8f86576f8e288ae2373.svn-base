package com.wise.ds.repository;

import java.util.Comparator;

import net.sf.json.JSONObject;

public class DimensionSorter implements Comparator<JSONObject> {

    @Override
    public int compare(JSONObject dim1, JSONObject dim2) {
    	
    	if(!dim1.get("AREA_INDEX").equals("") ||!dim2.get("AREA_INDEX").equals("") )
    	{
    		int index1 = dim1.getInt("AREA_INDEX");
            int index2 = dim2.getInt("AREA_INDEX");
            return index1 < index2 ? -1 : index1 > index2 ? 1:0;
    	}
    	else
    	{
    		return 0;
    	}
        
        
        
    }

}
