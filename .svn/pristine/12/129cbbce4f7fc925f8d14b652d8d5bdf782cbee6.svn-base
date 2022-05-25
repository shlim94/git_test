package com.wise.ds.query.util;

import java.util.Iterator;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.springframework.stereotype.Service;

import com.wise.authn.User;

@Service("sqlMapper")
public class SqlMapper {
	/*dogfoot shlim 20210414*/
	public String mapParameter(String sql, JSONObject params,String whereClause, User user) {
        String sqlMap = sql;
        
        String key;
        JSONObject valueObject;
        
        String value = "";
        String defValue = "";
        String valueType;
        String parameterType;
        
        @SuppressWarnings("unchecked")
        Iterator<String> keySet = params.keys();
        /* DOGFOOT ktkang 데이터 집합 기본값 USE_SQL 로 되어있을 때 오류 수정  20200701 */
        if(whereClause.equals("dataset")) {
        	while(keySet.hasNext()) {
        		key = (String) keySet.next();
        		valueObject = params.getJSONObject(key);

        		parameterType = valueObject.containsKey("parameterType") ? valueObject.getString("parameterType") : "";
        		/* DOGFOOT ktkang 데이터 집합 기본값 USE_SQL 로 되어있을 때 오류 수정  20200701 */
        		if(parameterType.equals("")) {
        			parameterType = valueObject.containsKey("PARAM_TYPE") ? valueObject.getString("PARAM_TYPE") : "";
        		}

        		value = valueObject.getString("whereClause");

        		if ("BETWEEN_CAND".equals(parameterType) || "BETWEEN_INPUT".equals(parameterType) || "BETWEEN_LIST".equals(parameterType)) {
        			sqlMap = sqlMap.replaceAll(" (?i)BETWEEN ", " = " );
        		}

        		key = key.replaceAll("\\[", "\\\\[").replaceAll("\\]", "\\\\]").replaceAll("\\.","\\\\.");
        		//정규식 단어 완전 일치 ^
        		sqlMap = sqlMap.replaceAll("(" + key + ")\\s" , value + " ");
        		sqlMap = sqlMap.replaceAll("(" + key + ")," , value + ",");
        		sqlMap = sqlMap.replaceAll("(" + key + ")\\)" , value + ")");
        		sqlMap = sqlMap.replaceAll("(" + key + ")\\|" , value + "|");
        		sqlMap = sqlMap.replaceAll( key , value );
        	}
        } else {
        	while(keySet.hasNext()) {
        		key = (String) keySet.next();
        		valueObject = params.getJSONObject(key);

        		if(sqlMap == "") {
        			sqlMap = valueObject.getString("defaultValue");
        		}
        		parameterType = valueObject.containsKey("parameterType") ? valueObject.getString("parameterType") : "";
        		valueType = valueObject.getString("type");

        		if ("BETWEEN_CAND".equals(parameterType)) {
        			String tmpVal = "";
        			if(key.lastIndexOf("_fr") > -1)
        			{
        				value = valueObject.getString("betweenCalendarValue");
        				value = this.getValue(valueType, value);
        				value = value + " AND ";
        			}
        			else
        			{
        				tmpVal = valueObject.getString("betweenCalendarValue");
        				tmpVal = this.getValue(valueType, tmpVal);
        				value = value + tmpVal;
        				key = valueObject.getString("orgParamName");
        			}
        		} 
        		else if ("BETWEEN_LIST".equals(parameterType)|| "BETWEEN_INPUT".equals(parameterType)) {
        			String tmpVal = "";
        			if(key.lastIndexOf("_fr") > -1)
        			{
        				value = valueObject.getString("value");
        				value = this.getValue(valueType, value);
        				value = value + " AND ";
        			}
        			else
        			{
        				tmpVal = valueObject.getString("value");
        				tmpVal = this.getValue(valueType, tmpVal);
        				value = value + tmpVal;
        				key = valueObject.getString("uniqueName");
        			}
        		} 

        		else {

        			Object valObj = valueObject.get("value");
        			Object defObj = valueObject.get("defaultValue");
        			JSONArray valueList;
        			JSONArray defValueList;

        			if(valObj instanceof JSONArray)
        			{
        				valueList = valueObject.getJSONArray("value");
        			}
        			else
        			{
        				valueList = new JSONArray();
        				valueList.add(valueObject.getString("value"));
        			}

        			if (valueList.size() == 1) {
        				value = this.getValue(valueType, valueList.getString(0));
        				/* DOGFOOT ktkang 빈값을 강제로 전체로 조회하던 부분 변경  20200702 */
        				if("_EMPTY_VALUE_".equals(value) || "'_EMPTY_VALUE_'".equals(value)) {
//        					value = "''";
        					if(defObj instanceof JSONArray)
                			{
        						defValueList = valueObject.getJSONArray("defaultValue");
                			}
                			else
                			{
                				defValueList = new JSONArray();
                				defValueList.add(valueObject.getString("defaultValue"));
                			}
        					/* DOGFOOT ktkang 고용정보원11 필터 기본값 없을때 조건절로 넘어가도록 */
        					if(defValueList.size() > 0) {
        						defValue = this.getValue(valueType, defValueList.getString(0));
        					} else {
        						defValue = "_ALL_VALUE_";
        					}
        					if(!"_EMPTY_VALUE_".equals(defValue) && !"'_EMPTY_VALUE_'".equals(defValue) && !"_ALL_VALUE_".equals(defValue) && !"'_ALL_VALUE_'".equals(defValue) && !"'null'".equals(defValue)
        							&& !"'[All]'".equals(defValue) && !"[All]".equals(defValue)) {
        						value = defValue;
        					} else {
        						value = valueObject.getString("whereClause");
        					}
        				} else if ("_ALL_VALUE_".equals(value) || "'_ALL_VALUE_'".equals(value)|| "'null'".equals(value)) {
        					//whereClause = (String) valueObject.getString("whereClause");
        					value = valueObject.getString("whereClause");
        				} 
        				/*    else if(value.equalsIgnoreCase("''"))
                    {
                    	String hiddenValues = valueObject.getString("hiddenValue");

                    	 if (hiddenValues.length() > 0) {
                             value = "'" + hiddenValues + "'";
                         }
                         else {
                             value = "";
                         }
                    }*/
        			}
        			else if (valueList.size() == 0) {
        				value = valueObject.getString("defaultValue");
        				/* DOGFOOT ktkang 빈값을 강제로 전체로 조회하던 부분 변경  20200702 */
        				if("".equals(value) || "''".equals(value)) {
//        					value = "''";
        					whereClause = (String) valueObject.getString("whereClause");
        					value = whereClause;
        				} else if ("[All]".equals(value) || "'[All]'".equals(value)) {
        					whereClause = (String) valueObject.getString("whereClause");
        					value = whereClause;
        				} 
        			}
        			else if (valueList.size() > 1) {
        				value = "";
        				for (int x0 = 0; x0 < valueList.size(); x0++) {
        					value += this.getValue(valueType, valueList.getString(x0)) + ",";
        				}
        				value = value.substring(0, value.length() - 1);
        			}
        			else {
        				value = "";
        			}
        		}

        		key = key.replaceAll("\\[", "\\\\[").replaceAll("\\]", "\\\\]").replaceAll("\\.","\\\\.");
        		//정규식 단어 완전 일치 ^
        		sqlMap = sqlMap.replaceAll("(" + key + ")\\s" , value + " ");
        		sqlMap = sqlMap.replaceAll("(" + key + ")," , value + ",");
        		sqlMap = sqlMap.replaceAll("(" + key + ")\\)" , value + ")");
        		sqlMap = sqlMap.replaceAll("(" + key + ")\\|" , value + "|");
        		sqlMap = sqlMap.replaceAll( key , value );
        	}
        }
        
        return sqlMap;
    }
	
	public String mapParameter(String sql, JSONObject params) {
        String sqlMap = sql;
        
        String key;
        JSONObject valueObject;
        
        String value = "";
        String valueType;
        String parameterType;
        
        @SuppressWarnings("unchecked")
        Iterator<String> keySet = params.keys();
         
        while(keySet.hasNext()) {
            key = (String) keySet.next();
            valueObject = params.getJSONObject(key);
            
            parameterType = valueObject.containsKey("parameterType") ? valueObject.getString("parameterType") : "";
            if(parameterType.equals("")) {
            	parameterType = valueObject.containsKey("PARAM_TYPE") ? valueObject.getString("PARAM_TYPE") : "";
            }
            
            valueType = valueObject.containsKey("type") ? valueObject.getString("type") : "";
            if(valueType.equals("")) {
            	valueType = valueObject.containsKey("DATA_TYPE") ? valueObject.getString("DATA_TYPE") : "";
            }
            
            if ("BETWEEN_CAND".equals(parameterType)) {
            	String tmpVal = "";
            	if(key.lastIndexOf("_fr") > -1)
            	{
            		value = valueObject.getString("betweenCalendarValue");
            		value = this.getValue(valueType, value);
            		/* DOGFOOT ktkang 비트윈 달력 처음에 불러올 때 빈값 처리  20200708 */
            		if(value.indexOf("_EMPTY_VALUE_") > -1) {
    					value = valueObject.getString("defaultValue");
    					value = value.split(",")[0].replace("[", "").replace("\"", "");
    				}
            		value = value + " AND ";
            	}
            	else
            	{
            		tmpVal = valueObject.getString("betweenCalendarValue");
            		tmpVal = this.getValue(valueType, tmpVal);
            		/* DOGFOOT ktkang 비트윈 달력 처음에 불러올 때 빈값 처리  20200708 */
            		if(tmpVal.indexOf("_EMPTY_VALUE_") > -1) {
            			tmpVal = valueObject.getString("defaultValue");
            			tmpVal = tmpVal.split(",")[1].replace("]", "").replace("\"", "");
    				}
            		value = value + tmpVal;
            		key = valueObject.getString("orgParamName");
            	}
            }
            else if ("BETWEEN_LIST".equals(parameterType)) {
            	String tmpVal = "";
            	if(key.lastIndexOf("_fr") > -1)
            	{
            		value = valueObject.getString("betweenCalendarValue");
            		/* DOGFOOT ktkang 빈값을 강제로 전체로 조회하던 부분 변경  20200702 */
            		if("_EMPTY_VALUE_".equals(value) || "'_EMPTY_VALUE_'".equals(value)) {
//            			value = "";
            			value = (String) valueObject.getString("whereClause");
            		} else if ("_ALL_VALUE_".equals(value) || "'_ALL_VALUE_'".equals(value)) {
            			value = (String) valueObject.getString("whereClause");
                    } else {
                    	value = this.getValue(valueType, value);
                    }
            		value = value + " AND ";
            	}
            	else
            	{
            		tmpVal = valueObject.getString("betweenCalendarValue");
            		/* DOGFOOT ktkang 빈값을 강제로 전체로 조회하던 부분 변경  20200702 */
            		if("_EMPTY_VALUE_".equals(tmpVal) || "'_EMPTY_VALUE_'".equals(tmpVal)) {
//            			tmpVal = "''";
            			tmpVal = (String) valueObject.getString("whereClause");
            		} else if ("_ALL_VALUE_".equals(tmpVal) || "'_ALL_VALUE_'".equals(tmpVal)) {
            			tmpVal = (String) valueObject.getString("whereClause");
                    } else {
                    	tmpVal = this.getValue(valueType, tmpVal);
                    }
            		value = value + tmpVal;
            		key = valueObject.getString("orgParamName");
            	}
            } 
            else if("BETWEEN_INPUT".equals(parameterType)) {
            	String tmpVal = "";
            	if(key.lastIndexOf("_fr") > -1)
            	{
            		value = valueObject.getString("betweenCalendarValue");
//            		value = this.getValue(valueType, value);
            		if ("_EMPTY_VALUE_".equals(value) || "'_EMPTY_VALUE_'".equals(value)
                            || "_ALL_VALUE_".equals(value) || "'_ALL_VALUE_'".equals(value)) {
            			value = (String) valueObject.getString("whereClause");
                    } else {
                    	value = this.getValue(valueType, value);
                    }
            		value = value + " AND ";
            	}
            	else
            	{
            		tmpVal = valueObject.getString("betweenCalendarValue");
//            		tmpVal = this.getValue(valueType, tmpVal);
					/* DOGFOOT ktkang 빈값을 강제로 전체로 조회하던 부분 변경  20200702 */
            		if("_EMPTY_VALUE_".equals(tmpVal) || "'_EMPTY_VALUE_'".equals(tmpVal)) {
//            			tmpVal = "";
            			tmpVal = (String) valueObject.getString("whereClause");
            		} else if ("_ALL_VALUE_".equals(tmpVal) || "'_ALL_VALUE_'".equals(tmpVal)) {
            			tmpVal = (String) valueObject.getString("whereClause");
                    } else {
                    	tmpVal = this.getValue(valueType, tmpVal);
                    }
            		value = value + tmpVal;
            		key = valueObject.getString("orgParamName");
            	}
            }
            else {
                String whereClause;
                Object valObj = valueObject.get("value");
                JSONArray valueList;
                
                /* DOGFOOT hsshim 200103
				 * 스프레드 시트 필터 오류 수정
				 */
				 /* DOGFOOT ktkang 스프레드 시트 필터 오류 수정  20200703 */
                if (valObj == null || valObj.toString().equals("[null]")) {
                	valueList = new JSONArray();
                }
                else if(valObj instanceof JSONArray) {
                	valueList = valueObject.getJSONArray("value");
                }
                else {
                /* DOGFOOT hsshim 200103 끝 */
                	valueList = new JSONArray();
                	valueList.add(valueObject.getString("value"));
                }
                
                if (valueList.size() == 1) {
                    value = this.getValue(valueType, valueList.getString(0));
                    /* DOGFOOT ktkang 빈값을 강제로 전체로 조회하던 부분 변경  20200702 */
                    if("_EMPTY_VALUE_".equals(value) || "'_EMPTY_VALUE_'".equals(value)) {
//                    	value = "";
                    	 whereClause = (String) valueObject.getString("whereClause");
                         value = whereClause;
                    } else if ("_ALL_VALUE_".equals(value) || "'_ALL_VALUE_'".equals(value)) {
                        whereClause = (String) valueObject.getString("whereClause");
                        value = whereClause;
                    } 
                    /*dogfoot 조건절 없는 매개변수 생성시 오류 수정 shlim 20200625*/
                    /*dogfoot 달력 NUMERIC TYPE 오류 수정 shlim 20210311*/
                    if(value.equals("")) {
                    	if(valueObject.get("type").equals("NUMERIC")){
                    		value = "0";
                    	}else {
                    		value = "''";
                    	}
                    	
                    }
                /*    else if(value.equalsIgnoreCase("''"))
                    {
                    	String hiddenValues = valueObject.getString("hiddenValue");
                    	 
                    	 if (hiddenValues.length() > 0) {
                             value = "'" + hiddenValues + "'";
                         }
                         else {
                             value = "";
                         }
                    }*/
                }
                else if (valueList.size() == 0) {
                	value = this.getValue(valueType, valueObject.getString("defaultValue"));
                	/* DOGFOOT ktkang 빈값을 강제로 전체로 조회하던 부분 변경  20200702 */
                	if("".equals(value) || "''".equals(value)) {
//                		value = "";
                		whereClause = (String) valueObject.getString("whereClause");
                        value = whereClause;
                	} else if ("[All]".equals(value) || "'[All]'".equals(value)) {
                        whereClause = (String) valueObject.getString("whereClause");
                        value = whereClause;
                    } 
                }
                else if (valueList.size() > 1) {
                    value = "";
                    for (int x0 = 0; x0 < valueList.size(); x0++) {
                        value += this.getValue(valueType, valueList.getString(x0)) + ",";
                    }
                    value = value.substring(0, value.length() - 1);
                }
                else {
                    value = "";
                }
            }
            key = key.replaceAll("\\[", "\\\\[").replaceAll("\\]", "\\\\]").replaceAll("\\.","\\\\.");
            //정규식 단어 완전 일치 ^
            sqlMap = sqlMap.replaceAll("(" + key + ")\\s" , value + " ");
            sqlMap = sqlMap.replaceAll("(" + key + ")," , value + ",");
            sqlMap = sqlMap.replaceAll("(" + key + ")\\)" , value + ")");
            sqlMap = sqlMap.replaceAll("(" + key + ")\\|" , value + "|");
            sqlMap = sqlMap.replaceAll( key , value );
        }
        
        return sqlMap;
    }
    
    
    private String getValue(String type, String value) {
        String ret;
        
        if ("string".equalsIgnoreCase(type) || "DateTime".equalsIgnoreCase(type)) {
            ret = "'" + value + "'";
        }
        else if ("int".equalsIgnoreCase(type) || "integer".equalsIgnoreCase(type)
                    || "number".equalsIgnoreCase(type) || "numeric".equalsIgnoreCase(type)) {
            ret = value + "";
        }
        else {
            ret = "";
        }
        
        return ret;
    }
}
