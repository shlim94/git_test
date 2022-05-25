package com.wise.ds.query.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.wise.common.util.CoreUtils;
import com.wise.ds.sql.CubeTableColumn;

import net.sf.json.JSONObject;

@Service("sqlConvertor")
public class SqlConvertor {
    
    private Map<String,String> targetWords = new HashMap<String,String>();
    
    public SqlConvertor() {
        
        this.targetWords.put("&#39;", "'");
        this.targetWords.put("&#34;", "\"");
        this.targetWords.put("&quot;", "\"");
        this.targetWords.put("&#60;", "<");
        this.targetWords.put("&lt;", "<");
        this.targetWords.put("&#61;", "=");
        this.targetWords.put("&#62;", ">");
        this.targetWords.put("&gt;", ">");
        
    }
    
    public String insertSubquery(String sql, String subquery, JSONObject subtarget) {
        String converted = sql;

        if(converted.contains("WHERE")) {
        	if(converted.contains("GROUP BY")) {
        		converted.replace("GROUP BY", "AND (" + subquery + ") \r\n GROUP BY");
        	}
        }else {
        	if(converted.contains("GROUP BY")) {
        		String subsql = "WHERE " + subtarget.getString("targetUniNm") + " IN (" + subquery + " \r\n GROUP ";
        		String [] splitedQuery = converted.split("GROUP");
        		converted = splitedQuery[0] + subsql + splitedQuery[1];
        	}
        }
        
        return converted;
    }
    
    public String convert(String sql) {
        String converted = sql;
        
        Object[] words = this.targetWords.keySet().toArray();
        
        for (Object word : words) {
            converted = converted.replaceAll((String) word, this.targetWords.get(word));
        }
        
        return converted;
    }
    
    public String convertColumnToExpression(String sql, List<CubeTableColumn> columnInformations) {

		for (CubeTableColumn column : columnInformations) {
			if (!"".equals(CoreUtils.ifNull(column.getExpression())) && sql.indexOf(column.getPhysicalColumnName()) > -1) {
				sql = sql.replaceAll(column.getPhysicalColumnName(), column.getExpression());
			}
		}

		return sql;
	}
    
    /* DOGFOOT ktkang 테스트 쿼리보기용 쿼리 수정  20200629 */
    public String convertTopN(String sql, String dbType, int rowNum) {
    	/* DOGFOOT ktkang 데이터 집합 만들기 때 1행만 가져오는 부분  20200114 */
//    	String converted= sql.toUpperCase();
//    	if(!converted.contains("JOIN")) {
			/* DOGFOOT ktkang mssql 에서 with 절 에러 수정  20200717 */
    		if(dbType.equals("MS-SQL") && !sql.toLowerCase().contains("with")) {
    			sql = "SELECT TOP " + rowNum + " * FROM (\n" + sql + "\n) AS A";
    		} else if(dbType.equals("MS-SQL") && sql.toLowerCase().contains("with")) {
    			return sql;
    		} else if(dbType.contains("DB2")){
    			sql = "\n" + sql + "\n" + " FETCH FIRST " + rowNum + " ROW ONLY";
    		} else if(dbType.contains("IMPALA") || dbType.equals("MYSQL") || dbType.equals("MARIA") || dbType.equals("NETEZZA")){
    			sql = "\n" + sql + "\n" + " LIMIT " + rowNum;
    		} else {
    			sql = "SELECT * FROM (\n" + sql + "\n) WHERE ROWNUM <= " + rowNum;
    		}
//    	} else {
//    		converted = sql;
//    	}

    	return sql;
    }
}
