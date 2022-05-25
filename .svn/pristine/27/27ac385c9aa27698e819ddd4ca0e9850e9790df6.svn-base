package com.wise.ds.query.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.wise.authn.User;
import com.wise.context.config.Configurator;
import com.wise.ds.repository.ReportMasterVO;

@Service("sqlStorage")
public class SqlStorage {
    private static final Logger logger = LoggerFactory.getLogger(SqlStorage.class);
    
    private Object lock = new Object();
    private Map<String, String> storage = new HashMap<String, String>();
    private Map<String, String> logstore = new HashMap<String, String>();
    
    public String diagnostic() {
        String diagnostic = "";
        Object[] keyset = this.storage.keySet().toArray();
        
        for (int x0 = 0; x0 < keyset.length; x0++) {
            diagnostic += "sql id: " + keyset[x0] + ", compressed size: " + new String(this.storage.get(keyset[x0])).length() + "bytes.<br/>";
            diagnostic += "SQL> " + this.getSql((String) keyset[x0]) + "<br/>";
            diagnostic += "-----------------------------------------------------------------------------------------------------------------<br/>";            
        }
        
        return diagnostic;
    }
    
    public void clear() {
        this.storage.clear();
    }
    
    public void clearSqlById(String sqlId){
    	this.storage.remove(sqlId);
    }

    public void store(JSONObject reportMasterInfo) {
    	String sql = "";
    	String sqlId;
    	byte[] gzipSql;
    	JSONObject dataSetObj;
    	if(reportMasterInfo.getJSONObject("datasetJson").has("DATASET_ELEMENT")) {
    		JSONArray dataSetElements = reportMasterInfo.getJSONObject("datasetJson").getJSONArray("DATASET_ELEMENT");
    		for (int x0 = 0; x0 < dataSetElements.size(); x0++) {
    			dataSetObj = (JSONObject) dataSetElements.get(x0);

    			sqlId = dataSetObj.getString("wise_sql_id");

    			//if (!this.storage.containsKey(sqlId)) {
    				synchronized (this.lock) {
    					if(!dataSetObj.has("SQL_QUERY")) {
    						sql = dataSetObj.getString("DATASET_QUERY");
    						logger.debug("sql size : " + sql.length());
    						logger.debug(sql);
    						gzipSql = this.compress(sql);
    						logger.debug("gzip sql size : " + gzipSql.length);
    					}else {
    						String encoding = Configurator.getInstance().getConfig("encoding");
    						sql = new String(dataSetObj.getString("SQL_QUERY"));
    					}

    					this.storage.put(sqlId, sql);
    				}
    			//}else {
    			//	sql = this.storage.get(sqlId);
    			//}
    			dataSetObj.remove("SQL_QUERY");
    			dataSetObj.put("SQL_QUERY", sql);
    			dataSetObj.remove("DATASET_QUERY");
    		}
    	} else {
    		dataSetObj = reportMasterInfo.getJSONObject("datasetJson");
    		
    		sqlId = dataSetObj.getString("wise_sql_id");
    		sql = dataSetObj.getString("SQL_QUERY");
    		gzipSql = this.compress(sql);
    		
    		this.storage.put(sqlId, sql);
    	}
    }

    public String getSql(String sqlId) {
    	 // byte[] gzipSql = this.storage.get(sqlId);
        
        //   if (gzipSql == null) {
         //      throw new NotFoundSqlException();
         //  }
           
          // return this.decompress(gzipSql);
       	return this.storage.get(sqlId);
    }

    private byte[] compress(String str) {
        if (str == null || str.length() == 0) {
            return str.getBytes();
        }
        ByteArrayOutputStream obj = new ByteArrayOutputStream();
        try {
        	GZIPOutputStream gzip = new GZIPOutputStream(obj);
            gzip.write(str.getBytes("UTF-8"));
            gzip.close();
        } catch (IOException e) {
        	e.printStackTrace();
        }
        return obj.toByteArray();
    }

    private String decompress(byte[] bytes) {
    	String outStr = "";
    	try {
    		GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(bytes));
            BufferedReader bf = new BufferedReader(new InputStreamReader(gis, "UTF-8"));
            String line;
            while ((line = bf.readLine()) != null) {
                outStr += line;
            }
    	} catch (IOException e) {
        	e.printStackTrace();
        }
        return outStr;
    }
}
