package com.wise.ds.repository;

import java.io.UnsupportedEncodingException;
import org.bouncycastle.util.encoders.Base64;

import com.wise.context.config.Configurator;

public class QueryLogVO {
	private String EVENT_DT;
	private String EVENT_TIME;
	private String REPORT_TYPE;
	private String USER_ID;
	private String USER_NM;
	private String GRP_NM;
	private String ACCESS_IP;
	private String DS_NM;
	private String DB_NM;
	private String DB_IP;
	private String DBMS_TYPE;
	private String RUN_TIME;
	private String RUN_QUERY_BASE64;
	
	public String getEVENT_DT() {
		return EVENT_DT;
	}
	public void setEVENT_DT(String eVENT_DT) {
		EVENT_DT = eVENT_DT;
	}
	public String getEVENT_TIME() {
		return EVENT_TIME;
	}
	public void setEVENT_TIME(String eVENT_TIME) {
		EVENT_TIME = eVENT_TIME;
	}
	public String getREPORT_TYPE() {
		return REPORT_TYPE;
	}
	public void setREPORT_TYPE(String rEPORT_TYPE) {
		REPORT_TYPE = rEPORT_TYPE;
	}
	public String getUSER_ID() {
		return USER_ID;
	}
	public void setUSER_ID(String uSER_ID) {
		USER_ID = uSER_ID;
	}
	public String getUSER_NM() {
		return USER_NM;
	}
	public void setUSER_NM(String uSER_NM) {
		USER_NM = uSER_NM;
	}
	public String getGRP_NM() {
		return GRP_NM;
	}
	public void setGRP_NM(String gRP_NM) {
		GRP_NM = gRP_NM;
	}
	public String getACCESS_IP() {
		return ACCESS_IP;
	}
	public void setACCESS_IP(String aCCESS_IP) {
		ACCESS_IP = aCCESS_IP;
	}
	public String getDS_NM() {
		return DS_NM;
	}
	public void setDS_NM(String dS_NM) {
		DS_NM = dS_NM;
	}
	public String getDB_NM() {
		return DB_NM;
	}
	public void setDB_NM(String dB_NM) {
		DB_NM = dB_NM;
	}
	public String getDB_IP() {
		return DB_IP;
	}
	public void setDB_IP(String dB_IP) {
		DB_IP = dB_IP;
	}
	public String getDBMS_TYPE() {
		return DBMS_TYPE;
	}
	public void setDBMS_TYPE(String dBMS_TYPE) {
		DBMS_TYPE = dBMS_TYPE;
	}
	public String getRUN_TIME() {
		return RUN_TIME;
	}
	public void setRUN_TIME(String rUN_TIME) {
		RUN_TIME = rUN_TIME;
	}
	public String getRUN_QUERY_BASE64() {
		return RUN_QUERY_BASE64;
	}
	public void setRUN_QUERY_BASE64(String rUN_QUERY_BASE64) {
		RUN_QUERY_BASE64 = rUN_QUERY_BASE64;
	}
	public String getSqlQueryString() throws UnsupportedEncodingException {
		String result = "";
		String encodedQuery = this.getRUN_QUERY_BASE64();
		if (encodedQuery.length() > 0) {
			String encoding = Configurator.getInstance().getConfig("encoding");
	        result = new String(Base64.decode(encodedQuery.getBytes()), encoding);
		}
		return result;
	}
}
