package com.wise.authn;

import java.sql.Timestamp;

public class LoginLogVO {
	private Timestamp EVENT_DT;
	private String LOG_TYPE;
	private String USER_ID;
	private String USER_NM;
	private int USER_NO;
	private int GRP_ID;
	private String GRP_NM;
	private String ACCESS_IP;
	private String ACCESS_GUID;
	private int MOD_USER_NO;
	private Timestamp MOD_DT;
	private String PROG_TYPE;
	
	public LoginLogVO(Timestamp eVENT_DT, String lOG_TYPE, String uSER_ID, String uSER_NM, int uSER_NO, int gRP_ID,
			String gRP_NM, String aCCESS_IP, String aCCESS_GUID, int mOD_USER_NO, Timestamp mOD_DT, String pROG_TYPE) {
		EVENT_DT = eVENT_DT;
		LOG_TYPE = lOG_TYPE;
		USER_ID = uSER_ID;
		USER_NM = uSER_NM;
		USER_NO = uSER_NO;
		GRP_ID = gRP_ID;
		GRP_NM = gRP_NM;
		ACCESS_IP = aCCESS_IP;
		ACCESS_GUID = aCCESS_GUID;
		MOD_USER_NO = mOD_USER_NO;
		MOD_DT = mOD_DT;
		PROG_TYPE = pROG_TYPE;
	}
	
	public Timestamp getEVENT_DT() {
		return EVENT_DT;
	}
	public void setEVENT_DT(Timestamp eVENT_DT) {
		EVENT_DT = eVENT_DT;
	}
	public String getLOG_TYPE() {
		return LOG_TYPE;
	}
	public void setLOG_TYPE(String lOG_TYPE) {
		LOG_TYPE = lOG_TYPE;
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
	public int getUSER_NO() {
		return USER_NO;
	}
	public void setUSER_NO(int uSER_NO) {
		USER_NO = uSER_NO;
	}
	public int getGRP_ID() {
		return GRP_ID;
	}
	public void setGRP_ID(int gRP_ID) {
		GRP_ID = gRP_ID;
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
	public String getACCESS_GUID() {
		return ACCESS_GUID;
	}
	public void setACCESS_GUID(String aCCESS_GUID) {
		ACCESS_GUID = aCCESS_GUID;
	}
	public int getMOD_USER_NO() {
		return MOD_USER_NO;
	}
	public void setMOD_USER_NO(int mOD_USER_NO) {
		MOD_USER_NO = mOD_USER_NO;
	}
	public Timestamp getMOD_DT() {
		return MOD_DT;
	}
	public void setMOD_DT(Timestamp mOD_DT) {
		MOD_DT = mOD_DT;
	}
	public String getPROG_TYPE() {
		return PROG_TYPE;
	}
	public void setPROG_TYPE(String pROG_TYPE) {
		PROG_TYPE = pROG_TYPE;
	}
}
