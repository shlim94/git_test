package com.wise.authn;

import java.sql.Timestamp;

public class UserSessionVO {
	private String USER_ID;
	private int USER_NO;
	private String USER_SESSION_KEY;
	private String LOG_TYPE;
	private String ACCESS_IP;
	private Timestamp LAST_MSG_DT;
	private int MOD_USER_NO;
	private String MOD_USER_ID;
	private Timestamp MOD_DT;
	private int inactiveDays;
	
	public String getUSER_ID() {
		return USER_ID;
	}
	public void setUSER_ID(String uSER_ID) {
		USER_ID = uSER_ID;
	}
	public int getUSER_NO() {
		return USER_NO;
	}
	public void setUSER_NO(int uSER_NO) {
		USER_NO = uSER_NO;
	}
	public String getUSER_SESSION_KEY() {
		return USER_SESSION_KEY;
	}
	public void setUSER_SESSION_KEY(String uSER_SESSION_KEY) {
		USER_SESSION_KEY = uSER_SESSION_KEY;
	}
	public String getLOG_TYPE() {
		return LOG_TYPE;
	}
	public void setLOG_TYPE(String lOG_TYPE) {
		LOG_TYPE = lOG_TYPE;
	}
	public String getACCESS_IP() {
		return ACCESS_IP;
	}
	public void setACCESS_IP(String aCCESS_IP) {
		ACCESS_IP = aCCESS_IP;
	}
	public Timestamp getLAST_MSG_DT() {
		return LAST_MSG_DT;
	}
	public void setLAST_MSG_DT(Timestamp lAST_MSG_DT) {
		LAST_MSG_DT = lAST_MSG_DT;
	}
	public int getMOD_USER_NO() {
		return MOD_USER_NO;
	}
	public void setMOD_USER_NO(int mOD_USER_NO) {
		MOD_USER_NO = mOD_USER_NO;
	}
	public String getMOD_USER_ID() {
		return MOD_USER_ID;
	}
	public void setMOD_USER_ID(String mOD_USER_ID) {
		MOD_USER_ID = mOD_USER_ID;
	}
	public Timestamp getMOD_DT() {
		return MOD_DT;
	}
	public void setMOD_DT(Timestamp mOD_DT) {
		MOD_DT = mOD_DT;
	}
	public int getInactiveDays() {
		return inactiveDays;
	}
	public void setInactiveDays(int inactiveDays) {
		this.inactiveDays = inactiveDays;
	}
}
