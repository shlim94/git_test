package com.wise.ds.repository;

public class SameTimeConVO {
	private String USER_ID;
	private String LOG_TYPE;
	private String ACCESS_IP;
	private String LAST_MSG_DT;
	
	public String getUSER_ID() {
		return USER_ID;
	}
	public void setUSER_ID(String uSER_ID) {
		this.USER_ID = uSER_ID;
	}
	
	public String getLOG_TYPE() {
		return LOG_TYPE;
	}
	public void setLOG_TYPE(String lOG_TYPE) {
		this.LOG_TYPE = lOG_TYPE;
	}
	
	public String getACCESS_IP() {
		return ACCESS_IP;
	}
	public void setACCESS_IP(String aCCESS_IP) {
		this.ACCESS_IP = aCCESS_IP;
	}
	
	public String getLAST_MSG_DT() {
		return LAST_MSG_DT;
	}
	public void setLAST_MSG_DT(String lAST_MSG_DT) {
		this.LAST_MSG_DT = lAST_MSG_DT;
	}
}
