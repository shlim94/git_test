package com.wise.ds.repository;

public class DSViewVO {
	private String DS_ID;
	private String DS_NM;
	private String DB_NM;
	private String IP;
	private String USER_ID;
	private String PASSWD;
	private String PORT;
	private String OWNER_NM;
	private String DBMS_TYPE;
	private String DS_DESC;
	private String DS_CONNSTR;
	private String DS_VIEW_ID;
	private String DS_VIEW_NM;
	private String DS_VIEW_DESC;
	public String getDS_ID() {
		return DS_ID;
	}
	public void setDS_ID(String dS_ID) {
		DS_ID = dS_ID;
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
	public String getIP() {
		return IP;
	}
	public void setIP(String iP) {
		IP = iP;
	}
	public String getUSER_ID() {
		return USER_ID;
	}
	public void setUSER_ID(String uSER_ID) {
		USER_ID = uSER_ID;
	}
	public String getPASSWD() {
		return PASSWD;
	}
	public void setPASSWD(String pASSWD) {
		PASSWD = pASSWD;
	}
	public String getPORT() {
		return PORT;
	}
	public void setPORT(String pORT) {
		PORT = pORT;
	}
	public String getOWNER_NM() {
		return OWNER_NM;
	}
	public void setOWNER_NM(String oWNER_NM) {
		OWNER_NM = oWNER_NM;
	}
	public String getDBMS_TYPE() {
		return DBMS_TYPE;
	}
	public void setDBMS_TYPE(String dBMS_TYPE) {
		DBMS_TYPE = dBMS_TYPE;
	}
	public String getDS_DESC() {
		return DS_DESC;
	}
	public void setDS_DESC(String dS_DESC) {
		DS_DESC = dS_DESC;
	}
	public String getDS_CONNSTR() {
		return DS_CONNSTR;
	}
	public void setDS_CONNSTR(String dS_CONNSTR) {
		DS_CONNSTR = dS_CONNSTR;
	}
	public String getDS_VIEW_ID() {
		return DS_VIEW_ID;
	}
	public void setDS_VIEW_ID(String dS_VIEW_ID) {
		DS_VIEW_ID = dS_VIEW_ID;
	}
	public String getDS_VIEW_NM() {
		return DS_VIEW_NM;
	}
	public void setDS_VIEW_NM(String dS_VIEW_NM) {
		DS_VIEW_NM = dS_VIEW_NM;
	}
	public String getDS_VIEW_DESC() {
		return DS_VIEW_DESC;
	}
	public void setDS_VIEW_DESC(String dS_VIEW_DESC) {
		DS_VIEW_DESC = dS_VIEW_DESC;
	}
	@Override
	public String toString() {
		return "DSViewVO [DS_ID=" + DS_ID + ", DS_NM=" + DS_NM + ", DB_NM=" + DB_NM + ", IP=" + IP + ", USER_ID="
				+ USER_ID + ", PASSWD=" + PASSWD + ", PORT=" + PORT + ", OWNER_NM=" + OWNER_NM + ", DBMS_TYPE="
				+ DBMS_TYPE + ", DS_DESC=" + DS_DESC + ", DS_CONNSTR=" + DS_CONNSTR + ", DS_VIEW_ID=" + DS_VIEW_ID
				+ ", DS_VIEW_NM=" + DS_VIEW_NM + ", DS_VIEW_DESC=" + DS_VIEW_DESC + "]";
	}
}
