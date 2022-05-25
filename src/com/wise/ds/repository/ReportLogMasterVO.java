package com.wise.ds.repository;

import java.sql.Timestamp;

public class ReportLogMasterVO {
	private String LOG_SEQ;
	private Timestamp EVENT_DT;
	private int REPORT_ID;
	private String REPORT_NM;
	private String REPORT_TYPE;
	private String USER_ID;
	private String USER_NM;
	private int USER_NO;
	private int GRP_ID;
	private String GRP_NM;
	private String ACCESS_IP;
	private Timestamp ST_DT;
	private Timestamp ED_DT;
	private String STATUS_CD;
	private String ACCESS_GUID;
	private String RUN_QUERY;
	private int DS_ID;
	private String RUN_TIME;
	
	private String PROG_TYPE;
	
	private String ITEMNM;
	private String ITEMID;

	public ReportLogMasterVO() {
		super();
		// TODO Auto-generated constructor stub
	}

	//REPORT-USE2
	public void setReportUseLog(String lOG_SEQ, int rEPORT_ID, String rEPORT_NM, String rEPORT_TYPE, String uSER_ID,
			String uSER_NM, int uSER_NO, int gRP_ID, String gRP_NM, String aCCESS_IP, Timestamp sT_DT, Timestamp eD_DT,
			String sTATUS_CD, String pROG_TYPE) {
		LOG_SEQ = lOG_SEQ;
		REPORT_ID = rEPORT_ID;
		REPORT_NM = rEPORT_NM;
		REPORT_TYPE = rEPORT_TYPE;
		USER_ID = uSER_ID;
		USER_NM = uSER_NM;
		USER_NO = uSER_NO;
		GRP_ID = gRP_ID;
		GRP_NM = gRP_NM;
		ACCESS_IP = aCCESS_IP;
		ST_DT = sT_DT;
		ED_DT = eD_DT;
		STATUS_CD = sTATUS_CD;
		PROG_TYPE = pROG_TYPE;
	}
	
	//REPORT-PRINT && REPROT-USE
	public void setReportUtilLog(Timestamp eVENT_DT, int rEPORT_ID, String rEPORT_NM, String rEPORT_TYPE, String uSER_ID,
			String uSER_NM, int uSER_NO, int gRP_ID, String gRP_NM, String aCCESS_IP, String aCCESS_GUID,
			String pROG_TYPE) {
		EVENT_DT = eVENT_DT;
		REPORT_ID = rEPORT_ID;
		REPORT_NM = rEPORT_NM;
		REPORT_TYPE = rEPORT_TYPE;
		USER_ID = uSER_ID;
		USER_NM = uSER_NM;
		USER_NO = uSER_NO;
		GRP_ID = gRP_ID;
		GRP_NM = gRP_NM;
		ACCESS_IP = aCCESS_IP;
		ACCESS_GUID = aCCESS_GUID;
		PROG_TYPE = pROG_TYPE;
	}
	//ITEM-EXPORT
	public void setReportUtilLog(Timestamp eVENT_DT, int rEPORT_ID, String rEPORT_NM, String rEPORT_TYPE, String uSER_ID,
			String uSER_NM, int uSER_NO, int gRP_ID, String gRP_NM, String aCCESS_IP, String aCCESS_GUID,
			String pROG_TYPE,String ItemID, String ItemNM) {
		EVENT_DT = eVENT_DT;
		REPORT_ID = rEPORT_ID;
		REPORT_NM = rEPORT_NM;
		REPORT_TYPE = rEPORT_TYPE;
		USER_ID = uSER_ID;
		USER_NM = uSER_NM;
		USER_NO = uSER_NO;
		GRP_ID = gRP_ID;
		GRP_NM = gRP_NM;
		ACCESS_IP = aCCESS_IP;
		ACCESS_GUID = aCCESS_GUID;
		PROG_TYPE = pROG_TYPE;
		ITEMID = ItemID;
		ITEMNM = ItemNM;
	}
	
	public void setReportUtilLog(int rEPORT_ID, String rEPORT_NM, String rEPORT_TYPE, String uSER_ID,
			String uSER_NM, int uSER_NO, int gRP_ID, String gRP_NM, String aCCESS_IP, String aCCESS_GUID,
			String pROG_TYPE) {
		REPORT_ID = rEPORT_ID;
		REPORT_NM = rEPORT_NM;
		REPORT_TYPE = rEPORT_TYPE;
		USER_ID = uSER_ID;
		USER_NM = uSER_NM;
		USER_NO = uSER_NO;
		GRP_ID = gRP_ID;
		GRP_NM = gRP_NM;
		ACCESS_IP = aCCESS_IP;
		ACCESS_GUID = aCCESS_GUID;
		PROG_TYPE = pROG_TYPE;
	}
	
	//REPORT-QUERY
	public void setReportQueryLog(Timestamp eVENT_DT, int rEPORT_ID, String rEPORT_NM, String rEPORT_TYPE, String uSER_ID, 
			String uSER_NM, int uSER_NO, int gRP_ID, String gRP_NM, String aCCESS_IP, String aCCESS_GUID, String rUN_QUERY, int dS_ID, String rUN_TIME, String pROG_TYPE) {
		EVENT_DT = eVENT_DT;
		REPORT_ID = rEPORT_ID;
		REPORT_NM = rEPORT_NM;
		REPORT_TYPE = rEPORT_TYPE;
		USER_ID = uSER_ID;
		USER_NM = uSER_NM;
		USER_NO = uSER_NO;
		GRP_ID = gRP_ID;
		GRP_NM = gRP_NM;
		ACCESS_IP = aCCESS_IP;
		ACCESS_GUID = aCCESS_GUID;
		RUN_QUERY = rUN_QUERY;
		DS_ID = dS_ID;
		RUN_TIME = rUN_TIME;
		PROG_TYPE = pROG_TYPE;
	}
	
	//REPORT-QUERY
	public void setReportQueryLog(int rEPORT_ID, String rEPORT_NM, String rEPORT_TYPE, String uSER_ID, 
			String uSER_NM, int uSER_NO, int gRP_ID, String gRP_NM, String aCCESS_IP, String aCCESS_GUID, String rUN_QUERY, int dS_ID, String rUN_TIME, String pROG_TYPE) {
		REPORT_ID = rEPORT_ID;
		REPORT_NM = rEPORT_NM;
		REPORT_TYPE = rEPORT_TYPE;
		USER_ID = uSER_ID;
		USER_NM = uSER_NM;
		USER_NO = uSER_NO;
		GRP_ID = gRP_ID;
		GRP_NM = gRP_NM;
		ACCESS_IP = aCCESS_IP;
		ACCESS_GUID = aCCESS_GUID;
		RUN_QUERY = rUN_QUERY;
		DS_ID = dS_ID;
		RUN_TIME = rUN_TIME;
		PROG_TYPE = pROG_TYPE;
	}

	public String getLOG_SEQ() {
		return LOG_SEQ;
	}
	public void setLOG_SEQ(String lOG_SEQ) {
		LOG_SEQ = lOG_SEQ;
	}
	public Timestamp getEVENT_DT() {
		return EVENT_DT;
	}
	public void setEVENT_DT(Timestamp eVENT_DT) {
		EVENT_DT = eVENT_DT;
	}
	public int getREPORT_ID() {
		return REPORT_ID;
	}
	public void setREPORT_ID(int rEPORT_ID) {
		REPORT_ID = rEPORT_ID;
	}
	public String getREPORT_NM() {
		return REPORT_NM;
	}
	public void setREPORT_NM(String rEPORT_NM) {
		REPORT_NM = rEPORT_NM;
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
	public Timestamp getST_DT() {
		return ST_DT;
	}
	public void setST_DT(Timestamp sT_DT) {
		ST_DT = sT_DT;
	}
	public Timestamp getED_DT() {
		return ED_DT;
	}
	public void setED_DT(Timestamp eD_DT) {
		ED_DT = eD_DT;
	}
	public String getSTATUS_CD() {
		return STATUS_CD;
	}
	public void setSTATUS_CD(String sTATUS_CD) {
		STATUS_CD = sTATUS_CD;
	}
	public String getACCESS_GUID() {
		return ACCESS_GUID;
	}
	public void setACCESS_GUID(String aCCESS_GUID) {
		ACCESS_GUID = aCCESS_GUID;
	}
	public String getPROG_TYPE() {
		return PROG_TYPE;
	}
	public void setPROG_TYPE(String pROG_TYPE) {
		PROG_TYPE = pROG_TYPE;
	}
	public String getRUN_QUERY() {
		return RUN_QUERY;
	}
	public void setRUN_QUERY(String rUN_QUERY) {
		RUN_QUERY = rUN_QUERY;
	}
	public int getDS_ID() {
		return DS_ID;
	}
	public void setDS_ID(int dS_ID) {
		DS_ID = dS_ID;
	}
	public String getRUN_TIME() {
		return RUN_TIME;
	}
	public void setRUN_TIME(String rUN_TIME) {
		RUN_TIME = rUN_TIME;
	}
	public String getITEMNM() {
		return ITEMNM;
	}
	public void setITEMNM(String iTEMNM) {
		ITEMNM = iTEMNM;
	}
	public String getITEMID() {
		return ITEMID;
	}
	public void setITEMID(String iTEMID) {
		ITEMID = iTEMID;
	}

	@Override
	public String toString() {
		return "ReportLogMasterVO [LOG_SEQ=" + LOG_SEQ + ", EVENT_DT=" + EVENT_DT + ", REPORT_ID=" + REPORT_ID
				+ ", REPORT_NM=" + REPORT_NM + ", REPORT_TYPE=" + REPORT_TYPE + ", USER_ID=" + USER_ID + ", USER_NM="
				+ USER_NM + ", USER_NO=" + USER_NO + ", GRP_ID=" + GRP_ID + ", GRP_NM=" + GRP_NM + ", ACCESS_IP="
				+ ACCESS_IP + ", ST_DT=" + ST_DT + ", ED_DT=" + ED_DT + ", STATUS_CD=" + STATUS_CD + ", ACCESS_GUID="
				+ ACCESS_GUID + ", RUN_QUERY=" + RUN_QUERY + ", DS_ID=" + DS_ID + ", RUN_TIME=" + RUN_TIME
				+ ", PROG_TYPE=" + PROG_TYPE + "]";
	}
	
}
