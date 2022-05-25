package com.wise.ds.repository;

import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wise.ds.repository.service.impl.DataSetServiceImpl;

public class DashReportMasterVO {
	final static private Logger logger = LoggerFactory.getLogger(DashReportMasterVO.class);
	
	private String PROG_TYPE;
	private String EVENT_DT;
	private String EVENT_DATE;
	private String EVENT_TIME;
	private int REPORT_ID;
	private String REPORT_NM;
	public String getEVENT_DATE() {
		return EVENT_DATE;
	}
	public void setEVENT_DATE(String eVENT_DATE) {
		EVENT_DATE = eVENT_DATE;
	}
	public String getEVENT_TIME() {
		try {
		    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
		    Date StartParsedDate = dateFormat.parse(ST_DT);
		    Date EndParsedDate = dateFormat.parse(ED_DT);
		    
		    long diff;
		    if(EndParsedDate.getTime() > StartParsedDate.getTime())
		    	diff = EndParsedDate.getTime() - StartParsedDate.getTime();
		    else{
		    	diff = StartParsedDate.getTime() - EndParsedDate.getTime();
		    }
		    long hour = TimeUnit.MILLISECONDS.toHours(diff);
		    long min =  TimeUnit.MILLISECONDS.toMinutes(diff)  - TimeUnit.HOURS.toMinutes(TimeUnit.MILLISECONDS.toHours(diff));
		    long sec =  TimeUnit.MILLISECONDS.toSeconds(diff) - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(diff)  - TimeUnit.HOURS.toMinutes(TimeUnit.MILLISECONDS.toHours(diff)));
		    EVENT_TIME = String.format("%02d:%02d:%02d ",hour,min,sec);
		} catch(ParseException e) {
		    logger.debug("DashReportMasterVO getEVENT_TIME 날짜 포멧 에러");
		}
		return EVENT_TIME;
	}
	public void setEVENT_TIME(String eVENT_TIME) {
		EVENT_TIME = eVENT_TIME;
	}
	private int FLD_ID;
	private String LOG_SEQ;
	private String ST_DT;
	private String ED_DT;
	private String STATUS_CD;

	private String FLD_TYPE;
	private int REPORT_ORDINAL;
	private String REPORT_TYPE;
	private String AUTH_VIEW;
	private String USER_ID;
	private String USER_NM;
	private String USER_NO;
	private String GRP_ID;
	private String GRP_NM;
	private String ACCESS_IP;
	
	
	public String getLOG_SEQ() {
		return LOG_SEQ;
	}
	public void setLOG_SEQ(String lOG_SEQ) {
		LOG_SEQ = lOG_SEQ;
	}
	public String getST_DT() {
		return ST_DT;
	}
	public void setST_DT(String sT_DT) {
		ST_DT = sT_DT;
	}
	public String getED_DT() {
		return ED_DT;
	}
	public void setED_DT(String eD_DT) {
		ED_DT = eD_DT;
	}
	public String getSTATUS_CD() {
		return STATUS_CD;
	}
	public void setSTATUS_CD(String sTATUS_CD) {
		STATUS_CD = sTATUS_CD;
	}
	
	public String getPROG_TYPE() {
		return PROG_TYPE;
	}
	public void setPROG_TYPE(String pROG_TYPE) {
		PROG_TYPE = pROG_TYPE;
	}
	public String getEVENT_DT() {
		return EVENT_DT;
	}
	public void setEVENT_DT(String eVENT_DT) {
		EVENT_DT = eVENT_DT;
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
	public String getUSER_NO() {
		return USER_NO;
	}
	public void setUSER_NO(String uSER_NO) {
		USER_NO = uSER_NO;
	}
	public String getGRP_ID() {
		return GRP_ID;
	}
	public void setGRP_ID(String gRP_ID) {
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
	private String ACCESS_GUID;
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
	public int getFLD_ID() {
		return FLD_ID;
	}
	public void setFLD_ID(int fLD_ID) {
		FLD_ID = fLD_ID;
	}
	public String getFLD_TYPE() {
		return FLD_TYPE;
	}
	public void setFLD_TYPE(String fLD_TYPE) {
		FLD_TYPE = fLD_TYPE;
	}
	public int getREPORT_ORDINAL() {
		return REPORT_ORDINAL;
	}
	public void setREPORT_ORDINAL(int rEPORT_ORDINAL) {
		REPORT_ORDINAL = rEPORT_ORDINAL;
	}
	public String getREPORT_TYPE() {
		return REPORT_TYPE;
	}
	public void setREPORT_TYPE(String rEPORT_TYPE) {
		REPORT_TYPE = rEPORT_TYPE;
	}
	public String getAUTH_VIEW() {
		return AUTH_VIEW;
	}
	public void setAUTH_VIEW(String aUTH_VIEW) {
		AUTH_VIEW = aUTH_VIEW;
	}
}
