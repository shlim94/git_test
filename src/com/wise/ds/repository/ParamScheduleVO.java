package com.wise.ds.repository;

import java.sql.Timestamp;

public class ParamScheduleVO {
	private int SCH_ID;
	private Timestamp  EXEC_ST_DT;
	private Timestamp  EXEC_ED_DT;
	private String EXEC_DATA;
	private String ERROR_MSG;
	private String STATUS_CD;
	
	public int getSCH_ID() {
        return SCH_ID;
    }

    public void setSCH_ID(int sCH_ID) {
        this.SCH_ID = sCH_ID;
    }
    
    public Timestamp getEXEC_ST_DT() {
		return EXEC_ST_DT;
	}

	public void setEXEC_ST_DT(Timestamp eXEC_ST_DT) {
		EXEC_ST_DT = eXEC_ST_DT;
	}

	public Timestamp getEXEC_ED_DT() {
		return EXEC_ED_DT;
	}

	public void setEXEC_ED_DT(Timestamp eXEC_ED_DT) {
		EXEC_ED_DT = eXEC_ED_DT;
	}

	public String getEXEC_DATA() {
        return EXEC_DATA;
    }

    public void setEXEC_DATA(String eXEC_DATA) {
        this.EXEC_DATA = eXEC_DATA;
    }

	public String getSTATUS_CD() {
		return STATUS_CD;
	}

	public void setSTATUS_CD(String sTATUS_CD) {
		STATUS_CD = sTATUS_CD;
	}

	public String getERROR_MSG() {
		return ERROR_MSG;
	}

	public void setERROR_MSG(String eRROR_MSG) {
		ERROR_MSG = eRROR_MSG;
	}
}
