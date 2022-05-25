/* DOGFOOT ktkang KERIS 보고서 백업 기능  20200205 */
package com.wise.ds.repository;

import java.util.List;

public class ReportBackup {
private String P_PARAM;
	
	//UP_USER_MSTR_ACT용
	private String REPORT_ID;
	private String REPORT_NM;
	private String FLD_ID;
	private String FLD_TYPE;
	private String REPORT_ORDINAL;
	private String REPORT_TYPE;
	private String REPORT_TAG;
	private String REPORT_DESC;
	private String REPORT_LAYOUT;
	private String GRID_INFO;
	private String DATASRC_ID;
	private String DATASRC_TYPE;
	private String DATASET_TYPE;
	private String REPORT_XML;
	private String CHART_XML;
	private String LAYOUT_XML;
	private String DATASET_XML;
	private String PARAM_XML;
	private String DATASET_QUERY;
	private String REG_USER_NO;
	private String REG_DT;
	private String DEL_YN;
	private String PROMPT_YN;
	private String REPORT_SUB_TITLE;
	private String MOD_USER_NO;
	private String MOD_DT;
	private String PRIVACY_YN;
	/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
	private String LAYOUT_CONFIG;
	
	//UP_USER_MSTR 용
	private String USER_NO;
	
	//프로시저 리턴값
	private List p_result;
	private List p_error;
	private String out_RtnVal;

	public void setResultList(List list) {
		this.p_result = list;
	}

	public void setP_error(List p_error) {
		this.p_error = p_error;
	}
	
	public String getOut_RtnVal() {
		return out_RtnVal;
	}

	public void setOut_RtnVal(String out_RtnVal) {
		this.out_RtnVal = out_RtnVal;
	}

	public String getP_PARAM() {
		return P_PARAM;
	}

	public void setP_PARAM(String p_PARAM) {
		P_PARAM = p_PARAM;
	}

	public String getREPORT_ID() {
		return REPORT_ID;
	}

	public void setREPORT_ID(String rEPORT_ID) {
		REPORT_ID = rEPORT_ID;
	}
	
	public String getREPORT_NM() {
		return REPORT_NM;
	}

	public void setREPORT_NM(String rEPORT_NM) {
		if(rEPORT_NM == null) {
			REPORT_NM = null;
		} else {
			REPORT_NM = "'" + rEPORT_NM + "'";
		}
	}

	public String getREPORT_ORDINAL() {
		return REPORT_ORDINAL;
	}

	public void setREPORT_ORDINAL(String rEPORT_ORDINAL) {
		REPORT_ORDINAL = rEPORT_ORDINAL;
	}

	public String getREPORT_TAG() {
		return REPORT_TAG;
	}

	public void setREPORT_TAG(String rEPORT_TAG) {
		if(rEPORT_TAG == null) {
			REPORT_TAG = null;
		} else {
			REPORT_TAG = "'" + rEPORT_TAG + "'";
		}
	}

	public String getREPORT_DESC() {
		return REPORT_DESC;
	}

	public void setREPORT_DESC(String rEPORT_DESC) {
		if(rEPORT_DESC == null) {
			REPORT_DESC = null;
		} else {
			REPORT_DESC = "'" + rEPORT_DESC + "'";
		}
	}

	public String getREPORT_LAYOUT() {
		return REPORT_LAYOUT;
	}

	public void setREPORT_LAYOUT(String rEPORT_LAYOUT) {
		if(rEPORT_LAYOUT == null) {
			REPORT_LAYOUT = null;
		} else {
			REPORT_LAYOUT = "'" + rEPORT_LAYOUT + "'";
		}
	}

	public String getGRID_INFO() {
		return GRID_INFO;
	}

	public void setGRID_INFO(String gRID_INFO) {
		if(gRID_INFO == null) {
			GRID_INFO = null;
		} else {
			GRID_INFO = "'" + gRID_INFO + "'";
		}
	}

	public String getDATASRC_ID() {
		return DATASRC_ID;
	}

	public void setDATASRC_ID(String dATASRC_ID) {
		DATASRC_ID = dATASRC_ID;
	}

	public String getDATASRC_TYPE() {
		return DATASRC_TYPE;
	}

	public void setDATASRC_TYPE(String dATASRC_TYPE) {
		if(dATASRC_TYPE == null) {
			DATASRC_TYPE = null;
		} else {
			DATASRC_TYPE = "'" + dATASRC_TYPE + "'";
		}
	}

	public String getDATASET_TYPE() {
		return DATASET_TYPE;
	}

	public void setDATASET_TYPE(String dATASET_TYPE) {
		if(dATASET_TYPE == null) {
			DATASET_TYPE = null;
		} else {
			DATASET_TYPE = "'" + dATASET_TYPE + "'";
		}
	}

	public String getREPORT_XML() {
		return REPORT_XML;
	}

	public void setREPORT_XML(String rEPORT_XML) {
		if(rEPORT_XML == null) {
			REPORT_XML = null;
		} else {
			REPORT_XML = "'" + rEPORT_XML + "'";
		}
		REPORT_XML = rEPORT_XML;
	}

	public String getCHART_XML() {
		return CHART_XML;
	}

	public void setCHART_XML(String cHART_XML) {
		if(cHART_XML == null) {
			CHART_XML = null;
		} else {
			CHART_XML = "'" + cHART_XML + "'";
		}
	}

	public String getLAYOUT_XML() {
		return LAYOUT_XML;
	}

	public void setLAYOUT_XML(String lAYOUT_XML) {
		if(lAYOUT_XML == null) {
			LAYOUT_XML = null;
		} else {
			LAYOUT_XML = "'" + lAYOUT_XML + "'";
		}
	}

	public String getDATASET_XML() {
		return DATASET_XML;
	}

	public void setDATASET_XML(String dATASET_XML) {
		if(dATASET_XML == null) {
			DATASET_XML = null;
		} else {
			DATASET_XML = "'" + dATASET_XML + "'";
		}
	}

	public String getPARAM_XML() {
		return PARAM_XML;
	}

	public void setPARAM_XML(String pARAM_XML) {
		if(pARAM_XML == null) {
			PARAM_XML = null;
		} else {
			PARAM_XML = "'" + pARAM_XML + "'";
		}
	}

	public String getDATASET_QUERY() {
		return DATASET_QUERY;
	}

	public void setDATASET_QUERY(String dATASET_QUERY) {
		if(dATASET_QUERY == null) {
			DATASET_QUERY = null;
		} else {
			DATASET_QUERY = "'" + dATASET_QUERY + "'";
		}
	}

	public String getREG_USER_NO() {
		return REG_USER_NO;
	}

	public void setREG_USER_NO(String rEG_USER_NO) {
		REG_USER_NO = rEG_USER_NO;
	}
	
	public String getREG_DT() {
		return REG_DT;
	}

	public void setREG_DT(String rEG_DT) {
		if(rEG_DT == null) {
			REG_DT = null;
		} else {
			REG_DT = "'" + rEG_DT + "'";
		}
	}

	public String getDEL_YN() {
		return DEL_YN;
	}

	public void setDEL_YN(String dEL_YN) {
		if(dEL_YN == null) {
			DEL_YN = null;
		} else {
			DEL_YN = "'" + dEL_YN + "'";
		}
	}

	public String getPROMPT_YN() {
		return PROMPT_YN;
	}

	public void setPROMPT_YN(String pROMPT_YN) {
		if(pROMPT_YN == null) {
			PROMPT_YN = null;
		} else {
			PROMPT_YN = "'" + pROMPT_YN + "'";
		}
	}

	public String getREPORT_SUB_TITLE() {
		return REPORT_SUB_TITLE;
	}

	public void setREPORT_SUB_TITLE(String rEPORT_SUB_TITLE) {
		if(rEPORT_SUB_TITLE == null) {
			REPORT_SUB_TITLE = null;
		} else {
			REPORT_SUB_TITLE = "'" + rEPORT_SUB_TITLE + "'";
		}
	}

	public String getMOD_USER_NO() {
		return MOD_USER_NO;
	}

	public void setMOD_USER_NO(String mOD_USER_NO) {
		MOD_USER_NO = mOD_USER_NO;
	}

	public String getMOD_DT() {
		return MOD_DT;
	}

	public void setMOD_DT(String mOD_DT) {
		if(mOD_DT == null) {
			MOD_DT = null;
		} else {
			MOD_DT = "'" + mOD_DT + "'";
		}
	}
	
	public String getPRIVACY_YN() {
		return PRIVACY_YN;
	}

	public void setPRIVACY_YN(String pRIVACY_YN) {
		if(pRIVACY_YN == null) {
			PRIVACY_YN = null;
		} else {
			PRIVACY_YN = "'" + pRIVACY_YN + "'";
		}
	}

	public List getP_result() {
		return p_result;
	}

	public void setP_result(List p_result) {
		this.p_result = p_result;
	}

	public String getREPORT_TYPE() {
		return REPORT_TYPE;
	}

	public void setREPORT_TYPE(String rEPORT_TYPE) {
		if(rEPORT_TYPE == null) {
			REPORT_TYPE = null;
		} else {
			REPORT_TYPE = "'" + rEPORT_TYPE + "'";
		}
	}

	public String getFLD_TYPE() {
		return FLD_TYPE;
	}

	public void setFLD_TYPE(String fLD_TYPE) {
		if(fLD_TYPE == null) {
			FLD_TYPE = null;
		} else {
			FLD_TYPE = "'" + fLD_TYPE + "'";
		}
	}

	public String getFLD_ID() {
		return FLD_ID;
	}

	public void setFLD_ID(String fLD_ID) {
		FLD_ID = fLD_ID;
	}

	public String getUSER_NO() {
		return USER_NO;
	}

	public void setUSER_NO(String uSER_NO) {
		USER_NO = uSER_NO;
	}
	
	public String getLAYOUT_CONFIG() {
		return LAYOUT_CONFIG;
	}

	public void setLAYOUT_CONFIG(String lAYOUT_CONFIG) {
		LAYOUT_CONFIG = lAYOUT_CONFIG;
	}
}
