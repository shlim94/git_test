package com.wise.ds.repository;

import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.json.XML;

import com.wise.common.secure.SecureUtils;
import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

public class DataSetInfoVO {
	private String P_PARAM;
	
	private int DATASET_ID;
	private String DATASET_NM;
	private int FLD_ID;
	private int DATASRC_ID;
	private String DATASRC_TYPE;
	private String DATASET_TYPE;
	private String SQL_XML;
	private String SQL_QUERY;
	private String DATASET_DESC;
	private int DATASET_ORDINAL;
	private int REG_USER_NO;
	private int MOD_USER_NO;
	private String PRIVACY_YN;
	
	private List p_result;
	private List p_error;
	private String out_RtnVal;
	
    
	public String getP_PARAM() {
		return P_PARAM;
	}

	public void setP_PARAM(String p_PARAM) {
		P_PARAM = p_PARAM;
	}

	public int getDATASET_ID() {
		return DATASET_ID;
	}

	public void setDATASET_ID(int dATASET_ID) {
		DATASET_ID = dATASET_ID;
	}

	public String getDATASET_NM() {
		return DATASET_NM;
	}

	public void setDATASET_NM(String dATASET_NM) {
		DATASET_NM = dATASET_NM;
	}

	public int getFLD_ID() {
		return FLD_ID;
	}

	public void setFLD_ID(int fLD_ID) {
		FLD_ID = fLD_ID;
	}

	public int getDATASRC_ID() {
		return DATASRC_ID;
	}

	public void setDATASRC_ID(int dATASRC_ID) {
		DATASRC_ID = dATASRC_ID;
	}

	public String getDATASRC_TYPE() {
		return DATASRC_TYPE;
	}

	public void setDATASRC_TYPE(String dATASRC_TYPE) {
		DATASRC_TYPE = dATASRC_TYPE;
	}

	public String getDATASET_TYPE() {
		return DATASET_TYPE;
	}

	public void setDATASET_TYPE(String dATASET_TYPE) {
		DATASET_TYPE = dATASET_TYPE;
	}

	public String getSQL_XML() {
		return SQL_XML;
	}

	public void setSQL_XML(String sQL_XML) {
		SQL_XML = sQL_XML;
	}

	public String getSQL_QUERY() {
		return SQL_QUERY;
	}

	public void setSQL_QUERY(String sQL_QUERY) {
		SQL_QUERY = sQL_QUERY;
	}

	public String getDATASET_DESC() {
		return DATASET_DESC;
	}

	public void setDATASET_DESC(String dATASET_DESC) {
		DATASET_DESC = dATASET_DESC;
	}

	public int getDATASET_ORDINAL() {
		return DATASET_ORDINAL;
	}

	public void setDATASET_ORDINAL(int dATASET_ORDINAL) {
		DATASET_ORDINAL = dATASET_ORDINAL;
	}

	public int getREG_USER_NO() {
		return REG_USER_NO;
	}

	public void setREG_USER_NO(int rEG_USER_NO) {
		REG_USER_NO = rEG_USER_NO;
	}

	public int getMOD_USER_NO() {
		return MOD_USER_NO;
	}

	public void setMOD_USER_NO(int mOD_USER_NO) {
		MOD_USER_NO = mOD_USER_NO;
	}

	public String getPRIVACY_YN() {
		return PRIVACY_YN;
	}

	public void setPRIVACY_YN(String pRIVACY_YN) {
		PRIVACY_YN = pRIVACY_YN;
	}

	public List getP_result() {
		return p_result;
	}

	public void setP_result(List p_result) {
		this.p_result = p_result;
	}

	public String getOut_RtnVal() {
		return out_RtnVal;
	}

	public void setOut_RtnVal(String out_RtnVal) {
		this.out_RtnVal = out_RtnVal;
	}

	@Override
	public String toString() {
		return "DataSetInfoVO [P_PARAM=" + P_PARAM + ", DATASET_ID=" + DATASET_ID + ", DATASET_NM=" + DATASET_NM
				+ ", FLD_ID=" + FLD_ID + ", DATASRC_ID=" + DATASRC_ID + ", DATASRC_TYPE=" + DATASRC_TYPE
				+ ", DATASET_TYPE=" + DATASET_TYPE + ", SQL_XML=" + SQL_XML + ", SQL_QUERY=" + SQL_QUERY
				+ ", DATASET_DESC=" + DATASET_DESC + ", DATASET_ORDINAL=" + DATASET_ORDINAL + ", REG_USER_NO="
				+ REG_USER_NO + ", MOD_USER_NO=" + MOD_USER_NO + ", PRIVACY_YN=" + PRIVACY_YN + "]";
	}

}
