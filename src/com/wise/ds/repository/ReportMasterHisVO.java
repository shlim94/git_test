package com.wise.ds.repository;

import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.annotation.Resource;

import org.bouncycastle.util.encoders.Base64;
import org.json.JSONException;
import org.json.XML;

import com.wise.common.secure.SecureUtils;
import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;
import com.wise.ds.repository.service.DataSetService;

import jxl.common.Logger;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.xml.XMLSerializer;

public class ReportMasterHisVO {
	final static Logger logger = Logger.getLogger(ReportMasterVO.class);

	@Resource(name = "dataSetService")
    private DataSetService dataSetServiceImpl;
	
	private String REPORT_ID;
	private int REPORT_SEQ;
	private String REPORT_NM;
	private String REPORT_TYPE;
	private String REPORT_TAG;
	private String REPORT_SUB_TITLE;
	private String REPORT_DESC;
	private String FLD_ID;
	private String FLD_TYPE;
	private String REPORT_ORDINAL;
	private String REPORT_XML;
	private String LAYOUT_XML;
	private String DATASET_XML;
	private String PARAM_XML;
	private String REPORT_LAYOUT;
	private String DATASRC_ID;
	private String DATASRC_TYPE;
	private String DATASET_TYPE;
	private String DATASET_QUERY;
	private String LAYOUT_CONFIG;
	private String DEL_YN;
	private String PROMPT_YN;
	private String MOD_USER_ID;
	private int MOD_USER_NO;
	private String MOD_DT;
	private String CHART_XML;
	private String GRID_INFO;
	private String PRIVACY_YN;
	private String DIRECT_VIEW;
	

	public String getREPORT_LAYOUT() {
		return REPORT_LAYOUT;
	}

	public void setREPORT_LAYOUT(String rEPORT_LAYOUT) {
		REPORT_LAYOUT = rEPORT_LAYOUT;
	}

	public String getREPORT_ID() {
		return REPORT_ID;
	}

	public void setREPORT_ID(String rEPORT_ID) {
		REPORT_ID = rEPORT_ID;
	}
	
	public int getREPORT_SEQ() {
		return REPORT_SEQ;
	}

	public void setREPORT_SEQ(int rEPORT_SEQ) {
		REPORT_SEQ = rEPORT_SEQ;
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

	public String getREPORT_TAG() {
		return REPORT_TAG;
	}

	public void setREPORT_TAG(String rEPORT_TAG) {
		REPORT_TAG = rEPORT_TAG;
	}

	public String getREPORT_SUB_TITLE() {
		return REPORT_SUB_TITLE;
	}

	public void setREPORT_SUB_TITLE(String rEPORT_SUB_TITLE) {
		REPORT_SUB_TITLE = rEPORT_SUB_TITLE;
	}

	public String getREPORT_DESC() {
		return REPORT_DESC;
	}

	public void setREPORT_DESC(String rEPORT_DESC) {
		REPORT_DESC = rEPORT_DESC;
	}

	public String getFLD_ID() {
		return FLD_ID;
	}

	public void setFLD_ID(String fLD_ID) {
		FLD_ID = fLD_ID;
	}

	public String getFLD_TYPE() {
		return FLD_TYPE;
	}

	public void setFLD_TYPE(String fLD_TYPE) {
		FLD_TYPE = fLD_TYPE;
	}

	public String getREPORT_ORDINAL() {
		return REPORT_ORDINAL;
	}

	public void setREPORT_ORDINAL(String rEPORT_ORDINAL) {
		REPORT_ORDINAL = rEPORT_ORDINAL;
	}

	public String getREPORT_XML() {
		return this.REPORT_XML;
	}

	public void setREPORT_XML(String rEPORT_XML){
		this.REPORT_XML = rEPORT_XML;
	}

	public String getLAYOUT_XML() {
		return this.LAYOUT_XML;
	}

	public void setLAYOUT_XML(String lAYOUT_XML) {
		this.LAYOUT_XML = lAYOUT_XML;
	}

	private XMLSerializer xmlSerializer;

	public ReportMasterHisVO() {
		this.xmlSerializer = new XMLSerializer();
	}

	public String getDATASET_XML() {
		return DATASET_XML;
	}

	public void setDATASET_XML(String dATASET_XML) throws UnsupportedEncodingException {
		this.DATASET_XML = dATASET_XML;
	}

	public String getPARAM_XML() {
		return PARAM_XML;
	}

	public void setPARAM_XML(String pARAM_XML) throws UnsupportedEncodingException {
		this.PARAM_XML = pARAM_XML;
	}

	public String getDEL_YN() {
		return DEL_YN;
	}

	public void setDEL_YN(String dEL_YN) {
		DEL_YN = dEL_YN;
	}

	public String getPROMPT_YN() {
		return PROMPT_YN;
	}

	public void setPROMPT_YN(String pROMPT_YN) {
		PROMPT_YN = pROMPT_YN;
	}

	public String getMOD_USER_ID() {
		return MOD_USER_ID;
	}

	public void setMOD_USER_ID(String mOD_USER_ID) {
		MOD_USER_ID = mOD_USER_ID;
	}

	public int getMOD_USER_NO() {
		return MOD_USER_NO;
	}

	public void setMOD_USER_NO(int mOD_USER_NO) {
		MOD_USER_NO = mOD_USER_NO;
	}
	
	public String getMOD_DT() {
		return MOD_DT;
	}

	public void setMOD_DT(String mOD_DT) {
		MOD_DT = mOD_DT;
	}

	public String getCHART_XML() {
		return CHART_XML;
	}

	public void setCHART_XML(String cHART_XML) throws UnsupportedEncodingException {
		this.CHART_XML = cHART_XML;
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
		DATASRC_TYPE = dATASRC_TYPE;
	}

	public String getDATASET_TYPE() {
		return DATASET_TYPE;
	}

	public void setDATASET_TYPE(String dATASET_TYPE) {
		DATASET_TYPE = dATASET_TYPE;
	}

	public String getDATASET_QUERY() {
		return DATASET_QUERY;
	}

	public void setDATASET_QUERY(String dATASET_QUERY) throws UnsupportedEncodingException {
		this.DATASET_QUERY = dATASET_QUERY;
	}

	public String getLAYOUT_CONFIG() {
		return LAYOUT_CONFIG;
	}

	public void setLAYOUT_CONFIG(String lAYOUT_CONFIG) {
		LAYOUT_CONFIG = lAYOUT_CONFIG;
	}
	
	public String getGRID_INFO() {
		return GRID_INFO;
	}

	public void setGRID_INFO(String gRID_INFO) {
		GRID_INFO = gRID_INFO;
	}
	
	public String getPRIVACY_YN() {
		return PRIVACY_YN;
	}

	public void setPRIVACY_YN(String pRIVACY_YN) {
		PRIVACY_YN = pRIVACY_YN;
	}
	
	public String getDIRECT_VIEW() {
		return DIRECT_VIEW;
	}

	public void setDIRECT_VIEW(String dIRECT_VIEW) {
		DIRECT_VIEW = dIRECT_VIEW;
	}
	
	@Override
	public String toString() {
		return "ReportMasterVO [REPORT_ID=" + REPORT_ID + ", REPORT_NM=" + REPORT_NM + ", REPORT_TYPE=" + REPORT_TYPE
				+ ", REPORT_TAG=" + REPORT_TAG + ", REPORT_SUB_TITLE=" + REPORT_SUB_TITLE + ", REPORT_DESC="
				+ REPORT_DESC + ", FLD_ID=" + FLD_ID + ", FLD_TYPE=" + FLD_TYPE + ", LAYOUT_XML=" + LAYOUT_XML
				+ ", DATASET_XML=" + DATASET_XML + ", PARAM_XML=" + PARAM_XML + ", layoutXml_decoded="
				+ ", datasetXml_decoded="  + ", paramXml_decoded="
				+ ", REG_USER_NO=" + ", PROMPT_YN=" + PROMPT_YN + ", datasetJson="
				+ ", paramJson=" + ", MOD_USER_NO=" + MOD_USER_NO + ", chartXml_decoded="
				+ ", chartXml=" + CHART_XML + ", chartJson=" + ", xmlSerializer="
				+ xmlSerializer + "]";
	}

	// public String toString() {
	// return "ReportMasterVO [id=" + id + ", name=" + name + ", type=" + type + ",
	// folderId=" + folderId + ", folderType=" + folderType
	// + ", layoutXmlBase64=" + layoutXmlBase64 + ", datasetXmlBase64=" +
	// datasetXmlBase64 + ", paramXmlBase64=" + paramXmlBase64
	// + ", layoutXml=" + layoutXml + ", datasetXml=" + datasetXml + ", paramXml=" +
	// paramXml + ", promptYN=" + promptYN
	// + ", datasetJson=" + datasetJson + ", paramJson=" + paramJson + ",
	// regUserId=" + regUserNo + ", xmlSerializer=" + xmlSerializer + "]";
	// }
}
