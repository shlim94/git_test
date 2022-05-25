package com.wise.ds.repository;

import java.io.UnsupportedEncodingException;
import java.util.Iterator;

import org.bouncycastle.util.encoders.Base64;
import org.json.XML;

import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;

import org.json.JSONObject;

public class ReportListMasterVO implements Cloneable {
	private int ID;
	private int FLD_ID;
	private String TEXT;
	private int UPPERID;
	private int ORDINAL;
	private String TYPE;
	private String REPORT_TYPE;
	private String PROMPT;
	private String SUBTITLE;
	private String CREATED_BY;
	private String CREATED_DATE;
	private String TAG;
	private String DESCRIPTION;
	private String QUERY;
	private String DATASET_XML;
	private String dataSetXmlDecoded;
	private String uniqueKey;
	private String upperKey;
	private String schedulePath;
	private String DIRECTVIEW;
	/* DOGFOOT ktkang 보고서 정렬 순서 다른 오류 수정  20200707 */
	private String REG_DT;
	
	public int getID() {
		return ID;
	}
	public void setID(int iD) {
		ID = iD;
	}
	public int getFLD_ID() {
		return FLD_ID;
	}
	public void setFLD_ID(int fLD_ID) {
		FLD_ID = fLD_ID;
	}
	public String getTEXT() {
		return TEXT;
	}
	public void setTEXT(String tEXT) {
		TEXT = tEXT;
	}
	public int getUPPERID() {
		return UPPERID;
	}
	public void setUPPERID(int uPPERID) {
		UPPERID = uPPERID;
	}
	public int getORDINAL() {
		return ORDINAL;
	}
	public void setORDINAL(int oRDINAL) {
		ORDINAL = oRDINAL;
	}
	public String getTYPE() {
		return TYPE;
	}
	public void setTYPE(String tYPE) {
		TYPE = tYPE;
	}
	public String getREPORT_TYPE() {
		return REPORT_TYPE;
	}
	public void setREPORT_TYPE(String rEPORT_TYPE) {
		REPORT_TYPE = rEPORT_TYPE;
	}
	public String getPROMPT() {
		return PROMPT;
	}
	public void setPROMPT(String pROMPT) {
		PROMPT = pROMPT;
	}
	public String getSUBTITLE() {
		return SUBTITLE;
	}
	public void setSUBTITLE(String sUBTITLE) {
		SUBTITLE = sUBTITLE;
	}
	public String getCREATED_BY() {
		return CREATED_BY;
	}
	public void setCREATED_BY(String cREATED_BY) {
		CREATED_BY = cREATED_BY;
	}
	public String getCREATED_DATE() {
		return CREATED_DATE;
	}
	public void setCREATED_DATE(String cREATED_DATE) {
		CREATED_DATE = cREATED_DATE;
	}
	public String getTAG() {
		return TAG;
	}
	public void setTAG(String tAG) {
		TAG = tAG;
	}
	public String getDESCRIPTION() {
		return DESCRIPTION;
	}
	public void setDESCRIPTION(String dESCRIPTION) {
		DESCRIPTION = dESCRIPTION;
	}
	/* DOGFOOT ktkang 보고서 정렬 순서 다른 오류 수정  20200707 */
	public String getREG_DT() {
		return REG_DT;
	}
	public void setREG_DT(String rEG_DT) {
		REG_DT = rEG_DT;
	}
	public String getQUERY() {
		return QUERY;
	}
	public void setQUERY(String qUERY) throws UnsupportedEncodingException {
		String encodedQuery = CoreUtils.ifNull(qUERY);
		if (encodedQuery.length() > 0) {
			String encoding = Configurator.getInstance().getConfig("encoding");
	        QUERY = new String(Base64.decode(encodedQuery.getBytes()), encoding);
		}
	}
	public String getDATASET_XML() {
		return DATASET_XML;
	}
	public void setDATASET_XML(String dATASET_XML) throws UnsupportedEncodingException {
		DATASET_XML = dATASET_XML;
		String encodedXml = CoreUtils.ifNull(dATASET_XML);
		if (encodedXml.length() > 0) {
			String encoding = Configurator.getInstance().getConfig("encoding");
			this.dataSetXmlDecoded = new String(Base64.decode(this.DATASET_XML.getBytes()), encoding);
		}
	}
	
	public String getQueryFromDatasetXml() {
		String result = "";
		if (dataSetXmlDecoded != null && dataSetXmlDecoded.length() > 0) {
			JSONObject dataset = XML.toJSONObject(dataSetXmlDecoded);
			result = getKeyValue(dataset, "DATASET_QUERY");
		}
		return result;
	}
	
	/**
	 * Recursively search for nested key and return its' value. If nested key does not exist, return empty string.
	 * @param object
	 * @param searchedKey
	 * @return
	 */
	public static String getKeyValue(JSONObject object, String searchedKey) {
		String result = "";
	    boolean exists = object.has(searchedKey);
	    if(!exists) {      
	    	Iterator<?> keys = object.keys();
			while(keys.hasNext()) {
				String key = (String)keys.next();
				if (object.get(key) instanceof JSONObject) {
					result = getKeyValue(object.getJSONObject(key), searchedKey);
			    }
			}
	    } else {
	    	result = object.getString(searchedKey);
	    }
	    return result;
	}
	
	@Override
	public String toString() {
		return "ReportListMasterVO [ID=" + ID + ", TEXT=" + TEXT + ", UPPERID=" + UPPERID + ", ORDINAL=" + ORDINAL
				+ ", TYPE=" + TYPE + ", REPORT_TYPE=" + REPORT_TYPE + ", PROMPT=" + PROMPT + ", SUBTITLE=" + SUBTITLE
				+ ", CREATED_BY=" + CREATED_BY + ", CREATED_DATE=" + CREATED_DATE + ", TAG=" + TAG + ", DESCRIPTION="
				+ DESCRIPTION + ", QUERY=" + QUERY + ", DATASET_XML=" + DATASET_XML + ", dataSetXmlDecoded="
				+ dataSetXmlDecoded + "]";
	}
	
	public String getUniqueKey() {
		return uniqueKey;
	}
	public void setUniqueKey(String UniqueKey) {
		uniqueKey = UniqueKey;
	}	
	public String getUpperKey() {
		return upperKey;
	}
	public void setUpperKey(String UpperKey) {
		upperKey = UpperKey;
	}	
	public String getSchedulePath() {
		return schedulePath;
	}
	public void setSchedulePath(String schedulePath) {
		this.schedulePath = schedulePath;
	}
	public String getDIRECTVIEW() {
		return DIRECTVIEW;
	}
	public void setDIRECTVIEW(String dIRECTVIEW) {
		this.DIRECTVIEW = dIRECTVIEW;
	}
	
	@Override
	public Object clone() throws CloneNotSupportedException {
		return super.clone();
	}	
}
