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

public class ReportMasterVO {
	final static Logger logger = Logger.getLogger(ReportMasterVO.class);

	@Resource(name = "dataSetService")
    private DataSetService dataSetServiceImpl;
	
	private String REPORT_ID;
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
	private String reportXml_decoded;
	private String layoutXml_decoded;
	private String datasetXml_decoded;
	private String paramXml_decoded;
	private String REPORT_LAYOUT;
	private String DATASRC_ID;
	private String DATASRC_TYPE;
	private String DATASET_TYPE;
	private String DATASET_QUERY;
	private String datasetquery_encoded;
	/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
	private String LAYOUT_CONFIG;
	private String DIRECT_VIEW;

	private String REG_USER_ID;
	private int REG_USER_NO;
	private String DEL_YN;
	private String PROMPT_YN;
	private JSONObject datasetJson;
//	private JSONArray paramJson; // can be JSONObject or JSONArray
//	 private Object paramJson; // can be JSONObject or JSONArray
	private JSONObject paramJson;
	private String MOD_USER_ID;
	private int MOD_USER_NO;
	private String chartXml_decoded;
	private String CHART_XML;
	
	/* DOGFOOT shlim reportmstr dsid 변경  20200309 */
	private String DECODE_DATASET;
	private String DECODE_PARAM;
	private String DECODE_REPORT;
	private int DECODE_REPORT_ID;

	private JSONObject chartJson;

	private JSONObject layoutJson;

	private JSONObject reportJson;

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
		return this.reportXml_decoded;
	}

	public void setREPORT_XML(String rEPORT_XML) throws UnsupportedEncodingException {
		this.REPORT_XML = CoreUtils.ifNull(rEPORT_XML);

		if (this.REPORT_XML.length() > 0) {
			String encoding = Configurator.getInstance().getConfig("encoding");
			this.reportXml_decoded = new String(Base64.decode(this.REPORT_XML.getBytes()), encoding);

			org.json.JSONObject json = XML.toJSONObject(this.reportXml_decoded);
			org.json.JSONObject REPORT_XML;
			try {
				REPORT_XML = json.getJSONObject("REPORT_XML");
			} catch (JSONException e) {
				REPORT_XML = json.getJSONObject("EXCEL_XML");
			}
			
			this.reportJson = JSONObject.fromObject(REPORT_XML.toString());
		}
	}

	public String getLAYOUT_XML() {
		return this.layoutXml_decoded;
	}

	public void setLAYOUT_XML(String lAYOUT_XML) throws NotFoundReportXmlException, UnsupportedEncodingException {
		this.LAYOUT_XML = CoreUtils.ifNull(lAYOUT_XML);

		if (this.LAYOUT_XML.length() > 0) {
			String encoding = Configurator.getInstance().getConfig("encoding");
			this.layoutXml_decoded = new String(Base64.decode(this.LAYOUT_XML.getBytes()), encoding);
		}
	}

	private XMLSerializer xmlSerializer;

	public ReportMasterVO() {
		this.xmlSerializer = new XMLSerializer();
	}

	public String getDATASET_XML() {
		return DATASET_XML;
	}

	public void setDATASET_XML(String dATASET_XML) throws UnsupportedEncodingException {
		String encoding = Configurator.getInstance().getConfig("encoding");

		this.DATASET_XML = CoreUtils.ifNull(dATASET_XML);

		if (this.DATASET_XML.length() > 0) {
			this.datasetXml_decoded = new String(Base64.decode(this.DATASET_XML.getBytes()), encoding);

			/*
			 * JSON json = this.xmlSerializer.read(this.datasetXml); this.datasetJson =
			 * JSONObject.fromObject(json);
			 */
			org.json.JSONObject json = XML.toJSONObject(this.datasetXml_decoded);
			org.json.JSONObject DATASET_XML;
			if (json.has("DATASET_XML")) {
				DATASET_XML = json.getJSONObject("DATASET_XML");
			} else {
				DATASET_XML = json;
			}

			this.datasetJson = JSONObject.fromObject(DATASET_XML.toString());
			if(this.datasetJson.has("DATASET_ELEMENT") && this.datasetJson.get("DATASET_ELEMENT").toString().length() != 0) {
				if(this.datasetJson.getJSONObject("DATASET_ELEMENT").has("DATASET")) {
					Object obj = this.datasetJson.getJSONObject("DATASET_ELEMENT").get("DATASET");
					if(obj instanceof JSONObject) {
						if(this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").has("DATASET_TYPE")) {//jsonArray 일 경우 분기 추가
							if(this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").getString("DATASET_TYPE").equals("DataSetDs")) {
								org.json.JSONObject dataset_xml = XML.toJSONObject(this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").getString("DATASET_XML"));
								//							this.datasetJson.getJSONObject("DATASET_ELEMENT").put("DATASET_JSON", dataset_xml.toString());
								if(dataset_xml.getJSONObject("DATA_SET").has("SEL_ELEMENT")) {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("SEL_ELEMENT", dataset_xml.getJSONObject("DATA_SET").get("SEL_ELEMENT").toString());
								}else {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("SEL_ELEMENT", "");
								}

								if(dataset_xml.getJSONObject("DATA_SET").has("WHERE_ELEMENT")) {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("WHERE_ELEMENT", dataset_xml.getJSONObject("DATA_SET").get("WHERE_ELEMENT").toString());
								}else {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("WHERE_ELEMENT", "");
								}

								if(dataset_xml.getJSONObject("DATA_SET").has("ORDER_ELEMENT")) {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("ORDER_ELEMENT", dataset_xml.getJSONObject("DATA_SET").get("ORDER_ELEMENT").toString());
								}else {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("ORDER_ELEMENT", "");
								}

								if(dataset_xml.getJSONObject("DATA_SET").has("REL_ELEMENT")) {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("REL_ELEMENT", dataset_xml.getJSONObject("DATA_SET").get("REL_ELEMENT").toString());
								}else {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("REL_ELEMENT", "");
								}

								if(dataset_xml.getJSONObject("DATA_SET").has("PARAM_ELEMENT")) {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("PARAM_ELEMENT", dataset_xml.getJSONObject("DATA_SET").get("PARAM_ELEMENT").toString());
								}else {
									this.datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET").put("PARAM_ELEMENT", "");
								}
							}
						}
					}
					else {
						JSONArray datasetArray = (JSONArray)obj;
						for(int i=0;i<datasetArray.size();i++) {
							org.json.JSONObject dataset_obj = new org.json.JSONObject(datasetArray.getJSONObject(i).toString());
							//						this.datasetJson.getJSONObject("DATASET_ELEMENT").put("DATASET_JSON", dataset_xml.toString());
							if(dataset_obj.getString("DATASET_TYPE").equals("DataSetDs")) {
								org.json.JSONObject dataset_xml = XML.toJSONObject(dataset_obj.getString("DATASET_XML")).getJSONObject("DATA_SET");

								if(dataset_xml.has("SEL_ELEMENT")) {
									dataset_obj.put("SEL_ELEMENT", dataset_xml.get("SEL_ELEMENT").toString());
								}else {
									dataset_obj.put("SEL_ELEMENT", "");
								}

								if(dataset_xml.has("WHERE_ELEMENT")) {
									dataset_obj.put("WHERE_ELEMENT", dataset_xml.get("WHERE_ELEMENT").toString());
								}else {
									dataset_obj.put("WHERE_ELEMENT", "");
								}

								if(dataset_xml.has("ORDER_ELEMENT")) {
									dataset_obj.put("ORDER_ELEMENT", dataset_xml.get("ORDER_ELEMENT").toString());
								}else {
									dataset_obj.put("ORDER_ELEMENT", "");
								}

								if(dataset_xml.has("REL_ELEMENT")) {
									dataset_obj.put("REL_ELEMENT", dataset_xml.get("REL_ELEMENT").toString());
								}else {
									dataset_obj.put("REL_ELEMENT", "");
								}

								if(dataset_xml.has("PARAM_ELEMENT")) {
									dataset_obj.put("PARAM_ELEMENT", dataset_xml.get("PARAM_ELEMENT").toString());
								}else {
									dataset_obj.put("PARAM_ELEMENT", "");
								}
							}
						}
					}
				}
			}
		}
	}

	public String getPARAM_XML() {
		return PARAM_XML;
	}

	public void setPARAM_XML(String pARAM_XML) throws UnsupportedEncodingException {
		String encoding = Configurator.getInstance().getConfig("encoding");

		this.PARAM_XML = CoreUtils.ifNull(pARAM_XML);

		if (this.PARAM_XML.length() > 0) {
			this.paramXml_decoded = new String(Base64.decode(this.PARAM_XML.getBytes()), encoding);

			//////////////////////////////////////////////////////////////////////////////////
			/*
			 * JSON json = this.xmlSerializer.read(this.paramXml);
			 * 
			 * if (json.isArray()) { this.paramJson = JSONArray.fromObject(json); } else {
			 * this.paramJson = new JSONArray(); JSONObject tempJson =
			 * JSONObject.fromObject(json); if (!tempJson.isNullObject()) {
			 * this.paramJson.add(tempJson.get("PARAM")); } }
			 */
			try {
				org.json.JSONObject json = XML.toJSONObject(this.paramXml_decoded);
				org.json.JSONObject PARAM_XML = json.getJSONObject("PARAM_XML");
				Object PARAM = PARAM_XML.get("PARAM");

				String PARAM_JSON_STR;
				if (PARAM instanceof org.json.JSONObject) {
					PARAM_JSON_STR = PARAM_XML.getJSONObject("PARAM").toString();
					JSONObject tempJson = JSONObject.fromObject(PARAM_JSON_STR);
//					this.paramJson = new JSONArray();
//					this.paramJson.add(tempJson);
					this.paramJson = new JSONObject();
					this.paramJson.put(tempJson.getString("PARAM_NM"),tempJson);
				} else {
					PARAM_JSON_STR = PARAM_XML.getJSONArray("PARAM").toString();
					JSONArray paramArr = JSONArray.fromObject(PARAM_JSON_STR);
					this.paramJson = new JSONObject();
					for(int i=0;i<paramArr.size();i++) {
						JSONObject obj = paramArr.getJSONObject(i);
						this.paramJson.put(obj.getString("PARAM_NM"), obj);
					}
					//				this.paramJson = JSONArray.fromObject(PARAM_JSON_STR);
				}
			} catch (org.json.JSONException e) {
				this.paramJson = new JSONObject();
				logger.info(e);
			}
			//////////////////////////////////////////////////////////////////////////////////

			String plainSql = null;
			String encSql = null;
			String paramName = null;
			Iterator<String> paramKey = this.paramJson.keys();

			while (paramKey.hasNext()) {
				String paramKeyName = paramKey.next().toString();
				JSONObject paramMetadata = this.paramJson.getJSONObject(paramKeyName);
				/* dogfoot WHATIF 분석 매개변수 저장 & 불러오기 shlim 20201022 */
				if(!paramMetadata.has("CALC_PARAM_YN")) {
					paramMetadata.put("wiseVariables", new JSONArray());
					if ("QUERY".equalsIgnoreCase(paramMetadata.getString("DATASRC_TYPE"))) {
						plainSql = CoreUtils.ifNull(paramMetadata.getString("DATASRC"));


						Iterator<String> targetParamKey = this.paramJson.keys();
						while(targetParamKey.hasNext()) {
							paramName = this.paramJson.getJSONObject(targetParamKey.next().toString()).getString("PARAM_NM");
							if(plainSql.indexOf(paramName) > -1) {
								paramMetadata.getJSONArray("wiseVariables").add(paramName);
								paramMetadata.getJSONArray("wiseVariables")
								.add(this.paramJson.getJSONObject(paramKeyName).getString("WHERE_CLAUSE"));
							}
						}

						encSql = SecureUtils.encSeed(Configurator.Constants.SEED_CBC_ENCRIPTION_KEY, plainSql);
						paramMetadata.put("DATASRC", encSql);
					}
				}
				
			}
			//		for (int x0 = 0; x0 < this.paramJson.size(); x0++) {
			//			JSONObject paramMetadata = this.paramJson.getJSONObject(x0);
			//			paramMetadata.put("wiseVariables", new JSONArray());
			//
			//			if ("QUERY".equalsIgnoreCase(paramMetadata.getString("DATASRC_TYPE"))) {
			//				plainSql = CoreUtils.ifNull(paramMetadata.getString("DATASRC"));
			//
			//				for (int x1 = 0; x1 < this.paramJson.size(); x1++) {
			//					paramName = this.paramJson.getJSONObject(x1).getString("PARAM_NM");
			//					if (plainSql.indexOf(paramName) > -1) {
			//						paramMetadata.getJSONArray("wiseVariables").add(paramName);
			//						paramMetadata.getJSONArray("wiseVariables")
			//								.add(this.paramJson.getJSONObject(x1).getString("WHERE_CLAUSE"));
			//					}
			//				}
			//
			//				encSql = SecureUtils.encSeed(Configurator.Constants.SEED_CBC_ENCRIPTION_KEY, plainSql);
			//				paramMetadata.put("DATASRC", encSql);
			//			}
			//		}
		}
	}

	public String getLayoutXml_decoded() {
		return layoutXml_decoded;
	}

	public void setLayoutXml_decoded(String layoutXml_decoded) {
		this.layoutXml_decoded = layoutXml_decoded;
	}

	public String getDatasetXml_decoded() {
		return datasetXml_decoded;
	}

	public void setDatasetXml_decoded(String datasetXml_decoded) {
		this.datasetXml_decoded = datasetXml_decoded;
	}

	public String getParamXml_decoded() {
		return paramXml_decoded;
	}

	public void setParamXml_decoded(String paramXml_decoded) {
		this.paramXml_decoded = paramXml_decoded;
	}

	public int getREG_USER_NO() {
		return REG_USER_NO;
	}

	public void setREG_USER_NO(int rEG_USER_NO) {
		REG_USER_NO = rEG_USER_NO;
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

	public JSONObject getDatasetJson() {
		return datasetJson;
	}

	public void setDatasetJson(JSONObject datasetJson) {
		this.datasetJson = datasetJson;
	}

	public Object getParamJson() {
		return paramJson;
	}

	public void setParamJson(JSONObject paramJson) {
		this.paramJson = paramJson;
	}

	public String getREG_USER_ID() {
		return REG_USER_ID;
	}

	public void setREG_USER_ID(String rEG_USER_ID) {
		REG_USER_ID = rEG_USER_ID;
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

	public String getChartXml_decoded() {
		return chartXml_decoded;
	}

	public void setChartXml_decoded(String chartXml_decoded) {
		this.chartXml_decoded = chartXml_decoded;
	}

	public String getCHART_XML() {
		return CHART_XML;
	}

	public void setCHART_XML(String cHART_XML) throws UnsupportedEncodingException {
		this.chartXml_decoded = CoreUtils.ifNull(cHART_XML);
		if ("".equals(this.chartXml_decoded)) {
			this.CHART_XML = "";
			this.chartJson = new JSONObject();
		} else {
			String encoding = Configurator.getInstance().getConfig("encoding");
			this.CHART_XML = new String(Base64.decode(this.chartXml_decoded.getBytes()), encoding);

			if ("".equals(CoreUtils.ifNull(this.CHART_XML))) {
				this.chartJson = new JSONObject();
			} else {
				org.json.JSONObject CHART_XML = XML.toJSONObject(this.CHART_XML);
				this.chartJson = JSONObject.fromObject(CHART_XML.toString());
			}
		}
	}

	public JSONObject getChartJson() {
		return chartJson;
	}

	public void setChartJson(JSONObject chartJson) {
		this.chartJson = chartJson;
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
		this.datasetquery_encoded = CoreUtils.ifNull(dATASET_QUERY);
		
		if ("".equals(this.datasetquery_encoded)) {
			this.DATASET_QUERY = "";
		} else {
			String encoding = Configurator.getInstance().getConfig("encoding");
			this.DATASET_QUERY = new String(Base64.decode(this.datasetquery_encoded.getBytes()), encoding);
		}
	}

	public JSONObject getLayoutJson() {
		return layoutJson;
	}

	public JSONObject getReportJson() {
		return reportJson;
	}

	public JSONObject getDataSourceAndParameterJson(String cUBE_NM) {
		Map<String, Object> basicInfo = new LinkedHashMap<String, Object>();
		basicInfo.put("id", this.getREPORT_ID());
		basicInfo.put("name", this.getREPORT_NM());
		basicInfo.put("type", this.getREPORT_TYPE());
		basicInfo.put("promptYn", this.getPROMPT_YN());
		/* DOGFOOT ktkang 주제영역 안열리는 오류 수정  20200110 */
		/* DOGFOOT hsshim 2020-02-19 주제영역 안열리는 오류 수정 */
		if (this.getDatasetJson() == null || (this.getDATASRC_TYPE() != null && this.getDATASRC_TYPE().equals("CUBE") && (this.getDATASET_TYPE() == null || this.getDATASET_TYPE().equals("") || "CUBE".equals(this.getDATASET_TYPE())))) {
			JSONObject datasetJson = new JSONObject();
			JSONObject datasetElement = new JSONObject();
			JSONArray datasetElementList = new JSONArray();
			
			datasetElement.put("DATASET_QUERY", this.getDATASET_QUERY());
			datasetElement.put("wise_sql_id", this.REPORT_ID + "-0");
			
			datasetElement.put("DATASET_NM", cUBE_NM);
			datasetElement.put("DATASET_TYPE", this.getDATASRC_TYPE());
			datasetElement.put("DATASRC_TYPE", this.getDATASRC_TYPE());
			datasetElement.put("DATASRC_ID", this.getDATASRC_ID());
			
			datasetElementList.add(datasetElement);
			datasetJson.put("DATASET_ELEMENT", datasetElementList);
			basicInfo.put("datasetJson", datasetJson);
			
			Object paramJsonObject = this.getParamJson();
			if ((paramJsonObject instanceof JSONArray && ((JSONArray) this.getParamJson()).isEmpty())
					|| (paramJsonObject instanceof JSONObject && ((JSONObject) this.getParamJson()).isNullObject())) {
				// basicInfo.put("paramJson", "");
				basicInfo.put("paramJson", new JSONArray());
			} else {
				basicInfo.put("paramJson", this.getParamJson());
			}
		} else {
			JSONObject datasetJson = this.getDatasetJson();

			JSONArray datasetElementList;
			if (datasetJson.has("DATASET_ELEMENT") && datasetJson.get("DATASET_ELEMENT").toString().length() != 0) {
				if (datasetJson.getJSONObject("DATASET_ELEMENT").get("DATASET") instanceof JSONObject) {
					JSONObject tmpJson = datasetJson.getJSONObject("DATASET_ELEMENT").getJSONObject("DATASET");
					// tmpJson.remove("DATASET_XML");
					String dataset_xml = tmpJson.getString("DATASET_XML");
					String[] arrXml1 = dataset_xml.split("<DATASET_NM>");
					if(arrXml1.length>1) {
						String[] arrXml2 = arrXml1[1].split("</DATASET_NM>");
						dataset_xml = arrXml1[0] + "<DATASET_NM>" + arrXml2[0].replaceAll("<", "&lt;").replaceAll(">", "&gt;") + "</DATASET_NM>" + arrXml2[1];
					}
					tmpJson.put("DATASET_JSON", XML.toJSONObject(dataset_xml).toString().replaceAll("&lt;", "<").replaceAll("&gt;", ">"));
					tmpJson.put("DATASET_NM", tmpJson.getString("DATASET_NM").replaceAll("&lt;", "<").replaceAll("&gt;", ">"));
					Object param_ELEMENT = tmpJson.getJSONObject("DATASET_JSON").getJSONObject("DATA_SET").get("PARAM_ELEMENT");
					if(param_ELEMENT instanceof JSONObject) {
						JSONObject paramJsonObject = tmpJson.getJSONObject("DATASET_JSON").getJSONObject("DATA_SET").getJSONObject("PARAM_ELEMENT");
						if(paramJsonObject.has("PARAM")) {
							JSONArray paramItems = new JSONArray();
							Object PARAM = paramJsonObject.get("PARAM");
							if(PARAM instanceof JSONObject) {
								JSONObject TemporaryParamJSON = paramJsonObject.getJSONObject("PARAM");
								String PARAM_NM = TemporaryParamJSON.getString("PARAM_NM");
								JSONObject obj = new JSONObject();
								obj.put("defaultValue", TemporaryParamJSON.get("DEFAULT_VALUE"));
								obj.put("name", TemporaryParamJSON.get("PARAM_CAPTION"));
								obj.put("paramName", TemporaryParamJSON.get("PARAM_NM"));
								obj.put("parameterType", TemporaryParamJSON.get("DATA_TYPE"));
								obj.put("type", TemporaryParamJSON.get("PARAM_TYPE"));
								obj.put("value", TemporaryParamJSON.get("DEFAULT_VALUE"));
								obj.put("whereClause", TemporaryParamJSON.get("WHERE_CLAUSE"));
								JSONObject paramElement = new JSONObject();
								paramElement.put(PARAM_NM, obj);
								paramItems.add(paramElement);
//								paramItems.add(PARAM_NM);
							}else {
								JSONArray paramArr = paramJsonObject.getJSONArray("PARAM");
								for(int i=0;i<paramArr.size();i++) {
									String PARAM_JSON_STR = paramArr.getJSONObject(i).getString("PARAM_NM");
									JSONObject obj = new JSONObject();
									obj.put("defaultValue", paramArr.getJSONObject(i).get("DEFAULT_VALUE"));
									obj.put("name", paramArr.getJSONObject(i).get("PARAM_CAPTION"));
									obj.put("paramName", paramArr.getJSONObject(i).get("PARAM_NM"));
									obj.put("parameterType", paramArr.getJSONObject(i).get("DATA_TYPE"));
									obj.put("type", paramArr.getJSONObject(i).get("PARAM_TYPE"));
									obj.put("value", paramArr.getJSONObject(i).get("DEFAULT_VALUE"));
									obj.put("whereClause", paramArr.getJSONObject(i).get("WHERE_CLAUSE"));
									JSONObject paramElement = new JSONObject();
									paramElement.put(PARAM_JSON_STR, obj);
									paramItems.add(paramElement);
								}
							}
							tmpJson.put("param_element", paramItems);
						}
					}else {
						tmpJson.put("param_element", new JSONArray());
					}
					datasetElementList = new JSONArray();
					datasetElementList.add(tmpJson);
				} else if (datasetJson.getJSONObject("DATASET_ELEMENT").get("DATASET") instanceof JSONArray) {
					datasetElementList = datasetJson.getJSONObject("DATASET_ELEMENT").getJSONArray("DATASET");

					for (int x0 = 0; x0 < datasetElementList.size(); x0++) {
						String dataset_xml = datasetElementList.getJSONObject(x0).getString("DATASET_XML");
						String[] arrXml1 = dataset_xml.split("<DATASET_NM>");
						if(arrXml1.length>1) {
							String[] arrXml2 = arrXml1[1].split("</DATASET_NM>");
							dataset_xml = arrXml1[0] + "<DATASET_NM>" + arrXml2[0].replaceAll("<", "&lt;").replaceAll(">", "&gt;") + "</DATASET_NM>" + arrXml2[1];
						}						
						datasetElementList.getJSONObject(x0).put("DATASET_JSON", XML.toJSONObject(dataset_xml).toString().replaceAll("&lt;", "<").replaceAll("&gt;", ">"));
						datasetElementList.getJSONObject(x0).put("DATASET_NM", datasetElementList.getJSONObject(x0).getString("DATASET_NM").replaceAll("&lt;", "<").replaceAll("&gt;", ">"));
						Object tempjson = datasetElementList.getJSONObject(x0).getJSONObject("DATASET_JSON").getJSONObject("DATA_SET").get("PARAM_ELEMENT");
						if(tempjson instanceof JSONObject) {
							JSONObject paramJsonObject = datasetElementList.getJSONObject(x0).getJSONObject("DATASET_JSON").getJSONObject("DATA_SET").getJSONObject("PARAM_ELEMENT");
							if(paramJsonObject.has("PARAM")) {
								JSONArray paramItems = new JSONArray();
								Object PARAM = paramJsonObject.get("PARAM");
								if(PARAM instanceof JSONObject) {
									JSONObject TemporaryParamJSON = paramJsonObject.getJSONObject("PARAM");
									String PARAM_NM = TemporaryParamJSON.getString("PARAM_NM");
									JSONObject obj = new JSONObject();
									obj.put("defaultValue", TemporaryParamJSON.get("DEFAULT_VALUE"));
									obj.put("name", TemporaryParamJSON.get("PARAM_CAPTION"));
									obj.put("paramName", TemporaryParamJSON.get("PARAM_NM"));
									obj.put("parameterType", TemporaryParamJSON.get("DATA_TYPE"));
									obj.put("type", TemporaryParamJSON.get("PARAM_TYPE"));
									obj.put("value", TemporaryParamJSON.get("DEFAULT_VALUE"));
									obj.put("whereClause", TemporaryParamJSON.get("WHERE_CLAUSE"));
									JSONObject paramElement = new JSONObject();
									paramElement.put(PARAM_NM, obj);
									paramItems.add(paramElement);
//									paramItems.add(PARAM_NM);
								}else {
									JSONArray paramArr = paramJsonObject.getJSONArray("PARAM");
									for(int i=0;i<paramArr.size();i++) {
										String PARAM_JSON_STR = paramArr.getJSONObject(i).getString("PARAM_NM");
										JSONObject obj = new JSONObject();
										obj.put("defaultValue", paramArr.getJSONObject(i).get("DEFAULT_VALUE"));
										obj.put("name", paramArr.getJSONObject(i).get("PARAM_CAPTION"));
										obj.put("paramName", paramArr.getJSONObject(i).get("PARAM_NM"));
										obj.put("parameterType", paramArr.getJSONObject(i).get("DATA_TYPE"));
										obj.put("type", paramArr.getJSONObject(i).get("PARAM_TYPE"));
										obj.put("value", paramArr.getJSONObject(i).get("DEFAULT_VALUE"));
										obj.put("whereClause", paramArr.getJSONObject(i).get("WHERE_CLAUSE"));
										JSONObject paramElement = new JSONObject();
										paramElement.put(PARAM_JSON_STR, obj);
										paramItems.add(paramElement);
									}
								}
								datasetElementList.getJSONObject(x0).put("param_element", paramItems);
							}
						}else if(tempjson instanceof JSONArray) {
							JSONArray paramJsonArray =  datasetElementList.getJSONObject(x0).getJSONObject("DATASET_JSON").getJSONObject("DATA_SET").getJSONArray("PARAM_ELEMENT");
							for(int paramsize = 0;paramsize<paramJsonArray.size();paramsize++) {
								JSONObject paramJsonObject =  paramJsonArray.getJSONObject(paramsize);
								if(paramJsonObject.has("PARAM")) {
									JSONArray paramItems = new JSONArray();
									Object PARAM = paramJsonObject.get("PARAM");
									if(PARAM instanceof JSONObject) {
										JSONObject TemporaryParamJSON = paramJsonObject.getJSONObject("PARAM");
										String PARAM_NM = TemporaryParamJSON.getString("PARAM_NM");
										JSONObject obj = new JSONObject();
										obj.put("defaultValue", TemporaryParamJSON.get("DEFAULT_VALUE"));
										obj.put("name", TemporaryParamJSON.get("PARAM_CAPTION"));
										obj.put("paramName", TemporaryParamJSON.get("PARAM_NM"));
										obj.put("parameterType", TemporaryParamJSON.get("DATA_TYPE"));
										obj.put("type", TemporaryParamJSON.get("PARAM_TYPE"));
										obj.put("value", TemporaryParamJSON.get("DEFAULT_VALUE"));
										obj.put("whereClause", TemporaryParamJSON.get("WHERE_CLAUSE"));
										JSONObject paramElement = new JSONObject();
										paramElement.put(PARAM_NM, obj);
										paramItems.add(paramElement);
//										paramItems.add(PARAM_NM);
									}else {
										JSONArray paramArr = paramJsonObject.getJSONArray("PARAM");
										for(int i=0;i<paramArr.size();i++) {
											String PARAM_JSON_STR = paramArr.getJSONObject(i).getString("PARAM_NM");
											JSONObject obj = new JSONObject();
											obj.put("defaultValue", paramArr.getJSONObject(i).get("DEFAULT_VALUE"));
											obj.put("name", paramArr.getJSONObject(i).get("PARAM_CAPTION"));
											obj.put("paramName", paramArr.getJSONObject(i).get("PARAM_NM"));
											obj.put("parameterType", paramArr.getJSONObject(i).get("DATA_TYPE"));
											obj.put("type", paramArr.getJSONObject(i).get("PARAM_TYPE"));
											obj.put("value", paramArr.getJSONObject(i).get("DEFAULT_VALUE"));
											obj.put("whereClause", paramArr.getJSONObject(i).get("WHERE_CLAUSE"));
											JSONObject paramElement = new JSONObject();
											paramElement.put(PARAM_JSON_STR, obj);
											paramItems.add(paramElement);
										}
									}
									datasetElementList.getJSONObject(x0).put("param_element", paramItems);
								}
							}
							
//							JSONObject paramJsonObject = datasetElementList.getJSONObject(x0).getJSONObject("DATASET_JSON").getJSONObject("DATA_SET").getJSONObject("PARAM_ELEMENT");
							
						}else {
							datasetElementList.getJSONObject(x0).put("param_element", new JSONArray());
						}
						// ((JSONObject) datasetElementList.get(x0)).remove("DATASET_XML");
					}
				} else {
					datasetElementList = new JSONArray();
				}
			} else {
				if (datasetJson.get("DATA_SET") instanceof JSONObject) {
					JSONObject tmpJson = datasetJson.getJSONObject("DATA_SET");
					tmpJson.put("DATASET_TYPE", this.getDATASET_TYPE());
					tmpJson.put("DATASRC_TYPE", this.getDATASRC_TYPE());
					tmpJson.put("DATASRC_ID", this.getDATASRC_ID());
					if(this.getDATASET_TYPE().equals("DataSetSQL") && !this.getREPORT_TYPE().equals("DashAny")) {
						tmpJson.remove("DATASET_QUERY");
						tmpJson.put("DATASET_QUERY", this.getDATASET_QUERY());
					}
					
					// tmpJson.remove("DATASET_XML");

					datasetElementList = new JSONArray();
					datasetElementList.add(tmpJson);
				} else {
					datasetElementList = new JSONArray();
				}
			}

			for (int x0 = 0; x0 < datasetElementList.size(); x0++) {
				((JSONObject) datasetElementList.get(x0)).put("wise_sql_id", this.REPORT_ID + "-" + x0);
			}

			datasetJson.put("DATASET_ELEMENT", datasetElementList);

			basicInfo.put("datasetJson", datasetJson);
		}

		Object paramJsonObject = this.getParamJson();
		if ((paramJsonObject instanceof JSONArray && ((JSONArray) this.getParamJson()).isEmpty())
				|| (paramJsonObject instanceof JSONObject && ((JSONObject) this.getParamJson()).isNullObject())) {
			// basicInfo.put("paramJson", "");
			basicInfo.put("paramJson", new JSONArray());
		} else {
			basicInfo.put("paramJson", this.getParamJson());
		}

		return JSONObject.fromObject(basicInfo);
	}
	
	/* DOGFOOT shlim reportmstr dsid 변경  20200309 */
	public String getDECODE_DATASET() {
		return DECODE_DATASET;
	}

	public void setDECODE_DATASET(String dECODE_DATASET) {
		this.DECODE_DATASET = dECODE_DATASET;
	}

	public String getDECODE_PARAM() {
		return DECODE_PARAM;
	}

	public void setDECODE_PARAM(String dECODE_PARAM) {
		this.DECODE_PARAM = dECODE_PARAM;
	}
	
	public int getDECODE_REPORT_ID() {
		return DECODE_REPORT_ID;
	}

	public void setDECODE_REPORT_ID(int dECODE_REPORT_ID) {
		this.DECODE_REPORT_ID = dECODE_REPORT_ID;
	}

	public String getLAYOUT_CONFIG() {
		return LAYOUT_CONFIG;
	}

	public void setLAYOUT_CONFIG(String lAYOUT_CONFIG) {
		LAYOUT_CONFIG = lAYOUT_CONFIG;
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
				+ layoutXml_decoded + ", datasetXml_decoded=" + datasetXml_decoded + ", paramXml_decoded="
				+ paramXml_decoded + ", REG_USER_NO=" + REG_USER_NO + ", PROMPT_YN=" + PROMPT_YN + ", datasetJson="
				+ datasetJson + ", paramJson=" + paramJson + ", MOD_USER_NO=" + MOD_USER_NO + ", chartXml_decoded="
				+ chartXml_decoded + ", chartXml=" + CHART_XML + ", chartJson=" + chartJson + ", xmlSerializer="
				+ xmlSerializer + "]";
	}

	public String getDECODE_REPORT() {
		return DECODE_REPORT;
	}

	public void setDECODE_REPORT(String dECODE_REPORT) {
		DECODE_REPORT = dECODE_REPORT;
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
