package com.wise.ds.repository.service.impl;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigDecimal;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.swing.text.BadLocationException;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.XML;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.github.rcaller.rstuff.RCaller;
import com.github.rcaller.rstuff.RCallerOptions;
import com.github.rcaller.rstuff.RCode;
import com.github.signaflo.timeseries.TimePeriod;
import com.github.signaflo.timeseries.TimeSeries;
import com.github.signaflo.timeseries.forecast.Forecast;
import com.github.signaflo.timeseries.model.arima.Arima;
import com.github.signaflo.timeseries.model.arima.ArimaOrder;
import com.wise.authn.User;
import com.wise.authn.dao.AuthenticationDAO;
import com.wise.common.util.CloseableList;
import com.wise.common.util.FileBackedJSONObjectList;
import com.wise.context.config.Configurator;
import com.wise.ds.repository.CubeHieMasterVO;
import com.wise.ds.repository.CubeMember;
import com.wise.ds.repository.CubeTableVO;
import com.wise.ds.repository.DSViewColVO;
import com.wise.ds.repository.DSViewHieVO;
import com.wise.ds.repository.DrillThruColumnVO;
import com.wise.ds.repository.ParamScheduleVO;
import com.wise.ds.repository.ReportFieldMasterVO;
import com.wise.ds.repository.ReportLogDetailMasterVO;
import com.wise.ds.repository.ReportLogMasterVO;
import com.wise.ds.repository.ReportMasterHisVO;
import com.wise.ds.repository.ReportMasterVO;
import com.wise.ds.repository.ReportParamVO;
import com.wise.ds.repository.ReportScheduleVO;
import com.wise.ds.repository.ReportSubLinkVO;
import com.wise.ds.repository.UploadHisVO;
import com.wise.ds.repository.UserGrpAuthReportListVO;
import com.wise.ds.repository.UserUploadMstrVO;
import com.wise.ds.repository.dao.ReportDAO;
import com.wise.ds.repository.service.DataSetService;
import com.wise.ds.repository.service.ReportService;
import com.wise.ds.sql.CubeTableColumn;
import com.wise.ds.statics.Analysis;
import com.wise.ds.util.Json2Xml;

import net.sf.json.JSONArray;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 *     수정일                 수정자             수정내용   
 *  ----------    --------    ---------------------------
 *  2015.06.08      DOGFOOT             최초 생성
 * </pre>
 */

@Service("reportService")
public class ReportServiceImpl implements ReportService {
    final static private Logger logger = LoggerFactory.getLogger(ReportServiceImpl.class);
    
    @Resource(name = "reportDAO")
    private ReportDAO reportDAO;
    
    @Resource(name = "authenticationDAO")
    private AuthenticationDAO authenticationDAO;
    
    @Autowired 
	private Json2Xml json2xml;
    
    @Autowired
	private DataSetService dataSetServiceImpl;
    
    @Override
	public ReportMasterVO selectReportBasicInformation(int reportId, String reportType) {
		// TODO Auto-generated method stub
//    	Map<String, Comparable> param = new HashMap<String, Comparable>();
//		param.put("P_PARAM", 0);
//		param.put("REPORT_ID",reportId);
//		param.put("REPORT_TYPE", reportType);
//		param.put("FLD_TYPE", "PUBLIC");
//		param.put("FLD_ID", "");
//		param.put("USER_NO", "");
        ReportParamVO param = new ReportParamVO();
        /* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
        param.setP_PARAM("99");
        param.setREPORT_ID(String.valueOf(reportId));
        param.setREPORT_TYPE(reportType);
        param.setFLD_TYPE("PUBLIC");
//        param.setFLD_ID("");
//        param.setUSER_NO("");
        
    	
		ReportMasterVO ret = this.reportDAO.select(param);
		return ret;
		
	}
    
    @Override
    public ReportMasterVO selectReportBasicInformation(int reportId, String reportType, String fldType) {
    	ReportParamVO param = new ReportParamVO();
    	/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
    	param.setP_PARAM("99");
    	param.setREPORT_ID(String.valueOf(reportId));
    	param.setREPORT_TYPE(reportType);
    	param.setFLD_TYPE(fldType);
     	
 		ReportMasterVO ret = this.reportDAO.select(param);
 		return ret;
	}
    /* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
    @Override
	public ReportMasterVO selectReportBasicInformationHis(int reportId, String reportType, String fldType, String reportSeq) {
    	ReportMasterHisVO param = new ReportMasterHisVO();
		param.setREPORT_ID(String.valueOf(reportId));
		param.setREPORT_TYPE(reportType);
		param.setREPORT_SEQ(Integer.parseInt(reportSeq));
		
		ReportMasterVO ret;
	    ret = this.reportDAO.selectHis(param);  
		
		return ret;
	}
    
	@Override
	public ReportMasterVO selectReportBasicInformationExceptLayout(int reportId, String reportType) {
		// TODO Auto-generated method stub
		ReportMasterVO param = new ReportMasterVO();
		param.setREPORT_ID(String.valueOf(reportId));
		param.setREPORT_TYPE(reportType);
		
		ReportMasterVO ret;
	    ret = this.reportDAO.selectExceptLayout(param);  
		
		return ret;
	}
	
	/* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
	@Override
	public ReportMasterVO selectReportBasicInformationExceptLayoutHis(int reportId, String reportType, String reportSeq) {
		// TODO Auto-generated method stub
		ReportMasterHisVO param = new ReportMasterHisVO();
		param.setREPORT_ID(String.valueOf(reportId));
		param.setREPORT_TYPE(reportType);
		param.setREPORT_SEQ(Integer.parseInt(reportSeq));
		
		ReportMasterVO ret;
	    ret = this.reportDAO.selectExceptLayoutHis(param);  
		
		return ret;
	}
	
	@Override
	public ReportMasterVO selectReportParam(int reportId) {
		// TODO Auto-generated method stub
		ReportMasterVO param = new ReportMasterVO();
		param.setREPORT_ID(String.valueOf(reportId));
		
		ReportMasterVO ret;
	    ret = this.reportDAO.selectReportParam(param);  
		
		return ret;
	}

	@Override
	public ReportMasterVO selectReportForLog(int reportId, String wiseReportType) {
		// TODO Auto-generated method stub
		ReportMasterVO param = new ReportMasterVO();
		param.setREPORT_ID(String.valueOf(reportId));
		param.setREPORT_TYPE(wiseReportType);
		ReportMasterVO ret;
	    ret = this.reportDAO.selectReportForLog(param);  
		return ret;
	}
	
	@Override
	public void enrollReportUseLog(boolean UseLog,ReportLogMasterVO logVO) {
		// TODO Auto-generated method stub
		if(UseLog) {
			int result = this.reportDAO.insertReportUseLog(logVO);
		}
	}
	
	@Override
	public void enrollReportQueryLog(boolean logUse, ReportLogMasterVO logVo) {
		// TODO Auto-generated method stub
		if(logUse) {
			int result = this.reportDAO.insertReportQueryLog(logVo);
		}
	}

	@Override
	public void enrollReportExportLog(boolean logUse, ReportLogMasterVO logVo) {
		// TODO Auto-generated method stub
		if(logUse) {
			int result = this.reportDAO.insertReportExportLog(logVo);
		}
	}
	@Override
	public void enrollReportPrintLog(boolean logUse, ReportLogMasterVO logVo) {
		// TODO Auto-generated method stub
		if(logUse) {
			int result = this.reportDAO.insertReportPrintLog(logVo);
		}
	}
	
	@Override
	public List<ReportSubLinkVO> selectReportSubLink(int reportId) {
		// TODO Auto-generated method stub
		List<ReportSubLinkVO> result = this.reportDAO.selectReportSubLink(reportId);
		return result;
	}
	
	@Override
	public List<ReportSubLinkVO> selectReportLink(int reportId) {
		// TODO Auto-generated method stub
		List<ReportSubLinkVO> result = this.reportDAO.selectReportLink(reportId);
		return result;
	}
	
	@Override
	public void insertLinkReport(ReportSubLinkVO reportSubLinkVo) {
			int result = this.reportDAO.insertLinkReport(reportSubLinkVo);
	}
	
	@Override
	public void insertSubLinkReport(ReportSubLinkVO reportSubLinkVo) {
			int result = this.reportDAO.insertSubLinkReport(reportSubLinkVo);
	}

	@Override
	public JSONObject callUpReportMstrACT(JSONObject obj,String remoteAddr) {
		// TODO Auto-generated method stub
//		Map<String, Comparable> param = new HashMap<String, Comparable>();
		ReportParamVO param = new ReportParamVO();
		boolean checkExceltion = true;
		String layoutXmlString ="";
		String paramXmlString = "";
		String dataSetXmlString = "";
		try {
			// KERIS 수정
			layoutXmlString = this.json2xml.sortLayoutXml(obj.getJSONObject("layout_xml"), remoteAddr);
			paramXmlString = this.json2xml.sortParamXml(obj.getJSONObject("param_xml"));
			dataSetXmlString = this.json2xml.sortDataSetXml(obj.getJSONObject("dataset_xml"), obj.getJSONObject("param_xml"), obj.getJSONObject("reportItemList"), false);
		} catch (IOException e) {
			e.printStackTrace();
			checkExceltion=false;
		} catch (BadLocationException ble) {
			ble.printStackTrace();
			checkExceltion=false;
		}
		
		String reportOrdinal = obj.getString("report_ordinal");
		logger.debug(layoutXmlString);
		String userNo = "";
		User user = this.authenticationDAO.selectRepositoryUserByUserId(obj.getString("userid"));
		if (user != null) {
			//2020.02.04 mksong 사용자번호 등록 오류 수정 dogfoot
			userNo = user.getUSER_NO()+"";
		}
		
		JSONObject ret = new JSONObject();
//		logger.debug(obj.getJSONObject("dataset_xml").toString());
		if(checkExceltion == true) {
		/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
			param.setP_PARAM("99");
			param.setREPORT_ID(obj.getString("report_id"));
			param.setREPORT_NM(obj.getString("report_nm"));
			param.setFLD_ID(obj.getString("fld_id"));
			param.setFLD_TYPE(obj.getString("fld_type"));
			param.setREPORT_ORDINAL(reportOrdinal.equals("")? "0":reportOrdinal);
//			param.setREPORT_TYPE("DashAny");
			/*dogfoot 통계 분석 추가 shlim 20201102*/
			param.setREPORT_TYPE(obj.getString("report_type"));
			param.setREPORT_TAG(obj.getString("report_tag"));
			param.setREPORT_DESC(obj.getString("report_desc"));
			param.setREPORT_LAYOUT("");
			param.setGRID_INFO("");
			param.setDATASRC_ID("");
			param.setDATASRC_TYPE("");
			param.setDATASET_TYPE("");
			/* DOGFOOT mksong BASE64 오류 수정  20200116 */
			param.setREPORT_XML(new String(java.util.Base64.getEncoder().encode(obj.getString("report_xml").getBytes())));
			param.setCHART_XML(new String(java.util.Base64.getEncoder().encode(XML.toString(obj.getJSONObject("chart_xml")).getBytes())));
			param.setLAYOUT_XML(new String(java.util.Base64.getEncoder().encode(layoutXmlString.getBytes())));
			param.setDATASET_XML(new String(java.util.Base64.getEncoder().encode(dataSetXmlString.getBytes())));
			param.setPARAM_XML(new String(java.util.Base64.getEncoder().encode(paramXmlString.getBytes())));
			param.setDATASET_QUERY("");
			param.setREG_USER_NO(userNo);
//			param.put("REG_USER_NO", "1001");
			param.setDEL_YN("N");
			param.setPROMPT_YN("N");
			param.setREPORT_SUB_TITLE("");//obj.getString("report_desc"));
//			param.put("MOD_USER_NO", obj.getString("userid"));
//			param.put("MOD_USER_NO", "1001");
			param.setMOD_USER_NO(userNo);
			param.setPRIVACY_YN("N");
			/* DOGFOOT syjin LAYOUT_CONFIG 추가  20200814 */
			param.setLAYOUT_CONFIG(obj.getString("layout_config"));
			param.setDIRECT_VIEW(obj.getString("direct_view"));
			
			
			ReportMasterVO vo = this.reportDAO.callUpReportMstrACT(param);
			if(vo != null) {
				ret.put("reportId", vo.getREPORT_ID());
				ret.put("layoutXmlString", layoutXmlString.substring(1));
				if(vo.getREPORT_ORDINAL() == null) {
					ret.put("reportOrdinal", reportOrdinal);
				}else {
					ret.put("reportOrdinal", vo.getREPORT_ORDINAL());
				}
				
			}
			
			//20200709 AJKIM 연결보고서 다른 이름 저장시 reportId가 원래 보고서의 id로 저장되는 오류 수정 dogfoot
			if(obj.getJSONArray("linkReport") != null && obj.getJSONArray("linkReport").length() > 0) {
				this.reportDAO.deleteReportLink(vo.getREPORT_ID());
				String linkXml = "";
				for(int i = 0; i < obj.getJSONArray("linkReport").length(); i++) {
					ReportSubLinkVO linkReport = new ReportSubLinkVO();
					JSONObject linkJson = obj.getJSONArray("linkReport").getJSONObject(i);
					
					try {
						// 2020.02.04 mksong 연결보고서 저장 오류 수정 dogfoot
						if(!linkJson.get("linkJson").equals("")) {
							linkXml = this.json2xml.sortLinkReportXml(linkJson.getJSONObject("linkJson"));
							linkReport.setLink_xml(new String(java.util.Base64.getEncoder().encode(linkXml.getBytes())));
						}else {
							linkXml = "";
							linkReport.setLink_xml(linkXml);
						}
						
					} catch (IOException e) {
						e.printStackTrace();
					}
					
					linkReport.setArg_id(vo.getREPORT_ID());
					/* DOGFOOT mksong BASE64 오류 수정  20200116 */
					linkReport.setLink_report_ordinal(0);
					linkReport.setLink_type(linkJson.getString("link_type"));
					linkReport.setTarget_id(String.valueOf(linkJson.getInt("target_id")));
					linkReport.setTarget_type(linkJson.getString("target_type"));
					
					this.reportDAO.insertLinkReport(linkReport);
				}
			} else {
				String del_report_id = vo.getREPORT_ID();
				if(!"".equals(del_report_id)) this.reportDAO.deleteReportLink(del_report_id);
			}
			
			if(obj.getJSONArray("subLinkReport") != null && obj.getJSONArray("subLinkReport").length() > 0) {
				String linkXml = "";
				String linkXml2 = "";
				for(int i = 0; i < obj.getJSONArray("subLinkReport").length(); i++) {
					ReportSubLinkVO linkReport = new ReportSubLinkVO();
					JSONObject linkJson = obj.getJSONArray("subLinkReport").getJSONObject(i);
					int seq = 0;
					
					try {
						// 2020.02.04 mksong 연결보고서 저장 오류 수정 dogfoot
						if(!linkJson.get("linkJson").equals("")) {
							linkXml = this.json2xml.sortSubLinkReportXml(linkJson.getJSONObject("linkJson"));
							linkReport.setLink_xml(new String(java.util.Base64.getEncoder().encode(linkXml.getBytes())));
						}else {
							linkXml = "";
							linkReport.setLink_xml(linkXml);
						}
						
					} catch (IOException e) {
						e.printStackTrace();
					}
					
					try {
						// 2020.02.04 mksong 연결보고서 저장 오류 수정 dogfoot
						if(!linkJson.get("linkJson").equals("")) {
							linkXml2 = this.json2xml.sortSubLinkReportDataXml(linkJson.getJSONObject("linkJson2"));
							linkReport.setLink_xml2(new String(java.util.Base64.getEncoder().encode(linkXml2.getBytes())));
						}else {
							linkXml2 = "";
							linkReport.setLink_xml2(linkXml2);
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
					
					linkReport.setArg_id(vo.getREPORT_ID());
					/* DOGFOOT mksong BASE64 오류 수정  20200116 */
					linkReport.setLink_xml(new String(java.util.Base64.getEncoder().encode(linkXml.getBytes())));
					linkReport.setLink_xml2(new String(java.util.Base64.getEncoder().encode(linkXml2.getBytes())));
					linkReport.setLink_report_ordinal(0);
					linkReport.setLink_type(linkJson.getString("link_type"));
					linkReport.setTarget_id(String.valueOf(linkJson.getInt("target_id")));
					linkReport.setTarget_type(linkJson.getString("target_type"));
					linkReport.setTarget_item(linkJson.getString("target_item"));
					
					/* DOGFOOT mksong SEQ NULLPOINTER 오류 수정 20200117 */
					ReportSubLinkVO subLinkVo = this.reportDAO.selectLinkSubReportYn(linkReport);
					if(subLinkVo == null) {
						seq = this.reportDAO.selectLinkSubReportSeq();
						linkReport.setSEQ(seq+1);
						this.reportDAO.insertSubLinkReport(linkReport);
					}else {
						seq = subLinkVo.getSEQ();
						linkReport.setSEQ(seq);
						this.reportDAO.updateSubLinkReport(linkReport);
					}
				}
			} else {
				String del_report_id = vo.getREPORT_ID();
				if(!"".equals(del_report_id)) this.reportDAO.deleteReportSubLink(vo.getREPORT_ID());
			}
		}
		
		return ret;
	}
	
	@Override
	public JSONObject callUpAdhocReportMstrACT(JSONObject obj,String remoteAddr) {
		// TODO Auto-generated method stub
//		Map<String, Comparable> param = new HashMap<String, Comparable>();
		ReportParamVO param = new ReportParamVO();
		boolean checkExceltion = true;
		String paramXmlString = "";
		String dataSetXmlString = "";
		ReportMasterVO vo = null;
		
		try {
			paramXmlString = this.json2xml.sortParamXml(obj.getJSONObject("param_xml"));
			dataSetXmlString = this.json2xml.sortDataSetXml(obj.getJSONObject("dataset_xml"), obj.getJSONObject("param_xml"), obj.getJSONObject("reportItemList"), false);
		} catch (IOException e) {
			checkExceltion=false;
			e.printStackTrace();
		}
		
		
		
		String reportOrdinal = obj.getString("report_ordinal");
		String userNo = "";
		User user = this.authenticationDAO.selectRepositoryUserByUserId(obj.getString("userid"));
		if (user != null) {
			//2020.02.04 mksong 사용자번호 등록 오류 수정 dogfoot
			userNo = user.getUSER_NO()+"";
		}
		
		JSONObject ret = new JSONObject();
//		logger.debug(obj.getJSONObject("dataset_xml").toString());
		if(checkExceltion == true) {
		/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
			param.setP_PARAM("99");
			if(obj.get("report_id") instanceof Integer) {
//				param.put("REPORT_ID", obj.getInt("report_id"));
				param.setREPORT_ID(obj.getInt("report_id")+"");
			}else {
				param.setREPORT_ID(obj.getString("report_id"));
			}
			param.setREPORT_NM(obj.getString("report_nm"));
			param.setFLD_ID(obj.getInt("fld_id")+"");
			param.setFLD_TYPE(obj.getString("fld_type"));
			param.setREPORT_ORDINAL(reportOrdinal);
			param.setREPORT_TYPE(obj.getString("report_type"));
			param.setREPORT_TAG(obj.getString("report_tag"));
			param.setREPORT_DESC(obj.getString("report_desc"));
			param.setREPORT_LAYOUT(obj.getString("report_layout"));
			param.setGRID_INFO("");
			String datasrc_id = obj.getString("datasrc_id");
			if(datasrc_id.indexOf(",")>-1) {
				String[] datasrcIdArr = datasrc_id.split(",");
				datasrc_id = datasrcIdArr[0];
			}
			param.setDATASRC_ID(datasrc_id);
			param.setDATASRC_TYPE(obj.getString("datasrc_type"));
			param.setDATASET_TYPE(obj.getString("dataset_type"));
			/* DOGFOOT mksong BASE64 오류 수정  20200116 */
			param.setREPORT_XML(new String(java.util.Base64.getEncoder().encode(XML.toString(obj.getJSONObject("report_xml")).getBytes())));
			param.setCHART_XML(new String(java.util.Base64.getEncoder().encode(XML.toString(obj.getJSONObject("chart_xml")).getBytes())));
			param.setLAYOUT_XML("");
			param.setDATASET_XML(new String(java.util.Base64.getEncoder().encode(dataSetXmlString.getBytes())));
			param.setPARAM_XML(new String(java.util.Base64.getEncoder().encode(paramXmlString.getBytes())));
			param.setDATASET_QUERY(new String(java.util.Base64.getEncoder().encode(obj.getString("dataset_query").getBytes())));
			param.setREG_USER_NO(userNo);
			param.setDEL_YN("N");
			param.setPROMPT_YN(obj.getString("prompt_yn"));
			param.setREPORT_SUB_TITLE(obj.getString("report_sub_title"));	
			param.setMOD_USER_NO(userNo);
			param.setPRIVACY_YN("N");
			/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
			/* DOGFOOT ajkim 보고서별 LAYOUT_CONFIG JsonObject일 경우에만 저장하도록 수정 20200819*/
			/*dogfoot shlim 20210415*/
			param.setLAYOUT_CONFIG(obj.getString("layout_config"));
			param.setDIRECT_VIEW(obj.getString("direct_view"));
			
			vo = this.reportDAO.callUpReportMstrACT(param);
			ret.put("reportId", vo.getREPORT_ID());
			ret.put("reportOrdinal", vo.getREPORT_ORDINAL());
		}
		
		/* DOGFOOT ktkang 주제영역 데이터 불러오기 기능 수정  20191212 */
		if(obj.has("linkReport") && obj.getJSONArray("linkReport").length() > 0) {
			String linkXml = "";
			this.reportDAO.deleteReportLink(vo.getREPORT_ID());
			for(int i = 0; i < obj.getJSONArray("linkReport").length(); i++) {
				ReportSubLinkVO linkReport = new ReportSubLinkVO();
				JSONObject linkJson = obj.getJSONArray("linkReport").getJSONObject(i);
				
				try {
					if(!linkJson.get("linkJson").equals("")) {
						linkXml = this.json2xml.sortLinkReportXml(linkJson.getJSONObject("linkJson"));
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
				
				linkReport.setArg_id(vo.getREPORT_ID());
				/* DOGFOOT mksong BASE64 오류 수정  20200116 */
				linkReport.setLink_xml(new String(java.util.Base64.getEncoder().encode(linkXml.getBytes())));
				linkReport.setLink_report_ordinal(0);
				linkReport.setLink_type(linkJson.getString("link_type"));
				linkReport.setTarget_id(String.valueOf(linkJson.getInt("target_id")));
				linkReport.setTarget_type(linkJson.getString("target_type"));
				
				this.reportDAO.insertLinkReport(linkReport);
			}
		} else {
			// this.reportDAO.deleteReportLink(obj.getString("report_id"));
		}
		
		/* DOGFOOT ktkang 주제영역 데이터 불러오기 기능 수정  20191212 */
		if(obj.has("subLinkReport") && obj.getJSONArray("subLinkReport").length() > 0) {
			String linkXml = "";
			String linkXml2 = "";
			for(int i = 0; i < obj.getJSONArray("subLinkReport").length(); i++) {
				ReportSubLinkVO linkReport = new ReportSubLinkVO();
				JSONObject linkJson = obj.getJSONArray("subLinkReport").getJSONObject(i);
				int seq = 0;
				
				try {
					linkXml = this.json2xml.sortSubLinkReportXml(linkJson.getJSONObject("linkJson"));
					linkXml2 = this.json2xml.sortSubLinkReportDataXml(linkJson.getJSONObject("linkJson2"));
				} catch (IOException e) {
					e.printStackTrace();
				}
				
				linkReport.setArg_id(String.valueOf(linkJson.getInt("arg_id")));
				/* DOGFOOT mksong BASE64 오류 수정  20200116 */
				linkReport.setLink_xml(new String(java.util.Base64.getEncoder().encode(linkXml.getBytes())));
				linkReport.setLink_xml2(new String(java.util.Base64.getEncoder().encode(linkXml2.getBytes())));
				linkReport.setLink_report_ordinal(0);
				linkReport.setLink_type(linkJson.getString("link_type"));
				linkReport.setTarget_id(String.valueOf(linkJson.getInt("target_id")));
				linkReport.setTarget_type(linkJson.getString("target_type"));
				linkReport.setTarget_item(linkJson.getString("target_item"));
				
				
				ReportSubLinkVO subLink = this.reportDAO.selectLinkSubReportYn(linkReport);
				if(subLink!=null) {
					seq = subLink.getSEQ();
				}
				linkReport.setSEQ(seq);
				
				if(seq > 0) {
					this.reportDAO.updateSubLinkReport(linkReport);
				} else {
					this.reportDAO.insertSubLinkReport(linkReport);
				}
			}
		} else {
			//this.reportDAO.deleteReportSubLink(obj.getString("report_id"));
		}
		
		
		return ret;
	}
	
	@Override
	public JSONObject callUpSpreadReportMstrACT(JSONObject obj,String remoteAddr) {
		// TODO Auto-generated method stub
//		Map<String, Comparable> param = new HashMap<String, Comparable>();
		ReportParamVO param = new ReportParamVO();
		boolean checkExceltion = true;
		String paramXmlString = "";
		String dataSetXmlString = "";
		
		try {
			paramXmlString = this.json2xml.sortParamXml(obj.getJSONObject("param_xml"));
			if(obj.getJSONObject("dataset_xml").length() > 0) {
				dataSetXmlString = this.json2xml.sortDataSetXml(obj.getJSONObject("dataset_xml"), obj.getJSONObject("param_xml"), obj.getJSONObject("reportItemList"), true);
			}
			
		} catch (IOException e) {
			checkExceltion=false;
			e.printStackTrace();
		}
		String reportOrdinal = obj.getString("report_ordinal");
		String userNo = "";
		User user = this.authenticationDAO.selectRepositoryUserByUserId(obj.getString("userid"));
		if (user != null) {
			//2020.02.04 mksong 사용자번호 등록 오류 수정 dogfoot
			userNo = user.getUSER_NO()+"";
		}
		
		JSONObject ret = new JSONObject();
		ReportMasterVO vo = null;
//		logger.debug(obj.getJSONObject("dataset_xml").toString());
		if(checkExceltion == true) {
		/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
			param.setP_PARAM("99");
			if(obj.get("report_id") instanceof Integer) {
//				param.put("REPORT_ID", obj.getInt("report_id"));
				param.setREPORT_ID(obj.getInt("report_id")+"");
			}else {
				param.setREPORT_ID(obj.getString("report_id"));
			}
			param.setREPORT_NM(obj.getString("report_nm"));
			param.setFLD_ID(obj.getInt("fld_id")+"");
			param.setFLD_TYPE(obj.getString("fld_type"));
			param.setREPORT_ORDINAL(reportOrdinal);
			param.setREPORT_TYPE(obj.getString("report_type"));
			param.setREPORT_TAG(obj.getString("report_tag"));
			param.setREPORT_DESC(obj.getString("report_desc"));
			param.setREPORT_LAYOUT(obj.getString("report_layout"));
			param.setGRID_INFO("");
			/* DOGFOOT ktkang 저장 에러 수정  20200904 */
			param.setDATASRC_ID(obj.getString("datasrc_id"));
			param.setDATASRC_TYPE(obj.getString("datasrc_type"));
			param.setDATASET_TYPE(obj.getString("dataset_type"));
			/* DOGFOOT mksong BASE64 오류 수정  20200116 */
			param.setREPORT_XML(new String(java.util.Base64.getEncoder().encode(obj.getString("report_xml").getBytes())));
			param.setCHART_XML("");
			param.setLAYOUT_XML("");
			param.setDATASET_XML(new String(java.util.Base64.getEncoder().encode(dataSetXmlString.getBytes())));
			param.setPARAM_XML(new String(java.util.Base64.getEncoder().encode(paramXmlString.getBytes())));
			param.setDATASET_QUERY(new String(java.util.Base64.getEncoder().encode(obj.getString("dataset_query").getBytes())));
			param.setREG_USER_NO(userNo);
			param.setDEL_YN("N");
			param.setPROMPT_YN(obj.getString("prompt_yn"));
			param.setREPORT_SUB_TITLE(obj.getString("report_sub_title"));	
			param.setMOD_USER_NO(userNo);
			param.setPRIVACY_YN("N");
			/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
			/*dogfoot 스프레드시트 저장 오류 수정 shlim 20200821*/
			param.setLAYOUT_CONFIG(obj.getString("layout_config"));
			param.setDIRECT_VIEW(obj.getString("direct_view"));
			
			vo = this.reportDAO.callUpReportMstrACT(param);
			ret.put("reportId", vo.getREPORT_ID());
			ret.put("reportOrdinal", vo.getREPORT_ORDINAL());
		}
		
		
		return ret;
	}
	
	@Override
	public List<ReportScheduleVO> selectReportScheduleList(ReportScheduleVO param) {
		return this.reportDAO.selectReportScheduleList(param);
	}

	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
	@Override
	public List<ReportScheduleVO> selectReportScheduleAllList() {
		return this.reportDAO.selectReportScheduleAllList();
	}
	
	@Override
	public List<ReportScheduleVO> selectReportScheduleAllList2() {
		return this.reportDAO.selectReportScheduleAllList2();
	}
	
	
	@Override
	public void insertReportSchedule(ReportScheduleVO param) {
		int result = this.reportDAO.insertReportSchedule(param);
	}
	
	public void deleteReportSchedule(ReportScheduleVO param) {
		int result = this.reportDAO.deleteReportSchedule(param);
	}

	public void deleteReportScheduleAll(ReportScheduleVO param) {
		int result = this.reportDAO.deleteReportScheduleAll(param);
	}

	@Override
	public void deleteReportScheduleAndData(ReportScheduleVO param) {
		int result = this.reportDAO.deleteReportScheduleAndData(param);
	}

	@Override
	public String checkReport(String reportNm,String fldId) {
		// TODO Auto-generated method stub
		ReportMasterVO param = new ReportMasterVO();
		param.setREPORT_NM(reportNm);
		param.setFLD_ID(fldId);
		String result = this.reportDAO.selectReportName(param);
		return result;
	}

	@Override
	public int insertReport(ReportMasterVO reportMaster) {
		// TODO Auto-generated method stub
		return this.reportDAO.insertReport(reportMaster);
	}

	@Override
	public void insertReportDetail(boolean logUse, ReportLogDetailMasterVO logdetail) {
		// TODO Auto-generated method stub
		if(logUse) {
			int result = this.reportDAO.insertReportDetail(logdetail);
		}
		
	}
	
	@Override
	public void updateReportUseLog(boolean logUse, ReportLogMasterVO vo) {
		// TODO Auto-generated method stub
		if(logUse) {
			int result = this.reportDAO.updateReportUseLog(vo);
		}
		
	}

	@Override
	public void updateReportLogDetail(boolean logUse, ReportLogMasterVO vo) {
		// TODO Auto-generated method stub
		if(logUse) {
			int result = this.reportDAO.updateReportLogDetail(vo);
		}
	}

	@Override
	public int updateReportLogDetailError(int interval) {
		return this.reportDAO.updateReportLogDetailError(interval);
	}
	
	@Override
	public int getReportLogCleanHour() {
		return this.reportDAO.getReportLogCleanHour();
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	@Override
	public ReportMasterVO selectReportType(String pid) {
		// TODO Auto-generated method stub
		return this.reportDAO.selectReportType(pid);
	}

	@Override
	public void insertUserUpload(UserUploadMstrVO uploadVo) {
		// TODO Auto-generated method stub
		this.reportDAO.insertUserUpload(uploadVo);
	}

	@Override
	public UploadHisVO selectHisUpload(UploadHisVO getseq) {
		// TODO Auto-generated method stub
		return this.reportDAO.selectHisUpload(getseq);
	}

	@Override
	public void insertUserUploadHis(UploadHisVO hisVo) {
		// TODO Auto-generated method stub
		this.reportDAO.insertUserUploadHis(hisVo);
	}

	@Override
	public List<UserUploadMstrVO> selectUserUpload(int dataSourceId) {
		// TODO Auto-generated method stub
		return this.reportDAO.selectUserUpload(dataSourceId);
	}

	@Override
    public List<DrillThruColumnVO> selectDrillThruCategoryList(int cubeId) {
        return this.reportDAO.selectDrillThruCategoryList(cubeId);
    }
	
	/* DOGFOOT ktkang KERIS 보고서 별 필드 정보 추가기능  20200123 */
	@Override
	public List<ReportFieldMasterVO> selectReportFieldList(int reportId) {
        return this.reportDAO.selectReportFieldList(reportId);
    }
	
	@Override
	public void deleteReportFieldList(int reportId) {
		this.reportDAO.deleteReportFieldList(reportId);
    }
	
	/* DOGFOOT ktkang KERIS 보고서 별 필드 정보 추가기능  수정 끝 20200123 */
	@Override
	public void insertReportField(ReportFieldMasterVO reportField) {
		this.reportDAO.insertReportField(reportField);
    }
	
	/* DOGFOOT ktkang KERIS EDS포탈에서 보여주는 보고서 체크 기능  20200205 */
	@Override
	public List<ReportParamVO> selectPotalReportList() {
		return this.reportDAO.selectPotalReportList();
	}
	
	/* DOGFOOT ktkang 주제영역 필터 기본값 추가 기능  20200207 */
	@Override
	public List<CubeTableColumn> selectCubeColumnInfomationList(CubeTableVO cubeTable) {
		return this.reportDAO.selectCubeColumnInfomationList(cubeTable);
	}
	/* DOGFOOT syjin 시계열분석 R 가공 데이터 */
	public List<LinkedHashMap<String, Object>> getTimeSeriesRForecast(
			List<LinkedHashMap<String, Object>> list,
			List<LinkedHashMap<String, Object>> measureInfoList,
			List<LinkedHashMap<String, Object>> seriesDimensionInfoList,
			Map<String, Object> params, int dataType) {
		
		int[][] pdq = {  
				{0, 0, 0}, {0, 0, 1}, {0, 0, 2}, {0, 1, 0}, {0, 1, 1}, {0, 1, 2}, {0, 2, 0}, {0, 2, 1}, {0, 2, 2},
				{1, 0, 0}, {1, 0, 1}, {1, 0, 2}, {1, 1, 0}, {1, 1, 1}, {1, 1, 2}, {1, 2, 0}, {1, 2, 1}, {1, 2, 2},
				{2, 0, 0}, {2, 0, 1}, {2, 0, 2}, {2, 1, 0}, {2, 1, 1}, {2, 1, 2}, {2, 2, 0}, {2, 2, 1}, {2, 2, 2}
			};
			
		String periodType = String.valueOf(params.get("periodType"));
		int timeFrequency = 0;
		int period = Integer.parseInt(String.valueOf(params.get("period")));
		//
		LinkedHashMap<String, Object> entryMap = list.get(0);
		double[][] objArr = new double[entryMap.entrySet().size()][list.size()];
		
		Map<String, Integer> keyMap = new HashMap<>();
		List<OffsetDateTime> dateList = new ArrayList<>();
		
		if(periodType.equals("year")) {
			//DOGFOOT syjin 시계열 분석 R코드 추가 20210202
			timeFrequency = 1;
		} else if(periodType.equals("month")) {
			//DOGFOOT syjin 시계열 분석 R코드 추가 20210202
			timeFrequency = 12;
		} 
		
		int keyIdx = 0;
		for(String key : entryMap.keySet()) {
			keyMap.put(key, keyIdx);
			keyIdx++;
		}
		
		//DOGFOOT syjin 시계열 분석 R코드 추가 20210202
		
		int timeYear = 0;
		int timeMonth = 0;
		int timeIndex = 0;
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		
		RCode code2 = RCode.create();
		RCallerOptions options2 = RCallerOptions.create();
		
		if(!seriesDimensionInfoList.isEmpty() && seriesDimensionInfoList.size() > 0) {

			 //차원그룹 有
			List<LinkedHashMap<String, Object>> tempDataList = new ArrayList<>();
			
			ArrayList<Map<String, Double>> measureList = new ArrayList<>();
			LinkedHashMap<String, Integer> measureNameMap = new LinkedHashMap<>();
			for(int i=0; i < measureInfoList.size(); i++) {
				measureNameMap.put(String.valueOf(measureInfoList.get(i).get(dataType == 0 ? "name" : "nameBySummaryType")), i);
			}
			
			ArrayList<Map<String, Object>> seriesDimensionList = new ArrayList<>();
			LinkedHashMap<String, Integer> seriesDimensionNameMap = new LinkedHashMap<>();
			for(int i=0; i < seriesDimensionInfoList.size(); i++) {
				seriesDimensionNameMap.put(String.valueOf(seriesDimensionInfoList.get(i).get("name")), i);
			}
			boolean isBreak = false;			
			boolean rFlag = true;
			String[] forecastDate = new String[period];
			double[] pointForecast = new double[period];
			double[] arima = new double[3];
			
			int order[] = new int[3];
			int printC = 1;
			
			for(LinkedHashMap<String, Object> _map : list) {
				if(isBreak) break;
				dateList = new ArrayList<>();
				measureList = new ArrayList<>();
				seriesDimensionList = new ArrayList<>();
				
				for(LinkedHashMap<String, Object> map : list) {
					
					boolean isMeasureData = false;
					boolean isSeriesDimension = false;
					boolean seriesDimensionChk = true;
					for(String key : seriesDimensionNameMap.keySet()) {
						if(!_map.get(key).equals(map.get(key))) seriesDimensionChk = false;
					}
					if(seriesDimensionChk) {
						for(String key : map.keySet()) {
							if(params.get("dimensionName").equals(key)) {
								String dateStr = String.valueOf(map.get(key)).replaceAll("[^0-9]", "");
								int year = Integer.parseInt(dateStr.substring(0, 4));
								int month = dateStr.length() > 5 ? Integer.parseInt(dateStr.substring(4, 6)) : 1;
								int day = dateStr.length() > 7 ? Integer.parseInt(dateStr.substring(6, 8)) : 1;
								
								if(timeIndex == 0) {
									timeYear = year;
									timeMonth = month;
									
									timeIndex++;
								}
								
								if(periodType.equals("month") && dateStr.length() < 5) {
									month = 12;
								} else if(periodType.equals("week") && dateStr.length() < 7) {
									Calendar cal = Calendar.getInstance();
									cal.set(year, month-1, day);
									day = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
								}
								
								dateList.add(OffsetDateTime.of(year, month, day, 0, 0, 0, 0, ZoneOffset.ofHours(0)));
								continue;
							}
							
							if(measureNameMap.get(key) != null && !isMeasureData) {
								LinkedHashMap<String, Double> measureDataMap = new LinkedHashMap<>();
								for(String measureName : measureNameMap.keySet()) {
									measureDataMap.put(measureName, map.get(measureName) == null ? 0 : Double.parseDouble(String.valueOf(map.get(measureName)).replaceAll("[^0-9]", "")));
								}
								measureList.add(measureDataMap);
								isMeasureData = true;
								continue;
							}
							if(seriesDimensionNameMap.get(key) != null && !isSeriesDimension) {
								LinkedHashMap<String, Object> seriesDimensionMap = new LinkedHashMap<>();
								for(String seriesDimension : seriesDimensionNameMap.keySet()) {
									seriesDimensionMap.put(seriesDimension, String.valueOf(map.get(seriesDimension)));
								}
								seriesDimensionList.add(seriesDimensionMap);
								isSeriesDimension = true;
							}
						}
					}
				}
				
				if(periodType.equals("year")) {
					//timePeriod = TimePeriod.oneYear();
				} else if(periodType.equals("month")) {
					//timePeriod = TimePeriod.oneMonth();
				} else {
					//timePeriod = TimePeriod.oneDay();
				}
				
				double[] data = new double[measureList.size()];
				LinkedHashMap<String, Map<String, Object>> dataMap = new LinkedHashMap<>();
				List<OffsetDateTime> offsetdatelist = new ArrayList<>();;
				
				
				
				double[] timeData = new double[data.length];
				int[] timeDate = timeYear != 1 ? new int[2] : new int[1];
				if(!"Y".equals(params.get("autoOrderYn"))) {
					order[0] = Integer.parseInt(String.valueOf(params.get("pOrder")));
					order[1] = Integer.parseInt(String.valueOf(params.get("dOrder")));
					order[2] = Integer.parseInt(String.valueOf(params.get("qOrder")));					
					
					code.addIntArray("arimaOrder", order);
				}else {
					params.put("pOrder", 0);
					params.put("dOrder", 2);
					params.put("qOrder", 0);
				}
				
				
				for(String key : measureNameMap.keySet()) {
					
					RCaller caller = RCaller.create(code, options);
					RCaller caller2 = RCaller.create(code2, options2);
					
					int i = 0;
					for(Map<String, Double> map : measureList) {
						if(map.get(key) != null) {
							data[i] = map.get(key);
							i++;
						}
					}
					
					timeData = data;
					//System.out.println("====timeData====");
					//System.out.println(Arrays.toString(timeData));
					
					for(OffsetDateTime time : dateList) {
						timeDate[0] = time.getYear();
						break;
					}
					
					//timeDate[0] = timeYear;
					if(timeYear != 1) timeDate[1] = timeMonth;
					
					if(dateList.size() != data.length || dateList.size() < 2) continue;
										
					code.addDoubleArray("timeData", timeData);
					code.addIntArray("timeDate", timeDate);
					code.addInt("timeFrequency", timeFrequency);
					code.addInt("period", period);
					
					code.addRCode("if(!c(\"forecast\") %in% installed.packages()[,\"Package\"]){");	//패키지 설치 여부 확인
					code.addRCode("install.packages(\"forecast\");}");	
					code.addRCode("library(forecast)");
					
					code.addRCode("ts <- ts(timeData, start=timeDate, frequency=timeFrequency)");										
					
					if("Y".equals(params.get("autoOrderYn"))) {
						code.addRCode("ts2 <- auto.arima(ts)");
						//code.addRCode("ts2 <- Arima(ts, order=c(0,2,0))");	//디폴트값 0,2,0 으로 수정 확인 필요
						
						code.addRCode("f = function(){");
						code.addRCode("min <- 999;");
						code.addRCode("result <- c(0,0,0);");
						code.addRCode("for(i in 0:2){");
						code.addRCode("for(j in 0:2){");
						code.addRCode("for(k in 0:2){");
						code.addRCode("val <- 1000;");
						code.addRCode("arima <- try(val <- AIC(Arima(ts, order=c(i,j,k))), silent = TRUE);");
						code.addRCode("if(min > val){");
						code.addRCode("min <- val;");
						code.addRCode("result <- c(i, j, k);");
						code.addRCode("}");
						code.addRCode("}");
						code.addRCode("}");
						code.addRCode("}");
						code.addRCode("return (result);");                
						code.addRCode("}");
						
						code.addRCode("arima <- f()");
						
						code.addRCode("ts2 <- Arima(ts, order = arima)");
					}else {										
						code.addRCode("ts2 <- Arima(ts, order=arimaOrder)");	
					}
					
					code.addRCode("ts3 <- forecast(ts2, period)");
					code.addRCode("result <- summary(ts3)");
					
					code.addRCode("forecastDate <- row.names(result)");
					code.addRCode("pointForecast <- result$`Point Forecast`");
					//code.addRCode("result <- ");
					
					caller.setRCode(code);
					caller2.setRCode(code);
					
					caller.runAndReturnResult("data.frame(forecastDate, pointForecast)");
					caller2.runAndReturnResult("c(arima)");
					//caller.runAndReturnResult("c(arima, forecastDate, pointForecast)");
					//try {
						//System.out.println("====List====");
						//System.out.println(caller.getParser().getXMLFileAsString());
						//System.out.println(caller2.getParser().getXMLFileAsString());
					//} catch (IOException e) {
						// TODO Auto-generated catch block
						////e.printStackTrace();
					//}
					
					forecastDate = caller.getParser().getAsStringArray("forecastDate");
					pointForecast = caller.getParser().getAsDoubleArray("pointForecast");
					System.out.println("====order====");
					System.out.println(Arrays.deepToString(caller2.getParser().getAsStringArray("carima")));
					
					Map<String, Object> temp = new HashMap<>();
					
					if(offsetdatelist.isEmpty()) { 
						//offsetdatelist.addAll(forecastSeries.observationTimes());
						for(int k=0; k<forecastDate.length; k++) {
							int forecastYear = Integer.parseInt(forecastDate[k]);
							offsetdatelist.add(OffsetDateTime.of(forecastYear, 1, 1, 0, 0, 0, 0, ZoneOffset.ofHours(0)));
						}
					}
					temp.put("data", pointForecast);
//					for(double point : pointForecast) {
//						System.out.println(printC + " : " + point);
//					}

					printC++;
					dataMap.put(key, temp);
				}
				
				boolean dupChk = true;
				LinkedHashMap<String, Object> tempDataMap = null;
				LinkedHashMap<String, Object> firstDataMap = new LinkedHashMap<>();
				for(int i=0; i<offsetdatelist.size(); i++) {
					tempDataMap = new LinkedHashMap<>();		
					for(String key : entryMap.keySet()) {
						if(key.equals(String.valueOf(params.get("dimensionName")))) {
							String dateStr = offsetdatelist.get(i).format(DateTimeFormatter.ofPattern("yyyyMMdd"));
							if(periodType.equals("year")) {
								dateStr = dateStr.substring(0, 4);
							} else if(periodType.equals("month")) {
								dateStr = dateStr.substring(0, 6);
							}
							tempDataMap.put(key, dateStr);
						}
						
						if(measureNameMap.get(key) != null) {
							double[] arr = (double[])dataMap.get(key).get("data");
							tempDataMap.put(key, Math.floor(arr[i]));
							
						}
						
						if(seriesDimensionNameMap.get(key) != null) {
							tempDataMap.put(key, _map.get(key));
						}
						
						if(!firstDataMap.isEmpty()) {
							if(tempDataMap.get(key) == null) continue;
							if(!firstDataMap.get(key).equals(tempDataMap.get(key))) {
								dupChk = false;
							}
						}
					}
					if(i == 0) firstDataMap = tempDataMap;
					if(i > 0 && dupChk) {
						isBreak = true;
					} else {
						tempDataList.add(tempDataMap);
					}
				}
				
				int offsetdateCnt = offsetdatelist.size() == 0 ? 1 : offsetdatelist.size();
				int seriesDimensionCnt = seriesDimensionInfoList.size() == 0 ? 1 : seriesDimensionInfoList.size();
				
				if(((tempDataList.size() * seriesDimensionCnt) / offsetdateCnt) == list.size()) {
					//isBreak = true;
					break;
				}
			}
			
			List<LinkedHashMap<String, Object>> dataList = new ArrayList<>();
			HashSet<LinkedHashMap<String, Object>> hashset = new HashSet<>(tempDataList);
			dataList = new ArrayList<>(hashset);
			
			ArrayList<String> keys = new ArrayList<String>(seriesDimensionNameMap.keySet());
			for(int i = keys.size()-1; i >= 0; i--) {
				String key = keys.get(i);
				Collections.sort(dataList, new Comparator<LinkedHashMap<String, Object>>() {
					@Override
					public int compare(LinkedHashMap<String, Object> map1, LinkedHashMap<String, Object> map2) {
						String val1 = null;
						String val2 = null;
						try {
							val1 = String.valueOf(map1.get(key));
							val2 = String.valueOf(map2.get(key));
						} catch (JSONException e) {
							e.printStackTrace();
						}
						return val1.compareTo(val2);
					}
				});
			}
			
			Collections.sort(dataList, new Comparator<LinkedHashMap<String, Object>>() {
				@Override
				public int compare(LinkedHashMap<String, Object> map1, LinkedHashMap<String, Object> map2) {
					String val1 = null;
					String val2 = null;
					try {
						val1 = String.valueOf(map1.get(params.get("dimensionName")));
						val2 = String.valueOf(map2.get(params.get("dimensionName")));
					} catch (JSONException e) {
						e.printStackTrace();
					}
					return val1.compareTo(val2);
				}
			});
			
			list.addAll(dataList);
			
			System.out.println("======dataList=====");
			for(LinkedHashMap<String, Object> map : dataList) {
				StringBuffer sb = new StringBuffer();
				for(String key : map.keySet()){
		            String value = String.valueOf(map.get(key));
		            sb.append(key.concat(" : ").concat(value).concat("  "));
		        }
				//System.out.println(sb.toString());
			}
		
		
		}else {
			//DOGFOOT syjin 시계열 분석 R코드 추가 20210202
		
			int dataIdx = 0;
			
			int order[] = new int[3];
			
			for(LinkedHashMap<String, Object> map : list) {
				for(String key : map.keySet()) {
					if(params.get("dimensionName").equals(key)) {
						double d = Double.parseDouble(String.valueOf(map.get(key)).replaceAll("[^0-9]", ""));
						String dateStr = String.valueOf(Integer.parseInt(String.valueOf(Math.round(d))));
						int year = Integer.parseInt(dateStr.substring(0, 4));
						int month = dateStr.length() > 5 ? Integer.parseInt(dateStr.substring(4, 6)) : 1;
						int day = dateStr.length() > 7 ? Integer.parseInt(dateStr.substring(6, 8)) : 1;
						
						if(dataIdx == (list.size() - 1)) {
							if(periodType.equals("month") && dateStr.length() < 5) {
								month = 12;
							} else if(periodType.equals("week") && dateStr.length() < 7) {
								Calendar cal = Calendar.getInstance();
								cal.set(year, month-1, day);
								day = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
							}
						}	
						
						if(dataIdx==0) {
							timeYear = year;
							timeMonth = month;
						}
						
						dateList.add(OffsetDateTime.of(year, month, day, 0, 0, 0, 0, ZoneOffset.ofHours(0)));
						
						continue;
					}
					if(dataType == 1 && key.equals("arg") && Character.isLowerCase(key.charAt(0))) continue;
					
					objArr[keyMap.get(key)][dataIdx] = map.get(key) == null ? 0 : Double.parseDouble(String.valueOf(map.get(key)).replaceAll("[^0-9]", ""));
				}
				dataIdx++;
			}
			
			for(String key : keyMap.keySet()) {
				if(!params.get("dimensionName").equals(key)) {
					if(dataType == 1 && key.equals("arg") && Character.isLowerCase(key.charAt(0))) continue;
					
					RCaller caller = RCaller.create(code, options);
					
					double[] timeData = objArr[1];
					int[] timeDate = timeYear != 1 ? new int[2] : new int[1];
					if(!"Y".equals(params.get("autoOrderYn"))) {
						order[0] = Integer.parseInt(String.valueOf(params.get("pOrder")));
						order[1] = Integer.parseInt(String.valueOf(params.get("dOrder")));
						order[2] = Integer.parseInt(String.valueOf(params.get("qOrder")));
															
						code.addIntArray("arimaOrder", order);
					}else {
						params.put("pOrder", 0);
						params.put("dOrder", 2);
						params.put("qOrder", 0);
					}
					timeDate[0] = timeYear;
					if(timeYear != 1) timeDate[1] = timeMonth;
										
					code.addDoubleArray("timeData", timeData);
					code.addIntArray("timeDate", timeDate);
					code.addInt("timeFrequency", timeFrequency);
					code.addInt("period", period);
					
					code.addRCode("if(!c(\"forecast\") %in% installed.packages()[,\"Package\"]){");	//패키지 설치 여부 확인
					code.addRCode("install.packages(\"forecast\");}");	
					code.addRCode("library(forecast)");
					
					code.addRCode("ts <- ts(timeData, start=timeDate, frequency=timeFrequency)");
					if("Y".equals(params.get("autoOrderYn"))) {
						//code.addRCode("ts2 <- auto.arima(ts)");
						code.addRCode("ts2 <- Arima(ts, order=c(0,2,0))");	//디폴트값 0,2,0 으로 수정 확인 필요
					}else {										
						code.addRCode("ts2 <- Arima(ts, order=arimaOrder)");
						
					}
					
					code.addRCode("ts3 <- forecast(ts2, period)");
					code.addRCode("result <- summary(ts3)");
					
					code.addRCode("forecastDate <- row.names(result)");
					code.addRCode("pointForecast <- result$`Point Forecast`");
					code.addRCode("result <- data.frame(forecastDate, pointForecast)");
					
					caller.setRCode(code);					
					caller.runAndReturnResult("result");
					
					System.out.println("바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값");
					try {
						System.out.println("바인딩된 값 : " + caller.getParser().getXMLFileAsString());
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					System.out.println("Available results from object : ");
					System.out.println(caller.getParser().getNames());
					
//					double[] method = caller.getParser().getAsDoubleArray("method");
//					System.out.println("method");
//					for(double k : method) {
//						System.out.print(k + ",");
//					}
					
					String[] forecastDate = caller.getParser().getAsStringArray("forecastDate");
					System.out.println("forecastDate");
					for(String k : forecastDate) {
						System.out.print(k + ",");
					}
					
					double[] pointForecast = caller.getParser().getAsDoubleArray("pointForecast");
					System.out.println("pointForecast");
					for(double k : pointForecast) {
						System.out.print(k + ",");
					}
					
					for(int k=0; k<forecastDate.length; k++) {
						LinkedHashMap<String, Object> data = new LinkedHashMap<>();
						for(String entryKey : entryMap.keySet()) {
							if(params.get("dimensionName").equals(entryKey) || (dataType == 1 && entryKey.equals("arg") && Character.isLowerCase(entryKey.charAt(0)))) {
								data.put(entryKey, forecastDate[k]);
							}else {
								data.put(entryKey, String.valueOf(new BigDecimal(pointForecast[k]).toPlainString()));
							}
						}
						
						list.add(data);
					}
					
					
				}
			}
		}
			
		
		return list;
	}
	/* DOGFOOT yhkim 시계열분석 가공 데이터 */
	@Override
	public List<LinkedHashMap<String, Object>> getTimeSeriesForecast(
			List<LinkedHashMap<String, Object>> list,
			List<LinkedHashMap<String, Object>> measureInfoList,
			List<LinkedHashMap<String, Object>> seriesDimensionInfoList,
			Map<String, Object> params, int dataType) {
		
		TimeSeries series;
		TimePeriod timePeriod;
		Arima arima = null;
		ArimaOrder order = ArimaOrder.order(0, 0, 0);
		Forecast forecast;
		TimeSeries forecastSeries;
		//yhkim 시계열 자동분석 추가 20201118 dogfoot
		int[][] pdq = {  
			{0, 0, 0}, {0, 0, 1}, {0, 0, 2}, {0, 1, 0}, {0, 1, 1}, {0, 1, 2}, {0, 2, 0}, {0, 2, 1}, {0, 2, 2},
			{1, 0, 0}, {1, 0, 1}, {1, 0, 2}, {1, 1, 0}, {1, 1, 1}, {1, 1, 2}, {1, 2, 0}, {1, 2, 1}, {1, 2, 2},
			{2, 0, 0}, {2, 0, 1}, {2, 0, 2}, {2, 1, 0}, {2, 1, 1}, {2, 1, 2}, {2, 2, 0}, {2, 2, 1}, {2, 2, 2}
		};
		
		String periodType = String.valueOf(params.get("periodType"));
		
		LinkedHashMap<String, Object> entryMap = list.get(0);
		double[][] objArr = new double[entryMap.entrySet().size()][list.size()];

		Map<String, Integer> keyMap = new HashMap<>();
		List<OffsetDateTime> dateList = new ArrayList<>();
		
		int keyIdx = 0;
		for(String key : entryMap.keySet()) {
			keyMap.put(key, keyIdx);
			keyIdx++;
		}
		
		if(!seriesDimensionInfoList.isEmpty() && seriesDimensionInfoList.size() > 0) {
			 //차원그룹 有
			List<LinkedHashMap<String, Object>> tempDataList = new ArrayList<>();
			
			ArrayList<Map<String, Double>> measureList = new ArrayList<>();
			LinkedHashMap<String, Integer> measureNameMap = new LinkedHashMap<>();
			for(int i=0; i < measureInfoList.size(); i++) {
				measureNameMap.put(String.valueOf(measureInfoList.get(i).get(dataType == 0 ? "name" : "nameBySummaryType")), i);
			}
			
			ArrayList<Map<String, Object>> seriesDimensionList = new ArrayList<>();
			LinkedHashMap<String, Integer> seriesDimensionNameMap = new LinkedHashMap<>();
			for(int i=0; i < seriesDimensionInfoList.size(); i++) {
				seriesDimensionNameMap.put(String.valueOf(seriesDimensionInfoList.get(i).get("name")), i);
			}
			boolean isBreak = false;
			int printC = 1;
			
			for(LinkedHashMap<String, Object> _map : list) {
				if(isBreak) break;
				dateList = new ArrayList<>();
				measureList = new ArrayList<>();
				seriesDimensionList = new ArrayList<>();
				for(LinkedHashMap<String, Object> map : list) {
					
					boolean isMeasureData = false;
					boolean isSeriesDimension = false;
					boolean seriesDimensionChk = true;
					for(String key : seriesDimensionNameMap.keySet()) {
						if(!_map.get(key).equals(map.get(key))) seriesDimensionChk = false;
					}
					if(seriesDimensionChk) {
						for(String key : map.keySet()) {
							if(params.get("dimensionName").equals(key)) {
								String dateStr = String.valueOf(map.get(key)).replaceAll("[^0-9]", "");
								int year = Integer.parseInt(dateStr.substring(0, 4));
								int month = dateStr.length() > 5 ? Integer.parseInt(dateStr.substring(4, 6)) : 1;
								int day = dateStr.length() > 7 ? Integer.parseInt(dateStr.substring(6, 8)) : 1;
								
								if(periodType.equals("month") && dateStr.length() < 5) {
									month = 12;
								} else if(periodType.equals("week") && dateStr.length() < 7) {
									Calendar cal = Calendar.getInstance();
									cal.set(year, month-1, day);
									day = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
								}
								
								dateList.add(OffsetDateTime.of(year, month, day, 0, 0, 0, 0, ZoneOffset.ofHours(0)));
								continue;
							}
							
							if(measureNameMap.get(key) != null && !isMeasureData) {
								LinkedHashMap<String, Double> measureDataMap = new LinkedHashMap<>();
								for(String measureName : measureNameMap.keySet()) {
									measureDataMap.put(measureName, map.get(measureName) == null ? 0 : Double.parseDouble(String.valueOf(map.get(measureName)).replaceAll("[^0-9]", "")));
								}
								measureList.add(measureDataMap);
								isMeasureData = true;
								continue;
							}
							if(seriesDimensionNameMap.get(key) != null && !isSeriesDimension) {
								LinkedHashMap<String, Object> seriesDimensionMap = new LinkedHashMap<>();
								for(String seriesDimension : seriesDimensionNameMap.keySet()) {
									seriesDimensionMap.put(seriesDimension, String.valueOf(map.get(seriesDimension)));
								}
								seriesDimensionList.add(seriesDimensionMap);
								isSeriesDimension = true;
							}
						}
					}
				}
				
				if(periodType.equals("year")) {
					timePeriod = TimePeriod.oneYear();
				} else if(periodType.equals("month")) {
					timePeriod = TimePeriod.oneMonth();
				} else {
					timePeriod = TimePeriod.oneDay();
				}
				
				double[] data = new double[measureList.size()];
				LinkedHashMap<String, Map<String, Object>> dataMap = new LinkedHashMap<>();
				List<OffsetDateTime> offsetdatelist = new ArrayList<>();;

				for(String key : measureNameMap.keySet()) {
					int i = 0;
					for(Map<String, Double> map : measureList) {
						if(map.get(key) != null) {
							data[i] = map.get(key);
							i++;
						}
					}
					
					//System.out.println("====timeData====");
					//System.out.println(Arrays.toString(data));
					
					if(dateList.size() != data.length || dateList.size() < 2) continue;
					
					series = TimeSeries.from(timePeriod, dateList, data);
					if("Y".equals(params.get("autoOrderYn"))) {
						order = Analysis.setArimaOrder(series, order, pdq, params);												
					} else {
						order = ArimaOrder.order(Integer.parseInt(String.valueOf(params.get("pOrder"))), Integer.parseInt(String.valueOf(params.get("dOrder"))), Integer.parseInt(String.valueOf(params.get("qOrder"))));
					}
					System.out.println("=======order======");
					System.out.println(order);
					
					arima = Arima.model(series, order);
					
					forecast = arima.forecast(Integer.parseInt(String.valueOf(params.get("period"))));
					forecastSeries = forecast.pointEstimates();
					
					Map<String, Object> temp = new HashMap<>();
					if(offsetdatelist.isEmpty()) offsetdatelist.addAll(forecastSeries.observationTimes());
					temp.put("data", forecastSeries.asArray());
//					for(double point : forecastSeries.asArray()) {
//						System.out.println(printC + " : " + point);
//					}
					printC++;
					dataMap.put(key, temp);
				}
				
				boolean dupChk = true;
				LinkedHashMap<String, Object> tempDataMap = null;
				LinkedHashMap<String, Object> firstDataMap = new LinkedHashMap<>();
				for(int i=0; i<offsetdatelist.size(); i++) {
					tempDataMap = new LinkedHashMap<>();		
					for(String key : entryMap.keySet()) {
						if(key.equals(String.valueOf(params.get("dimensionName")))) {
							String dateStr = offsetdatelist.get(i).format(DateTimeFormatter.ofPattern("yyyyMMdd"));
							if(periodType.equals("year")) {
								dateStr = dateStr.substring(0, 4);
							} else if(periodType.equals("month")) {
								dateStr = dateStr.substring(0, 6);
							}
							tempDataMap.put(key, dateStr);
						}
						
						if(measureNameMap.get(key) != null) {
							double[] arr = (double[])dataMap.get(key).get("data");
							tempDataMap.put(key, Math.floor(arr[i]));
							
						}
						
						if(seriesDimensionNameMap.get(key) != null) {
							tempDataMap.put(key, _map.get(key));
						}
						
						if(!firstDataMap.isEmpty()) {
							if(tempDataMap.get(key) == null) continue;
							if(!firstDataMap.get(key).equals(tempDataMap.get(key))) {
								dupChk = false;
							}
						}
					}
					if(i == 0) firstDataMap = tempDataMap;
					if(i > 0 && dupChk) {
						isBreak = true;
					} else {
						tempDataList.add(tempDataMap);
					}
				}
				
				int offsetdateCnt = offsetdatelist.size() == 0 ? 1 : offsetdatelist.size();
				int seriesDimensionCnt = seriesDimensionInfoList.size() == 0 ? 1 : seriesDimensionInfoList.size();
				
				if(((tempDataList.size() * seriesDimensionCnt) / offsetdateCnt) == list.size()) {
					//isBreak = true;
					break;
				}
			}
			
			List<LinkedHashMap<String, Object>> dataList = new ArrayList<>();
			HashSet<LinkedHashMap<String, Object>> hashset = new HashSet<>(tempDataList);
			dataList = new ArrayList<>(hashset);
			
			ArrayList<String> keys = new ArrayList<String>(seriesDimensionNameMap.keySet());
			for(int i = keys.size()-1; i >= 0; i--) {
				String key = keys.get(i);
				Collections.sort(dataList, new Comparator<LinkedHashMap<String, Object>>() {
					@Override
					public int compare(LinkedHashMap<String, Object> map1, LinkedHashMap<String, Object> map2) {
						String val1 = null;
						String val2 = null;
						try {
							val1 = String.valueOf(map1.get(key));
							val2 = String.valueOf(map2.get(key));
						} catch (JSONException e) {
							e.printStackTrace();
						}
						return val1.compareTo(val2);
					}
				});
			}
			
			Collections.sort(dataList, new Comparator<LinkedHashMap<String, Object>>() {
				@Override
				public int compare(LinkedHashMap<String, Object> map1, LinkedHashMap<String, Object> map2) {
					String val1 = null;
					String val2 = null;
					try {
						val1 = String.valueOf(map1.get(params.get("dimensionName")));
						val2 = String.valueOf(map2.get(params.get("dimensionName")));
					} catch (JSONException e) {
						e.printStackTrace();
					}
					return val1.compareTo(val2);
				}
			});
			
			list.addAll(dataList);
			
			//System.out.println("=======dataList======");
			for(LinkedHashMap<String, Object> map : dataList) {
				StringBuffer sb = new StringBuffer();
				for(String key : map.keySet()){
		            String value = String.valueOf(map.get(key));
		            sb.append(key.concat(" : ").concat(value).concat("  "));
		        }
				//System.out.println(sb.toString());
			}
		
		} else {
			int dataIdx = 0;
					
			for(LinkedHashMap<String, Object> map : list) {
				for(String key : map.keySet()) {
					if(params.get("dimensionName").equals(key)) {
						double d = Double.parseDouble(String.valueOf(map.get(key)).replaceAll("[^0-9]", ""));
						String dateStr = String.valueOf(Integer.parseInt(String.valueOf(Math.round(d))));
						int year = Integer.parseInt(dateStr.substring(0, 4));
						int month = dateStr.length() > 5 ? Integer.parseInt(dateStr.substring(4, 6)) : 1;
						int day = dateStr.length() > 7 ? Integer.parseInt(dateStr.substring(6, 8)) : 1;
						
						if(dataIdx == (list.size() - 1)) {
							if(periodType.equals("month") && dateStr.length() < 5) {
								month = 12;
							} else if(periodType.equals("week") && dateStr.length() < 7) {
								Calendar cal = Calendar.getInstance();
								cal.set(year, month-1, day);
								day = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
							}
						}						
						dateList.add(OffsetDateTime.of(year, month, day, 0, 0, 0, 0, ZoneOffset.ofHours(0)));
						
						continue;
					}
					if(dataType == 1 && key.equals("arg") && Character.isLowerCase(key.charAt(0))) continue;
					
					objArr[keyMap.get(key)][dataIdx] = map.get(key) == null ? 0 : Double.parseDouble(String.valueOf(map.get(key)).replaceAll("[^0-9]", ""));
				}
				dataIdx++;
			}
			
			if(periodType.equals("year")) {
				timePeriod = TimePeriod.oneYear();				
			} else if(periodType.equals("month")) {
				timePeriod = TimePeriod.oneMonth();				
			} else {
				timePeriod = TimePeriod.oneDay();
			}
			
			int seriesCnt = 0;
			Map<String, double[]> seriesMap = new HashMap<>();
			List<OffsetDateTime> timeList = new ArrayList<>();
				
			for(String key : keyMap.keySet()) {
				if(!params.get("dimensionName").equals(key)) {
					if(dataType == 1 && key.equals("arg") && Character.isLowerCase(key.charAt(0))) continue;
					series = TimeSeries.from(timePeriod, dateList, objArr[keyMap.get(key)]);
										
					if("Y".equals(params.get("autoOrderYn"))) {
						order = Analysis.setArimaOrder(series, order, pdq, params);
					} else {
						order = ArimaOrder.order(Integer.parseInt(String.valueOf(params.get("pOrder"))), Integer.parseInt(String.valueOf(params.get("dOrder"))), Integer.parseInt(String.valueOf(params.get("qOrder"))));
					}
					arima = Arima.model(series, order);
					
					forecast = arima.forecast(Integer.parseInt(String.valueOf(params.get("period"))));
					forecastSeries = forecast.pointEstimates();
					seriesMap.put(key, forecastSeries.asArray());
					if(timeList.isEmpty()) {
						timeList = forecastSeries.observationTimes();
						seriesCnt = forecastSeries.asArray().length;
					}
				}
			}
			
			String[] dateArr = new String[seriesCnt];
			
			int i = 0;
			for(OffsetDateTime dt : timeList) {
				dateArr[i] = dt.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
				i++;
			}
			
			for(int j = 0; j < dateArr.length; j++) {
				LinkedHashMap<String, Object> data = new LinkedHashMap<>();
				for(String key : entryMap.keySet()) {
					if(params.get("dimensionName").equals(key) || (dataType == 1 && key.equals("arg") && Character.isLowerCase(key.charAt(0)))) {
						String dateStr = dateArr[j];
						if(periodType.equals("year")) {
							dateStr = dateStr.substring(0, 4);
						} else if(periodType.equals("month")) {
							dateStr = dateStr.substring(0, 6);
						}
						data.put(key, dateStr);
					} else {
						data.put(key, Math.floor(seriesMap.get(key)[j]));
					}
				}
				list.add(data);
			}
		}
		
		return list;
	}
	
	@Override
	public int executeReportScheduleMaster() {
		int resultCnt = 0;
		Integer selectedSchId = 0;
		try {
	        String path = Configurator.getInstance().getApplicationContextRealLocation()+"DataFiles"+File.separator;
			
			List<ReportScheduleVO> result = new ArrayList<ReportScheduleVO>();
			
			SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmm");
			SimpleDateFormat parseTimeStamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
			Calendar cal = Calendar.getInstance();
			String today = null;
			today = formatter.format(cal.getTime());
			Timestamp ts = Timestamp.valueOf(parseTimeStamp.format(cal.getTime()));

			//40:실행대기
			result = selectReportScheduleAllList();
			
			for (ReportScheduleVO vo : result) {
				String regDate = vo.getSCH_DT();
				String formatDateString = regDate.substring(0,regDate.lastIndexOf(':'));
				formatDateString = formatDateString.replaceAll("-","").replaceAll(" ","").replaceAll(":", "");
				
				/* DOGFOOT ktkang 스케줄링 오류 수정  20201007 */
				if (Long.parseLong(today) > Long.parseLong(formatDateString)) {
					resultCnt++;
					selectedSchId = vo.getSCH_ID();
					Integer selectedReportId = vo.getREPORT_ID();

					String filePath = path + selectedSchId + "-" + selectedReportId.toString() + "-" + formatDateString;
					
					//50:실행중
					ParamScheduleVO schParam = new ParamScheduleVO();
					schParam.setSCH_ID(selectedSchId);
					schParam.setEXEC_ST_DT(ts);
					schParam.setEXEC_DATA(filePath);
					schParam.setSTATUS_CD("50");
					this.dataSetServiceImpl.insertSchData(schParam);
					
					CloseableList<net.sf.json.JSONObject> sqlItem = new FileBackedJSONObjectList();
					String reportType = selectReportType(selectedReportId.toString()).getREPORT_TYPE();
					String fldType = selectReportType(selectedReportId.toString()).getFLD_TYPE();
					ReportMasterVO reportvo = selectReportBasicInformation(selectedReportId, reportType, fldType);
                    net.sf.json.JSONObject info = reportvo.getDataSourceAndParameterJson("");
                    net.sf.json.JSONObject reportMasterInfo = net.sf.json.JSONObject.fromObject(info);
                    JSONArray dataSetElements = reportMasterInfo.getJSONObject("datasetJson").getJSONArray("DATASET_ELEMENT");
                    net.sf.json.JSONObject ret = new net.sf.json.JSONObject();
			        for (int i = 0; i < dataSetElements.size(); i++) {
			        	net.sf.json.JSONObject dataSetObj = (net.sf.json.JSONObject) dataSetElements.get(i);
	                    int dataSrcId = dataSetObj.getInt("DATASRC_ID");
	                    String dataSetName = dataSetObj.getString("DATASET_NM");
			            String dataSrcType = dataSetObj.getString("DATASRC_TYPE");
			            String sql = dataSetObj.getString("DATASET_QUERY");
			            net.sf.json.JSONObject params = net.sf.json.JSONObject.fromObject("{}");
			            sqlItem = this.dataSetServiceImpl.querySql(dataSrcId, dataSrcType, sql, params, 0, null);
			            ret.put(dataSetName, sqlItem);
			        }
			        
		        	File dataFile = new File(filePath);
		        	FileWriter fw = new FileWriter(dataFile);
					fw.write(ret.toString());
					fw.close();
			        
			        //60:실행완료
					schParam = new ParamScheduleVO();
					schParam.setSCH_ID(selectedSchId);
					schParam.setEXEC_ED_DT(new Timestamp(System.currentTimeMillis()));
					schParam.setSTATUS_CD("60");
					this.dataSetServiceImpl.insertSchData(schParam);
				}
			}
		}catch(Exception e) {
			e.printStackTrace();
			//99:에러
			ParamScheduleVO schParam = new ParamScheduleVO();
			schParam.setSCH_ID(selectedSchId);
			schParam.setEXEC_ED_DT(new Timestamp(System.currentTimeMillis()));
			schParam.setERROR_MSG(e.getMessage());
			schParam.setSTATUS_CD("99");
			this.dataSetServiceImpl.insertSchData(schParam);
		}		
		
		return resultCnt;
	}
	/* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
	@Override
	public void callUpReportMstrHisACT(JSONObject obj,String remoteAddr, int seq, String reportId) {
		// TODO Auto-generated method stub
//		Map<String, Comparable> param = new HashMap<String, Comparable>();
		ReportParamVO param = new ReportParamVO();
		boolean checkExceltion = true;
		String layoutXmlString ="";
		String paramXmlString = "";
		String dataSetXmlString = "";
		try {
			// KERIS 수정
			layoutXmlString = this.json2xml.sortLayoutXml(obj.getJSONObject("layout_xml"), remoteAddr);
			paramXmlString = this.json2xml.sortParamXml(obj.getJSONObject("param_xml"));
			dataSetXmlString = this.json2xml.sortDataSetXml(obj.getJSONObject("dataset_xml"), obj.getJSONObject("param_xml"), obj.getJSONObject("reportItemList"), false);
		} catch (IOException e) {
			e.printStackTrace();
			checkExceltion=false;
		} catch (BadLocationException ble) {
			ble.printStackTrace();
			checkExceltion=false;
		}
		
		String reportOrdinal = obj.getString("report_ordinal");
		logger.debug(layoutXmlString);
		String userNo = "";
		User user = this.authenticationDAO.selectRepositoryUserByUserId(obj.getString("userid"));
		if (user != null) {
			//2020.02.04 mksong 사용자번호 등록 오류 수정 dogfoot
			userNo = user.getUSER_NO()+"";
		}
		
		JSONObject ret = new JSONObject();
//		logger.debug(obj.getJSONObject("dataset_xml").toString());
		if(checkExceltion == true) {
		/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
			param.setP_PARAM("99");
			param.setREPORT_ID(reportId);
			param.setREPORT_SEQ(seq + 1);
			param.setREPORT_NM(obj.getString("report_nm"));
			param.setFLD_ID(obj.getString("fld_id"));
			param.setFLD_TYPE(obj.getString("fld_type"));
			param.setREPORT_ORDINAL(reportOrdinal.equals("")? "0":reportOrdinal);
			//param.setREPORT_TYPE("DashAny");
			/*dogfoot 통계 분석 추가 shlim 20201102*/
			param.setREPORT_TYPE(obj.getString("report_type"));
			param.setREPORT_TAG(obj.getString("report_tag"));
			param.setREPORT_DESC(obj.getString("report_desc"));
			param.setREPORT_LAYOUT("");
			param.setGRID_INFO("");
			param.setDATASRC_ID("");
			param.setDATASRC_TYPE("");
			param.setDATASET_TYPE("");
			/* DOGFOOT mksong BASE64 오류 수정  20200116 */
			param.setREPORT_XML(new String(java.util.Base64.getEncoder().encode(obj.getString("report_xml").getBytes())));
			param.setCHART_XML(new String(java.util.Base64.getEncoder().encode(XML.toString(obj.getJSONObject("chart_xml")).getBytes())));
			param.setLAYOUT_XML(new String(java.util.Base64.getEncoder().encode(layoutXmlString.getBytes())));
			param.setDATASET_XML(new String(java.util.Base64.getEncoder().encode(dataSetXmlString.getBytes())));
			param.setPARAM_XML(new String(java.util.Base64.getEncoder().encode(paramXmlString.getBytes())));
			param.setDATASET_QUERY("");
			param.setREG_USER_NO(userNo);
//			param.put("REG_USER_NO", "1001");
			param.setDEL_YN("N");
			param.setPROMPT_YN("N");
			param.setREPORT_SUB_TITLE("");//obj.getString("report_desc"));
//			param.put("MOD_USER_NO", obj.getString("userid"));
//			param.put("MOD_USER_NO", "1001");
			param.setMOD_USER_NO(userNo);
			param.setPRIVACY_YN("N");
			/* DOGFOOT syjin LAYOUT_CONFIG 추가  20200814 */
			param.setLAYOUT_CONFIG(obj.getString("layout_config"));
			
			this.reportDAO.callUpReportMstrHisACT(param);
		}
	}
	
	@Override
	public void callUpReportMstrACT2(JSONObject obj, ReportMasterHisVO reportMstrHis) {
		ReportParamVO param = new ReportParamVO();
		
		String userNo = "";
		User user = this.authenticationDAO.selectRepositoryUserByUserId(obj.getString("user_id"));
		if (user != null) {
			//2020.02.04 mksong 사용자번호 등록 오류 수정 dogfoot
			userNo = user.getUSER_NO()+"";
		}
		
		param.setP_PARAM("99");
		param.setREPORT_ID(obj.getString("report_id"));
		param.setREPORT_NM(obj.getString("report_nm"));
		param.setFLD_ID(obj.getString("fld_id"));
		param.setFLD_TYPE(obj.getString("fld_type"));
		param.setREPORT_ORDINAL(obj.getString("report_ordinal"));
		param.setREPORT_TYPE(reportMstrHis.getREPORT_TYPE());
		param.setREPORT_TAG(obj.getString("report_tag"));
		param.setREPORT_DESC(obj.getString("report_desc"));
		param.setREPORT_LAYOUT(reportMstrHis.getREPORT_LAYOUT());
		param.setGRID_INFO(reportMstrHis.getGRID_INFO());
		param.setDATASRC_ID(reportMstrHis.getDATASRC_ID());
		param.setDATASRC_TYPE(reportMstrHis.getDATASRC_TYPE());
		param.setDATASET_TYPE(reportMstrHis.getDATASET_TYPE());
		param.setREPORT_XML(reportMstrHis.getREPORT_XML());
		param.setCHART_XML(reportMstrHis.getCHART_XML());
		param.setLAYOUT_XML(reportMstrHis.getLAYOUT_XML());
		param.setDATASET_XML(reportMstrHis.getDATASET_XML());
		param.setPARAM_XML(reportMstrHis.getPARAM_XML());
		param.setDATASET_QUERY(reportMstrHis.getDATASET_QUERY());
		param.setREG_USER_NO(userNo);
		param.setDEL_YN(reportMstrHis.getDEL_YN());
		param.setPROMPT_YN(reportMstrHis.getPROMPT_YN());
		param.setREPORT_SUB_TITLE(obj.getString("report_sub_title"));
		param.setMOD_USER_NO(userNo);
		param.setPRIVACY_YN(reportMstrHis.getPRIVACY_YN());
		param.setLAYOUT_CONFIG(reportMstrHis.getLAYOUT_CONFIG());
		param.setDIRECT_VIEW(reportMstrHis.getDIRECT_VIEW());
		
		ReportMasterVO vo = this.reportDAO.callUpReportMstrACT(param);

	}

	@Override
	public List<ReportMasterHisVO> selectReportMstrHisList(JSONObject obj) {
		int reportId;
		if(obj.has("report_id")) {
			reportId = Integer.parseInt(obj.getString("report_id"));
		} else {
			reportId = Integer.parseInt(obj.getString("reportId"));
		}
		return this.reportDAO.selectReportMstrHisList(reportId);
	}
	
	@Override
	public List<ReportMasterHisVO> selectReportHisList(int reportId) {
		return this.reportDAO.selectReportHisList(reportId);
	}
	
	@Override
	public ReportMasterHisVO selectReportHis(int reportId, int reportSeq) {
		return this.reportDAO.selectReportHis(reportId, reportSeq);
	}
	
	@Override
	public int updateReportMstrHis(String reportId, String reportSeq) {
		ReportMasterHisVO param = new ReportMasterHisVO();
		param.setREPORT_ID(reportId);
		param.setREPORT_SEQ(Integer.parseInt(reportSeq));
		
		return this.reportDAO.updateReportMstrHis(param);
	}
	
	/* DOGFOOT ktkang 동시 작업 제한 기능 구현  20200922 */
	@Override
	public int selectReportWorks() {
		return this.reportDAO.selectReportWorks();
	}
	
	/* DOGFOOT ktkang 리포트 다운로드 권한 구현  20201109 */
	@Override
	public UserGrpAuthReportListVO userAuthByReport(int userNo, String reportId) {
		return this.reportDAO.userAuthByReport(userNo, reportId);
	}
	
	@Override
	public UserGrpAuthReportListVO grpAuthByReport(int grpId, String reportId) {
		return this.reportDAO.grpAuthByReport(grpId, reportId);
	}
	
	@Override
	public UserGrpAuthReportListVO userAuthByFolder(int userNo, String fldId) {
		return this.reportDAO.userAuthByFolder(userNo, fldId);
	}
	
	@Override
	public UserGrpAuthReportListVO grpAuthByFolder(int grpId, String fldId) {
		return this.reportDAO.grpAuthByFolder(grpId, fldId);
	}
	
	@Override
	public String selectSchedulePath(int reportId) {
		return this.reportDAO.selectSchedulePath(reportId);
	}
	
	/* DOGFOOT ktkang BMT 그룹핑 기능 구현  20201203 */
	@Override
	public List<DSViewColVO> selectCubeGroupingData(int cubeId) {
		return this.reportDAO.selectCubeGroupingData(cubeId);
	}
	
	@Override
	public List<CubeHieMasterVO> selectCubeGroupingTblList(int cubeId) {
		return this.reportDAO.selectCubeGroupingTblList(cubeId);
	}
	
	@Override
	public int deleteDsViewColMstr(int dsViewId) {
		return this.reportDAO.deleteDsViewColMstr(dsViewId);
	}
	
	@Override
	public int deleteDsViewHieMstr(int dsViewId) {
		return this.reportDAO.deleteDsViewHieMstr(dsViewId);
	}
	
	@Override
	public int deleteCubeHieMstr(int cubeId) {
		return this.reportDAO.deleteCubeHieMstr(cubeId);
	}
	
	@Override
	public int insertDsViewColMstr(JSONObject groupingData, int colNum, int colId, int dsViewId) {
		DSViewColVO param = new DSViewColVO();
		param.setDS_VIEW_ID(dsViewId);
		param.setTBL_NM(groupingData.getString("TBL_NM"));
		param.setCOL_NM("WISE_GROUPINGDATA_" + colNum);
		param.setCOL_CAPTION(groupingData.getString("COL_CAPTION"));
		param.setDATA_TYPE(groupingData.getString("DATA_TYPE"));
		param.setLENGTH(groupingData.getString("LENGTH"));
		param.setPK_YN(groupingData.getString("PK_YN"));
		param.setCOL_EXPRESS(groupingData.getString("COL_EXPRESS"));
		param.setCOL_ID(String.valueOf(colId));
		
		return this.reportDAO.insertDsViewColMstr(param);
	}
	
	@Override
	public int insertDsViewHieMstr(JSONObject groupingData, int colNum, int dsViewId) {
		String tblName = "[" + groupingData.getString("TBL_NM") + "]";
		String colName = "[" + "WISE_GROUPINGDATA_" + colNum + "]";
		
		DSViewHieVO param = new DSViewHieVO();
		param.setDS_VIEW_ID(dsViewId);
		param.setDIM_UNI_NM(tblName);
		param.setHIE_UNI_NM(tblName + "." + colName);
		param.setHIE_CAPTION(groupingData.getString("COL_CAPTION"));
		param.setTBL_NM(groupingData.getString("TBL_NM"));
		param.setKEY_COL("WISE_GROUPINGDATA_" + colNum);
		param.setNAME_COL("WISE_GROUPINGDATA_" + colNum);
		
		return this.reportDAO.insertDsViewHieMstr(param);
	}
	
	@Override
	public int insertCubeHieMstr(JSONObject groupingData, int colNum, int cubeId) {
		String tblName = "[" + groupingData.getString("TBL_NM") + "]";
		String colName = "[" + "WISE_GROUPINGDATA_" + colNum + "]";
		
		CubeHieMasterVO param = new CubeHieMasterVO();
		param.setCUBE_ID(cubeId);
		param.setHIE_UNI_NM(tblName + "." + colName);
		param.setDIM_UNI_NM(tblName);
		param.setHIE_CAPTION(groupingData.getString("COL_CAPTION"));
		param.setDIM_DIM_UNI_NM(tblName);
		param.setHIE_HIE_UNI_NM(tblName + "." + colName);
		
		return this.reportDAO.insertCubeHieMstr(param);
	}
	
	@Override
	public int selectMaxColId() {
		return this.reportDAO.selectMaxColId();
	}
	
	@Override
	public CubeMember selectCubeMasterInformation(int cubeId) {
		return this.reportDAO.selectCubeMasterInformation(cubeId);
	}
	
	@Override
	public List<CubeHieMasterVO> selectCubeGroupingDimList(String cubeId, String selectTableName) {
		Map<String, String> param = new HashMap<String, String>();
		param.put("cubeId", cubeId);
		param.put("selectTableName", selectTableName);
		
		return this.reportDAO.selectCubeGroupingDimList(param);
	}
	
	@Override
	public ReportMasterVO selectReportParamXmlList(int reportId) {
		// TODO Auto-generated method stub
		ReportMasterVO ret;
	    ret = this.reportDAO.selectReportParamXmlList(reportId);
	    return ret;
	}
	
	@Override
	public void updateReportDatasetParam(ReportMasterVO updateReportXmlVal) {
		// TODO Auto-generated method stub
		this.reportDAO.updateReportDatasetParam(updateReportXmlVal);
	}
}
