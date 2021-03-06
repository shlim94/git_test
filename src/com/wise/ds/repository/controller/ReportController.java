package com.wise.ds.repository.controller;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.lang.management.ManagementFactory;
import java.lang.ref.WeakReference;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import javax.annotation.Resource;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.swing.JEditorPane;
import javax.swing.text.EditorKit;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.http.client.utils.CloneUtils;
import org.apache.poi.hssf.usermodel.HSSFCell;
import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ooxml.util.SAXHelper;
import org.apache.poi.xssf.model.SharedStringsTable;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.SQLContext;
import org.apache.spark.sql.SparkSession;
import org.bouncycastle.util.encoders.Base64;
import org.json.XML;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.servlet.ModelAndView;
import org.xml.sax.ContentHandler;
import org.xml.sax.XMLReader;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.wise.authn.ConfigMasterVO;
import com.wise.authn.DataAuthentication;
import com.wise.authn.ReportDataPermission;
import com.wise.authn.User;
import com.wise.authn.UserGroupVO;
import com.wise.authn.WebConfigMasterVO;
import com.wise.authn.dao.AuthenticationDAO;
import com.wise.authn.exception.NotFoundUserException;
import com.wise.authn.exception.PermissionDeniedReportViewException;
import com.wise.authn.service.AuthenticationService;
import com.wise.common.diagnos.WDC;
import com.wise.common.diagnos.WdcTask;
import com.wise.common.file.SummaryMatrixFileWriterService;
import com.wise.common.message.AjaxMessageConverter;
import com.wise.common.message.WiseMessageSource;
import com.wise.common.secure.AES256Cipher;
import com.wise.common.secure.SecureUtils;
import com.wise.common.util.BrowserUtils;
import com.wise.common.util.CloseableList;
import com.wise.common.util.CoreUtils;
import com.wise.common.util.FileBackedJSONObjectList;
import com.wise.common.util.QueryExecutor;
import com.wise.common.util.ServiceTimeoutUtils;
import com.wise.common.util.Timer;
import com.wise.comp.impl.json.JSONArrayDataFrame;
import com.wise.comp.model.DataAggregation;
import com.wise.comp.model.DataFrame;
import com.wise.comp.model.Paging;
import com.wise.comp.pivotgrid.aggregator.DataAggregator;
import com.wise.comp.pivotgrid.param.FilterParam;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.PagingParam;
import com.wise.comp.pivotgrid.param.SortInfoParam;
import com.wise.comp.pivotgrid.param.SummaryParam;
import com.wise.comp.pivotgrid.param.TopBottomParam;
import com.wise.comp.pivotgrid.param.UdfGroupParam;
import com.wise.comp.pivotgrid.util.ParamUtils;
import com.wise.comp.pivotgrid.util.PivotGridJsonUtils;
import com.wise.comp.pivotmatrix.SummaryMatrix;
import com.wise.comp.pivotmatrix.SummaryMatrixFactory;
import com.wise.comp.pivotmatrix.SummaryMatrixProvider;
import com.wise.comp.pivotmatrix.impl.SummaryMatrixUtils;
import com.wise.context.config.Base64Coder;
import com.wise.context.config.Base64Encoder;
import com.wise.context.config.Configurator;
import com.wise.ds.query.util.QuertExcuter;
import com.wise.ds.query.util.SqlConvertor;
import com.wise.ds.query.util.SqlForEachMartDbType;
import com.wise.ds.query.util.SqlMapper;
import com.wise.ds.query.util.SqlStorage;
import com.wise.ds.query.util.TossExecutor;
import com.wise.ds.repository.CubeHieMasterVO;
import com.wise.ds.repository.CubeListMasterVO;
import com.wise.ds.repository.CubeMember;
import com.wise.ds.repository.CubeTableColumnVO;
import com.wise.ds.repository.CubeTableVO;
import com.wise.ds.repository.CubeVO;
import com.wise.ds.repository.DSViewColVO;
import com.wise.ds.repository.DataSetInfoMasterVO;
import com.wise.ds.repository.DataSetMasterVO;
import com.wise.ds.repository.DrillThruColumnVO;
import com.wise.ds.repository.EmptyReportIdException;
import com.wise.ds.repository.FolderMasterVO;
import com.wise.ds.repository.ReportFieldMasterVO;
import com.wise.ds.repository.ReportListMasterVO;
import com.wise.ds.repository.ReportLogDetailMasterVO;
import com.wise.ds.repository.ReportLogMasterVO;
import com.wise.ds.repository.ReportMasterHisVO;
import com.wise.ds.repository.ReportMasterVO;
import com.wise.ds.repository.ReportScheduleVO;
import com.wise.ds.repository.ReportSubLinkVO;
import com.wise.ds.repository.SubjectCubeMasterVO;
import com.wise.ds.repository.SubjectMasterVO;
import com.wise.ds.repository.SubjectViewMasterVO;
import com.wise.ds.repository.TableRelationVO;
import com.wise.ds.repository.TossExeVO;
import com.wise.ds.repository.UnRegisterdReportException;
import com.wise.ds.repository.UnSupportedRequestException;
import com.wise.ds.repository.UndefinedDataTypeForNullValueException;
import com.wise.ds.repository.UploadHisVO;
import com.wise.ds.repository.UserConfigVO;
import com.wise.ds.repository.UserGrpAuthReportListVO;
import com.wise.ds.repository.UserUploadMstrVO;
import com.wise.ds.repository.dao.DataSetDAO;
import com.wise.ds.repository.dataset.DataSetConst;
import com.wise.ds.repository.dataset.EmptyDataSetInformationException;
import com.wise.ds.repository.dataset.NotFoundDataSetTypeException;
import com.wise.ds.repository.dataset.NotFoundDatabaseConnectorException;
import com.wise.ds.repository.service.ConditionDefaultValueQueryService;
import com.wise.ds.repository.service.ConfigService;
import com.wise.ds.repository.service.DataSetService;
import com.wise.ds.repository.service.ReportConditionService;
import com.wise.ds.repository.service.ReportService;
import com.wise.ds.repository.service.impl.QueryResultCacheManager;
import com.wise.ds.sql.CubeTable;
import com.wise.ds.sql.CubeTableColumn;
import com.wise.ds.util.Json2Xml;
import com.wise.ds.util.ScheduleThread;
import com.wise.ds.util.SparkLoad;
import com.wise.ds.util.WebFileUtils;
import com.wise.ds.util.Xml2Json;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import wise.querygen.dto.Hierarchy;
import wise.querygen.dto.Relation;
import wise.querygen.dto.SelectCube;
import wise.querygen.dto.SelectCubeEtc;
import wise.querygen.dto.SelectCubeMeasure;
import wise.querygen.dto.SelectCubeOrder;
import wise.querygen.dto.SelectCubeWhere;
import wise.querygen.service.QuerySettingEx;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << ????????????(Modification Information) >>
 *     ?????????                 ?????????             ????????????   
 *  ----------    --------    ---------------------------
 *  2015.06.08      DOGFOOT             ?????? ??????
 * </pre>
 */

@Controller
@RequestMapping(value = "/report")
public class ReportController {
	private static final Logger logger = LoggerFactory.getLogger(ReportController.class);
	
	private static final long MAX_CACHEABLE_SUMMARY_MATRIX_SIZE = 100L * 1024L * 1024L; //100MB
	
	@Autowired 
	private Xml2Json xml2Json;
	
    @Autowired
    private SparkLoad sparkLoad;	
	
    @Resource(name = "reportService")
    private ReportService reportService;
    
    @Resource(name = "reportConditionService")
    private ReportConditionService reportConditionService;
    
    @Resource(name = "conditionDefaultValueQueryService")
    private ConditionDefaultValueQueryService conditionDefaultValueQueryService;
    
    @Resource(name = "dataSetService")
    private DataSetService dataSetServiceImpl;
    
    @Resource(name = "configService")
    private ConfigService configService;
    
    @Resource(name = "sqlStorage")
    private SqlStorage sqlStorage;
    
    @Resource(name = "authenticationService")
    private AuthenticationService authenticationService;
    
    @Resource(name = "wiseMessageSource")
    private WiseMessageSource messageSource;
    
    @Resource(name = "sqlConvertor")
	private SqlConvertor sqlConvertor;
    
    @Resource(name = "sqlMapper")
	private SqlMapper sqlMapper;
    
    @Resource(name = "dataSetDAO")
    private DataSetDAO dataSetDAO;
    
    @Resource(name = "authenticationDAO")
    private AuthenticationDAO authenticationDAO;
    
    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private DataAggregator dataAggregator;
    
    @Autowired
    private QueryResultCacheManager queryResultCacheManager;
    
    @Autowired
    private SummaryMatrixFileWriterService summaryMatrixFileWriterService;
    
    @Autowired
    private SummaryMatrixProvider summaryMatrixProvider;
    
    private JSONArray session = new JSONArray();
    private static String keyStr = "wiseitech_witeam";
    private static SecretKeySpec key = null;
    private static IvParameterSpec iniVec = null;
    
    public static final String UTF8_BOM = "\uFEFF";    
    
    private void authenticateReport(HttpServletRequest request, int reportId) {
        boolean doAuthn = Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication");
        boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
        try {
	        if (doAuthn) {
	            String authnMethod = Configurator.getInstance().getConfig("wise.ds.authentication.method", "SESSION");
	//            boolean sessionEnabled = Configurator.getInstance().getConfigBooleanValue("wise.ds.session");
	            if ("PARAMETER".equalsIgnoreCase(authnMethod)) {
	                String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
	                String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
	                String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
	                String userId = SecureUtils.getParameter(request, authnKey);
	                User user = this.authenticationService.getRepositoryUser(userId);
	                    
	                if (user == null) {
	                    
							throw new NotFoundUserException(this.messageSource.getMessage("signin.user.noexist.1", new String[]{userId}));
	                }
	                
//	                if(logUse) {
//	                	Timer time = new Timer();
//	                	time.start();
//	                	ReportMasterVO reportMasterVo = this.reportService.selectReportForLog(reportId, Configurator.Constants.WISE_REPORT_TYPE);
//	                	time.stop();
//	                	ReportLogMasterVO logVO = new ReportLogMasterVO();
//	//                	String ip = new WiseResource().getClientIP(request);
//	                	String ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
//	                	logVO.setReportUtilLog(Timer.formatTime(time.getStartTime()), reportId, reportMasterVo.getREPORT_NM(),  "DashAny", user.getId(), user.getName(), user.getNo(), user.getGRP_ID(), "", ip, "", "WB");
//	                  	this.reportService.enrollReportUseLog(logUse,logVO);
//	                }
	//                if(sessionEnabled) {
	//                	String ip = request.getHeader("X-Forwarded-For");
	//                    
	//                    logger.info(">>>> X-FORWARDED-FOR : " + ip);
	//
	//                    if (ip == null) {
	//                        ip = request.getHeader("Proxy-Client-IP");
	//                        logger.info(">>>> Proxy-Client-IP : " + ip);
	//                    }
	//                    if (ip == null) {
	//                        ip = request.getHeader("WL-Proxy-Client-IP"); // ?????????
	//                        logger.info(">>>> WL-Proxy-Client-IP : " + ip);
	//                    }
	//                    if (ip == null) {
	//                        ip = request.getHeader("HTTP_CLIENT_IP");
	//                        logger.info(">>>> HTTP_CLIENT_IP : " + ip);
	//                    }
	//                    if (ip == null) {
	//                        ip = request.getHeader("HTTP_X_FORWARDED_FOR");
	//                        logger.info(">>>> HTTP_X_FORWARDED_FOR : " + ip);
	//                    }
	//                    if (ip == null) {
	//                        ip = request.getRemoteAddr();
	//                    }
	//                    logger.info(">>>> Result : IP Address : "+ip);
	//                    String sessionkey = ip + userId;
	//                    byte[] sessionByte = sessionkey.getBytes();
	//                    MessageDigest digest;
	//                    digest = MessageDigest.getInstance("SHA-256");
	//        			digest.update(sessionByte);
	//        	        byte[] encryptSession = digest.digest();
	//        	        if(session.size() == 0)
	//        	        	throw new NotFoundUserException(this.messageSource.getMessage("signin.user.nouser.enrolled"));
	//                    for(int i=0;i<session.size();i++) {
	//                    	JSONObject obj = session.getJSONObject(i);
	//                    	if(obj.get("sessionKey").equals(new String(encryptSession))) {
	//                    		long diff = request.getSession(false).getLastAccessedTime() - obj.getLong("enrollTime");
	//                    		if((diff/1000)>=request.getSession(false).getMaxInactiveInterval()) {
	//                    			logger.debug("???????????? : "+(diff/1000));
	//                    			throw new NotFoundUserException(this.messageSource.getMessage("signin.user.expired"));
	//                    		}
	//                    		else {
	//                    			session.getJSONObject(i).put("enrollTime", request.getSession(false).getLastAccessedTime());
	//                    			logger.debug("revoke Session" +request.getSession(false).getLastAccessedTime());
	//                    		}
	//                    	}
	//                    }
	//                }
	//                request.getSession(false).setAttribute(sessionUserKey, user);
	//                logger.debug("session user =======> "+sessionUserKey+"\t"+user);
	            }
	            
	            User sessionUser = this.authenticationService.getSessionUser(request);
	            if (sessionUser == null) {
	                throw new NotFoundUserException(this.messageSource.getMessage("signin.user.not.login"));
	            }
	            
	            this.authenticationService.authenticate(sessionUser, reportId, Configurator.Constants.WISE_REPORT_TYPE);
	        }
	        else {
//	            if(logUse) {
//	            	Timer time = new Timer();
//	            	time.start();
//	            	ReportMasterVO reportMasterVo = this.reportService.selectReportForLog(reportId, Configurator.Constants.WISE_REPORT_TYPE);
//	            	time.stop();
//	            	ReportLogMasterVO logVO = new ReportLogMasterVO();
//	//            	String ip = new WiseResource().getClientIP(request);
//	            	String ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
//	            	logVO.setReportUtilLog(Timer.formatTime(time.getStartTime()), reportId, reportMasterVo.getREPORT_NM(),  "DashAny", "", "", 0, 0, "", ip, "", "WB");
//	            	this.reportService.enrollReportUseLog(logUse,logVO);
//	            }
	//          String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
	//          String userId = SecureUtils.getParameter(request, authnKey, "admin");
	//          User user = this.authenticationService.getRepositoryUser(userId);
	//          String path = "";
	//          java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
	//  		if(osBean.getName().indexOf("Windows") != -1) {
	//  			path = request.getSession(false).getServletContext().getRealPath("/")+"DataFiles\\";
	//  		}else {
	//  			path = request.getSession(false).getServletContext().getRealPath("/")+"DataFiles/";
	//  		}
	//  		
	//          ScheduleThread st = new ScheduleThread(this.reportService, this.sqlStorage, this.dataSetServiceImpl,user.getNo(), path);
	//          Thread t = new Thread(st, "test");
	//          t.start();
	        }
        } catch (Exception e) {
			e.printStackTrace();
		}
    }
    
    private void authenticateReport(HttpServletRequest request, int reportId,String reportType) throws Exception {
        boolean doAuthn = Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication");
        boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
        if (doAuthn) {
            String authnMethod = Configurator.getInstance().getConfig("wise.ds.authentication.method", "SESSION");
//            boolean sessionEnabled = Configurator.getInstance().getConfigBooleanValue("wise.ds.session");
            if ("PARAMETER".equalsIgnoreCase(authnMethod)) {
                String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
                String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
                String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
                String userId = SecureUtils.getParameter(request, authnKey);
                User user = this.authenticationService.getRepositoryUser(userId);
                    
                if (user == null) {
                    throw new NotFoundUserException(this.messageSource.getMessage("signin.user.noexist.1", new String[]{userId}));
                }
                
                if(logUse) {
                	Timer time = new Timer();
                	time.start();
                	ReportMasterVO reportMasterVo = this.reportService.selectReportForLog(reportId, Configurator.Constants.WISE_REPORT_TYPE);
                	time.stop();
                	ReportLogMasterVO logVO = new ReportLogMasterVO();
//                	String ip = new WiseResource().getClientIP(request);
                	String ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
//                	logVO.setReportUtilLog(Timer.formatTime(time.getStartTime()), reportId, reportMasterVo.getREPORT_NM(),  "DashAny", user.getId(), user.getName(), user.getNo(), user.getGRP_ID(), "", ip, "", "WB");
//                	logVO.setReportUseLog(String.valueOf(Timer.formatTime(time.getStartTime())),pid,reportMasterVo.getREPORT_NM(),logReportType,user.getUSER_ID(),user.getUSER_NM(),user.getUSER_NO(),user.getGRP_ID(),""/*user.getGrpnm()*/,ip,Timer.formatTime(timer.getStartTime()),Timer.formatTime(0),status,"DT");
//                  	this.reportService.enrollReportUseLog(logUse,logVO);
                }
            }
            
            User sessionUser = this.authenticationService.getSessionUser(request);
            if (sessionUser == null) {
                throw new NotFoundUserException(this.messageSource.getMessage("signin.user.not.login"));
            }
            
            this.authenticationService.authenticate(sessionUser, reportId, reportType);
        }
        else {
            if(logUse) {
            	Timer time = new Timer();
            	time.start();
            	ReportMasterVO reportMasterVo = this.reportService.selectReportForLog(reportId, reportType);
            	time.stop();
            	ReportLogMasterVO logVO = new ReportLogMasterVO();
//            	String ip = new WiseResource().getClientIP(request);
//            	String ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
//            	logVO.setReportUtilLog(Timer.formatTime(time.getStartTime()), reportId, reportMasterVo.getREPORT_NM(),  "DashAny", "", "", 0, 0, "", ip, "", "WB");
//              	this.reportService.enrollReportUseLog(logUse,logVO);
            }
        }
//        String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
//        String userId = SecureUtils.getParameter(request, authnKey, "admin");
//        User user = this.authenticationService.getRepositoryUser(userId);
//        String path = "";
//        java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
//		if(osBean.getName().indexOf("Windows") != -1) {
//			path = request.getSession(false).getServletContext().getRealPath("/")+"DataFiles\\";
//		}else {
//			path = request.getSession(false).getServletContext().getRealPath("/")+"DataFiles/";
//		}
//		
//        ScheduleThread st = new ScheduleThread(this.reportService, this.sqlStorage, this.dataSetServiceImpl,user.getNo(), path);
//        Thread t = new Thread(st, "test");
//        t.start();
    }
    
    
    
    /**
     * Returns JSON containing user info and master configuration settings.
     * @param user Object representing current user
     * @return JSON object with user and config information
     */
    private JSONObject getUserConfigurations(User user) {
    	JSONObject result = new JSONObject();
    	ConfigMasterVO configVo = authenticationService.getConfigMstr();
        WebConfigMasterVO webConfigVo = authenticationService.getWebConfigMstr();
        UserConfigVO userConfigVo = configService.selectUserConfig(user.getUSER_NO());

        org.json.JSONObject menuConfigJson = new org.json.JSONObject(webConfigVo.getMENU_CONFIG());
      //20210706 ?????? ?????? menuConfig??? ?????? dogfoot
        if(menuConfigJson.getJSONObject("Menu").has("USE_MENU_AUTH") && menuConfigJson.getJSONObject("Menu").getBoolean("USE_MENU_AUTH"))
        {
        	List<HashMap> menuAuth = configService.selectUserWbAuth(user.getUSER_NO());
        	if(menuAuth.size() == 0) {
        		menuAuth = configService.selectGrpWbAuth(Integer.toString(user.getGRP_ID()));
        	}
        	JSONObject menuAuthJson = new JSONObject();
        	if(menuAuth.size() > 0) {
        		menuAuthJson.put("ADHOC", menuAuth.get(0).get("ADHOC_AUTH"));
        		menuAuthJson.put("DASH", menuAuth.get(0).get("DASH_AUTH"));
        		menuAuthJson.put("EXCEL", menuAuth.get(0).get("EXCEL_AUTH"));
        		menuAuthJson.put("ANAL", menuAuth.get(0).get("ANAL_AUTH"));
        		menuAuthJson.put("DS", menuAuth.get(0).get("DS_AUTH"));
        		menuAuthJson.put("CONFIG", menuAuth.get(0).get("CONFIG_AUTH"));
        		menuAuthJson.put("DSVIEWER", menuAuth.get(0).get("DS_VIEWER_AUTH"));
        		menuAuthJson.put("DS_DETAIL", menuAuth.get(0).get("DS_AUTH_DETAIL"));

        		org.json.JSONObject dsAuthDetail = new org.json.JSONObject(menuAuth.get(0).get("DS_AUTH_DETAIL").toString());
        		org.json.JSONObject dsMenuType = menuConfigJson.getJSONObject("Menu").getJSONObject("DATASET_MENU_TYPE");
        		dsMenuType.put("CUBE", dsAuthDetail.getBoolean("CUBE"));
        		if(dsMenuType.getBoolean("DataSetDs"))
        			dsMenuType.put("DataSetDs", dsAuthDetail.getBoolean("DataSetDs"));
        		if(dsMenuType.getBoolean("DataSetDsJoin"))
        			dsMenuType.put("DataSetDsJoin", dsAuthDetail.getBoolean("DataSetDsJoin"));
        		if(dsMenuType.getBoolean("DataSetCube"))
        			dsMenuType.put("DataSetCube", dsAuthDetail.getBoolean("DataSetCube"));
        		if(dsMenuType.getBoolean("DataSetLoad"))
        			dsMenuType.put("DataSetLoad", dsAuthDetail.getBoolean("DataSetLoad"));
        		if(dsMenuType.getBoolean("DataSetSQL"))
        			dsMenuType.put("DataSetSQL", dsAuthDetail.getBoolean("DataSetSQL"));
        		if(dsMenuType.getBoolean("DataSetSingleDs"))
        			dsMenuType.put("DataSetSingleDs", dsAuthDetail.getBoolean("DataSetSingleDs"));
        		if(dsMenuType.getBoolean("DataSetUser"))
        			dsMenuType.put("DataSetUser", dsAuthDetail.getBoolean("DataSetUser"));

        		org.json.JSONObject leftMenuConfig = menuConfigJson.getJSONObject("Menu").getJSONObject("PROG_MENU_TYPE");

        		if(leftMenuConfig.getJSONObject("AdHoc").getBoolean("visible"))
        			leftMenuConfig.getJSONObject("AdHoc").put("visible", menuAuth.get(0).get("ADHOC_AUTH").equals("Y")? true : false);
        		if(leftMenuConfig.getJSONObject("Analysis").getBoolean("visible"))
        			leftMenuConfig.getJSONObject("Analysis").put("visible", menuAuth.get(0).get("ANAL_AUTH").equals("Y")? true : false);
        		if(leftMenuConfig.getJSONObject("Config").getBoolean("visible"))
        			leftMenuConfig.getJSONObject("Config").put("visible", menuAuth.get(0).get("CONFIG_AUTH").equals("Y")? true : false);
        		if(leftMenuConfig.getJSONObject("DSViewer").getBoolean("visible"))
        			leftMenuConfig.getJSONObject("DSViewer").put("visible", menuAuth.get(0).get("DS_VIEWER_AUTH").equals("Y")? true : false);
        		if(leftMenuConfig.getJSONObject("DashAny").getBoolean("visible"))
        			leftMenuConfig.getJSONObject("DashAny").put("visible", menuAuth.get(0).get("DASH_AUTH").equals("Y")? true : false);
        		if(leftMenuConfig.getJSONObject("DataSet").getBoolean("visible"))
        			leftMenuConfig.getJSONObject("DataSet").put("visible", menuAuth.get(0).get("DS_AUTH").equals("Y")? true : false);
        		if(leftMenuConfig.getJSONObject("Excel").getBoolean("visible"))
        			leftMenuConfig.getJSONObject("Excel").put("visible", menuAuth.get(0).get("EXCEL_AUTH").equals("Y")? true : false);
        	}
        	else {
        		menuAuthJson.put("ADHOC", false);
        		menuAuthJson.put("DASH",false);
        		menuAuthJson.put("EXCEL", false);
        		menuAuthJson.put("ANAL", false);
        		menuAuthJson.put("DS", false);
        		menuAuthJson.put("CONFIG", false);
        		menuAuthJson.put("DSVIEWER", false);
        		menuAuthJson.put("DS_DETAIL", false);

        		org.json.JSONObject dsMenuType = menuConfigJson.getJSONObject("Menu").getJSONObject("DATASET_MENU_TYPE");
        		dsMenuType.put("CUBE", false);
        		dsMenuType.put("DataSetDs", false);
        		dsMenuType.put("DataSetDsJoin", false);
        		dsMenuType.put("DataSetCube", false);
        		dsMenuType.put("DataSetLoad",false);
        		dsMenuType.put("DataSetSQL", false);
        		dsMenuType.put("DataSetSingleDs", false);
        		dsMenuType.put("DataSetUser", false);

        		org.json.JSONObject leftMenuConfig = menuConfigJson.getJSONObject("Menu").getJSONObject("PROG_MENU_TYPE");

        		leftMenuConfig.getJSONObject("AdHoc").put("visible", false);
        		leftMenuConfig.getJSONObject("Analysis").put("visible", false);
        		leftMenuConfig.getJSONObject("Config").put("visible", false);
        		leftMenuConfig.getJSONObject("DSViewer").put("visible", false);
        		leftMenuConfig.getJSONObject("DashAny").put("visible", false);
        		leftMenuConfig.getJSONObject("DataSet").put("visible", false);
        		leftMenuConfig.getJSONObject("Excel").put("visible", false);
        	}
        }
        
        
        String authMode = "viewer";
        UserGroupVO runMode = this.authenticationService.selectUserGroupRunMode(user);
		boolean grpMode = false;
		if(runMode.getUSER_RUN_MODE() == null || "".equals(runMode.getUSER_RUN_MODE())) {
			grpMode = true;
		}
		if(runMode != null && "ADMIN".equals(runMode.getUSER_RUN_MODE())) {
			authMode = "admin";
		} else if(runMode != null && "ADMIN".equals(runMode.getGRP_RUN_MODE()) && grpMode) {
			authMode = "admin";
		}
		
		// admin ????????? ????????? ????????? ???????????? visible false
//		if (!authMode.equals("admin")) {
//			leftMenuConfig.getJSONObject("Config").put("visible", false);
//		}
		
		String grpNm = "";
		
		if(runMode != null) {
			grpNm = runMode.getGRP_NM();
		}
		// global config
        result.put("mainTitle", configVo.getMAIN_TITLE());
        result.put("defaultPalette", configVo.getDASHBOARD_DEFAULT_PALETTE());
        result.put("defaultLayout", configVo.getDEFAULT_LAYOUT());
        result.put("showNullValue", "Y".equals(configVo.getNULL_VALUE_YN()));
        result.put("grpNm", grpNm);
        String nullValueString = configVo.getNULL_VALUE_STRING();
        if(nullValueString == null || nullValueString.equals("null")) {
        	nullValueString = "NULL";
        }
        result.put("nullValueString", nullValueString);
        result.put("searchLimitTime", configVo.getSEARCH_LIMIT_TIME());
        result.put("searchLimitRow", configVo.getSEARCH_LIMIT_SIZE());
        /* DOGFOOT ktkang ?????? ?????? ?????? ?????? ??????  20200922 */
        result.put("limitWorks", configVo.getLIMIT_WORKS());
        result.put("siteNm", configVo.getSITE_NM());
        result.put("spreadLisence",webConfigVo.getSPREAD_JS_LICENSE());
        result.put("dashboardLayout", webConfigVo.getDASHBOARD_LAYOUT());
        result.put("pivotAlignCenter", webConfigVo.getPIVOT_ALIGN_CENTER());
        result.put("gridAutoAlign", webConfigVo.getGRID_AUTO_ALIGN());
        /* DOGFOOT ktkang ????????? ????????? ?????? ????????? ???????????? ???????????? ?????? ??????  20200903 */
        result.put("gridDataPaging", webConfigVo.getGRID_DATA_PAGING());
        result.put("logo", webConfigVo.getLOGO());
        result.put("excelDownloadServerCount", webConfigVo.getEXCEL_DOWNLOAD_SERVER_COUNT());
        /* DOGFOOT ktkang ????????? ?????? ?????? ?????? ?????? ??????  20201015 */
        result.put("reportDirectView", webConfigVo.getREPORT_DIRECT_VIEW());
        /* DOGFOOT syjin LAYOUT_CONFIG ??????  20200814 */
        result.put("layoutConfig", webConfigVo.getLAYOUT_CONFIG());
        /* DOGFOOT syjin kakaoMap ??????  20200819 */
        result.put("kakaoMapApi", webConfigVo.getKAKAO_MAP_API_KEY());
        /* DOGFOOT ktkang ???????????? ?????? ?????? ??????, ?????? ???????????? ?????? ?????? ??????  20201013 */
        result.put("downloadFilter", webConfigVo.getDOWNLOAD_FILTER_YN());
        /* DOGFOOT ktkang BMT ???????????? ???????????? ??????  20201201 */
        result.put("oldSchedule", webConfigVo.getOLD_SCHEDULE_YN());
        result.put("pivotDrillUpDown", webConfigVo.getPIVOT_DRILL_UPDOWN());
        /*dogfoot userJsonObject ??? menu ?????? shlim 20210319*/
        result.put("menuconfig", menuConfigJson.toString());
        // user config
        result.put("userNo", user.getUSER_NO());
        result.put("userId", user.getUSER_ID());
        result.put("userNm", user.getUSER_NM());
        result.put("userRelCode", user.getUSER_REL_CD());
        result.put("userAuth", authMode);
        if(userConfigVo.getUSER_IMAGE() != null  && !userConfigVo.getUSER_IMAGE().equals("1001")) {
        	result.put("userImage", userConfigVo.getUSER_IMAGE());
        }
        result.put("userDatasetId", userConfigVo.getDEFAULT_DATASET_ID());
        result.put("userDatasetNm", userConfigVo.getDEFAULT_DATASET_NM());
        result.put("userReportId", userConfigVo.getDEFAULT_REPORT_ID());
        result.put("userReportNm", userConfigVo.getDEFAULT_REPORT_NM());
        result.put("userReportType", userConfigVo.getDEFAULT_REPORT_TYPE());
        result.put("userItemType", userConfigVo.getDEFAULT_ITEM());
        result.put("userPalette", userConfigVo.getDEFAULT_PALETTE());
        result.put("userViewerReportId", userConfigVo.getDEFAULT_VIEWER_REPORT_ID());
        result.put("userViewerReportNm", userConfigVo.getDEFAULT_VIEWER_REPORT_NM());
        result.put("userViewerReportType", userConfigVo.getDEFAULT_VIEWER_REPORT_TYPE());
        result.put("fontConfig", userConfigVo.getFONT_CONFIG());
        
    	return result;
    }
    
    private String requestPage(int pid, HttpServletRequest request, Model model) {
        String redirector;

        String browserType = BrowserUtils.getType(request);
        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
       /* for (String deny : denyBrowser) {
            if (deny.equalsIgnoreCase(browserType)) {
                model.addAttribute("BROWSER_TYPE", browserType);
                throw new UnSupportedBrowserException();
            }
        }*/
        
        this.authenticateReport(request, pid);
        
        model.addAttribute("pid", pid);
        logger.debug("invoke page : " + pid);
        
        redirector = "reportViewer";
        
        /* DOGFOOT syjin kakao map ?????? ?????? ??????  20200819 */
        WebConfigMasterVO webConfig = this.authenticationService.getWebConfigMstr();
        String kakaoMapApi = webConfig.getKAKAO_MAP_API_KEY();
        
        model.addAttribute("kakaoMapApi", kakaoMapApi);
        logger.debug("kakaoApiKey : " + kakaoMapApi);
        return redirector;
    }
    
    private String requestExcelPage(int pid, HttpServletRequest request, Model model) {
        String redirector;

        String browserType = BrowserUtils.getType(request);
        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
        
        this.authenticateReport(request, pid);
        
        model.addAttribute("pid", pid);
        logger.debug("invoke page : " + pid);
        
        redirector = "reportExcel";

        return redirector;
    }
    
    private String requestPage(int pid, HttpServletRequest request, Model model,String redirector,String reportType) throws Exception {

        String browserType = BrowserUtils.getType(request);
        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
       /* for (String deny : denyBrowser) {
            if (deny.equalsIgnoreCase(browserType)) {
                model.addAttribute("BROWSER_TYPE", browserType);
                throw new UnSupportedBrowserException();
            }
        }*/
        
        this.authenticateReport(request, pid, reportType);
        
        model.addAttribute("pid", pid);
        logger.debug("invoke page : " + pid);
        
        return redirector;
    }
    
    private User byPassSession(HttpServletRequest request) throws Exception {
    	request.setCharacterEncoding("utf-8");
        String authnMethod = Configurator.getInstance().getConfig("wise.ds.authentication.method", "SESSION");
        User user = null;
        if ("PARAMETER".equalsIgnoreCase(authnMethod)) {
            String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
            String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
            String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
            String userId = SecureUtils.getParameter(request, authnKey);
            String byPassKeyEncrypted = request.getParameter("assign_name");
            String byPassPWD = "meis";
            if(byPassKeyEncrypted != null) {
            	
            	String assignNameSecurity = Configurator.getInstance().getConfig("wise.ds.assign_name.security");
            	String byPassKey = "";
            	
            	if(assignNameSecurity.equals("aes")) {
            		//AES+MD5 ?????????
	            	Cipher cipher = null;
	                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	                
	        		// Initialize an encryption key and an initial vector.
	                MessageDigest md5 = MessageDigest.getInstance("MD5");
	                key = new SecretKeySpec(md5.digest(keyStr.getBytes("UTF8")), "AES");
	                iniVec = new IvParameterSpec(md5.digest(keyStr.getBytes("UTF8")));
	        		
	                cipher.init(Cipher.DECRYPT_MODE, key, iniVec);
	                byte[] encryptedValue = Base64Encoder.decode(byPassKeyEncrypted);
	                byte[] decryptedValue = cipher.doFinal(encryptedValue);
	
	        		// Return a string converted from the UTF-8 byte array.
	        		byPassKey = new String(decryptedValue, "UTF8");
            	} else {
            		//BASE64 ?????????
	            	byPassKey = new String(Base64Encoder.decode(byPassKeyEncrypted), "UTF-8");
	            }
        		if(byPassKey.equals(byPassPWD)) {
        			AES256Cipher a256 = AES256Cipher.getInstance();
        			userId = a256.decryptAESMD5(userId);
        			user = this.authenticationService.getRepositoryUser(userId);
                    
                    if (user == null) {
                        throw new NotFoundUserException(this.messageSource.getMessage("signin.user.noexist.1", new String[]{userId}));
                    }
                    request.getSession(true).setAttribute(sessionUserKey,user);
        		}
            }
        } else {
            String userId = SecureUtils.getParameter(request, "USER");
			user = this.authenticationService.getRepositoryUser(userId);
        }
        return user;
        
    }
    
    private User byPassSessionEncode(HttpServletRequest request) throws Exception {
    	request.setCharacterEncoding("utf-8");
        String authnMethod = Configurator.getInstance().getConfig("wise.ds.authentication.method", "SESSION");
        User user = null;
        if ("PARAMETER".equalsIgnoreCase(authnMethod)) {
            String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
            String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
            String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
            String userId = SecureUtils.getParameter(request, authnKey);
        	userId = URLDecoder.decode(userId, "UTF-8");
            String byPassKeyEncrypted = request.getParameter("assign_name");
            String byPassPWD = "meis";
            if(byPassKeyEncrypted != null) {
            	
            	String assignNameSecurity = Configurator.getInstance().getConfig("wise.ds.assign_name.security");
            	String byPassKey = "";
            	
            	if(assignNameSecurity.equals("aes")) {
            		//AES+MD5 ?????????
	            	Cipher cipher = null;
	                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	                
	        		// Initialize an encryption key and an initial vector.
	                MessageDigest md5 = MessageDigest.getInstance("MD5");
	                key = new SecretKeySpec(md5.digest(keyStr.getBytes("UTF8")), "AES");
	                iniVec = new IvParameterSpec(md5.digest(keyStr.getBytes("UTF8")));
	        		
	                cipher.init(Cipher.DECRYPT_MODE, key, iniVec);
	                byte[] encryptedValue = Base64Encoder.decode(byPassKeyEncrypted);
	                byte[] decryptedValue = cipher.doFinal(encryptedValue);
	
	        		// Return a string converted from the UTF-8 byte array.
	        		byPassKey = new String(decryptedValue, "UTF8");
            	} else {
            		//BASE64 ?????????
	            	byPassKey = new String(Base64Encoder.decode(byPassKeyEncrypted), "UTF-8");
	            }
        		if(byPassKey.equals(byPassPWD)) {
        			user = this.authenticationService.getRepositoryUser(userId);
                    
                    if (user == null) {
                        throw new NotFoundUserException(this.messageSource.getMessage("signin.user.noexist.1", new String[]{userId}));
                    }
                    request.getSession(true).setAttribute(sessionUserKey,user);
        		}
            }
        } else {
        	String userId = SecureUtils.getParameter(request, "USER");
			user = this.authenticationService.getRepositoryUser(userId);
        }
        return user;
        
    }
    
    @RequestMapping(value = {"/edit.do"})
    private ModelAndView requestPageView(HttpServletRequest request, Model model) throws Exception {
        String redirector = "reportDesigner";
        ModelAndView mv = new ModelAndView(redirector);

        String browserType = BrowserUtils.getType(request);
        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
       /* for (String deny : denyBrowser) {
            if (deny.equalsIgnoreCase(browserType)) {
                model.addAttribute("BROWSER_TYPE", browserType);
                throw new UnSupportedBrowserException();
            }
        }*/
        
        String cubeId = SecureUtils.getParameter(request, "cubeId");
        String reportId = SecureUtils.getParameter(request, "reportId");
        String mainAdhoc = SecureUtils.getParameter(request, "mainAdhoc");
        /* DOGFOOT ktkang ????????? ???????????? ?????? ??????  20200903 */
        String reportSeq = SecureUtils.getParameter(request, "reportSeq");
        String reportType = SecureUtils.getParameter(request, "reportType");
        /* DOGFOOT ktkang ?????? ?????? ?????? ??????  20201102 */
        String staticAnalysis = SecureUtils.getParameter(request, "staticAnalysis");
        String rAnalysis = SecureUtils.getParameter(request, "rAnalysis");
        /* 20210201 AJKIM ??????????????? ?????? ?????? dogfoot */
        String dataSetViewer = SecureUtils.getParameter(request, "dataSetViewer");
        
        try {
        	User user = this.authenticationService.getSessionUser(request);
        	
        	String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
            String userId = SecureUtils.getParameter(request, authnKey);
            String byPassKeyEncrypted = request.getParameter("assign_name");
            if(userId != null && !"1001".equals(userId) && byPassKeyEncrypted != null && !"1001".equals(byPassKeyEncrypted)) {
        		user = byPassSession(request);
        		if(user == null) {
        			throw new NotFoundUserException("signin.user.not.login");
        		}
            }
        	if(user == null) {
        		logger.debug("?????? ?????? ?????? ?????????");
        		user = byPassSession(request);
        		if(user == null) {
        			throw new NotFoundUserException("signin.user.not.login");
        		}
        	}
        	logger.debug(redirector);
        	if (user != null) {
        		
        		
        		/* shlim ????????? ????????? ?????? ?????? ????????? or ???????????? ????????? ?????? ?????? ??????*/
        		UserGroupVO runMode = this.authenticationService.selectUserGroupRunMode(user);
				boolean grpMode = false;
				boolean editMode = true;
				if(runMode.getUSER_RUN_MODE() == null || runMode.getUSER_RUN_MODE().equals("")) {
					grpMode = true;
				}
				String userId2 = URLEncoder.encode(user.getUSER_ID(), "UTF-8");
				String href = "";
				if (runMode == null) {
					editMode = true;
				} else if (grpMode && runMode.getGRP_RUN_MODE().equals("ADMIN") || (runMode.getUSER_RUN_MODE() != null && runMode.getUSER_RUN_MODE().equals("ADMIN"))) {
					editMode = true;
				} else if (grpMode  && runMode.getGRP_RUN_MODE().equals("VIEW")) {
					href = "report/viewer.do";
					mv = new ModelAndView("redirect:/"+href);
					Map<String, Object> map = new HashMap<String,Object>();
				    map.put("USER", userId);
				    map.put("assign_name", "bWVpcw==");

					mv.addAllObjects(map);
					editMode = false;
				} else if (runMode.getUSER_RUN_MODE() != null && runMode.getUSER_RUN_MODE().equals("VIEW")) {
					href = "report/viewer.do";
					mv = new ModelAndView("redirect:/"+href);
					Map<String, Object> map = new HashMap<String,Object>();
				    map.put("USER", userId);
				    map.put("assign_name", "bWVpcw==");

					mv.addAllObjects(map);
					editMode = false;
				} else {
					editMode = true;
				}
        		
				if(editMode) {
					JSONObject obj = getUserConfigurations(user);
	        		/* DOGFOOT ktkang ????????? ???????????? ?????? ??????  20200903 */
	        		if(reportSeq != null && !reportSeq.equals("1001")) {
	        			obj.put("userReportId", reportId);
	        			obj.put("userReportSeq", reportSeq);
	        			obj.put("userReportType", reportType);
	        		} else if(reportId != null && !reportId.equals("1001")) {
	        			obj.put("userReportId", reportId);
	        			obj.put("userReportType", "AdHoc");
	        		}
	        		//DOGFOOT MKSONG KERIS IF ??? ?????? 20200219 
	        		if(cubeId != null && !cubeId.equals("1001")) {
	        			/*dogfoot ???????????? url ????????? ??? ???????????? ???????????? shlim 20201209*/
//	        			obj.put("userItemType", "AdHoc");
	        			obj.put("userReportType", "DashAny");
	        			obj.put("selectCubeId", cubeId);
	        			/* DOGFOOT ktkang ????????? ?????? ????????? ??? ??? ?????? ?????? ????????? ??????????????? ??????  20200120 */
	        		} else if(mainAdhoc != null && mainAdhoc.equals("mainAdhoc")) {
	        			obj.put("userItemType", "AdHoc");
	        		} else if(staticAnalysis != null && "staticAnalysis".equals(staticAnalysis)) {
	        			obj.put("userItemType", "StaticAnalysis");
	        			obj.put("userAnalysisType", SecureUtils.getParameter(request, "staticAnalysisType"));
	        		} else if(rAnalysis != null && "rAnalysis".equals(rAnalysis)) {
	        			obj.put("userItemType", "RAnalysis");
	        		} else if(dataSetViewer != null && "dataSetViewer".equals(dataSetViewer)) {
	        			obj.put("userItemType", "DSViewer");
	        		}
	        		org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper();
	        		String jsonData = objectMap.writeValueAsString(obj);
	        		logger.debug(jsonData);
	        		
	        		//DOGFOOT syjin kakao map ?????? ?????? ?????? 20200819
	        		mv.addObject("kakaoMapApi", this.authenticationService.getWebConfigMstr().getKAKAO_MAP_API_KEY());
	        		mv.addObject("returnArr",jsonData);
	        		mv.addObject("mainTitle", obj.getString("mainTitle"));
				}
				
        		
        		
        	} else if(user == null) {
        		user = byPassSession(request);
        		if(user == null) {
        			throw new NotFoundUserException("signin.user.not.login");
        		}
        	}
        } catch (NotFoundUserException e) {
        	mv = new ModelAndView("redirect:/login.do");
        }
        return mv;
    }
    
    @RequestMapping(value = {"/excel.do"})
    private ModelAndView requestExcelView(HttpServletRequest request, Model model, HttpServletResponse resp) throws Exception {
        String redirector = "reportExcel";
        ModelAndView mv = new ModelAndView(redirector);

        String browserType = BrowserUtils.getType(request);
        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
        
        // handle user session
        User user = this.authenticationService.getSessionUser(request);
        if (user == null) {
        	throw new NotFoundUserException("signin.user.not.login");
        } else {
        	JSONObject obj = getUserConfigurations(user);
        	org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
            String jsonData = objectMap.writeValueAsString(obj);
            logger.debug(jsonData);
            mv.addObject("returnArr",jsonData);
            mv.addObject("mainTitle", obj.getString("mainTitle"));
        }
        
        return mv;
    }
    
    @RequestMapping(value = {"/{pid}/excel.do"}, method = RequestMethod.GET)
    public ModelAndView excelViewPage(HttpServletRequest request, @PathVariable("pid")int pid, Model model) throws Exception {
        String redirector;
        ModelAndView mv = null;

        if (!Configurator.getInstance().getConfigBooleanValue("wise.ds.report.view.support.restful")) {
            throw new UnSupportedRequestException("by restful");
        }
        
        redirector = this.requestExcelPage(pid, request, model);
        
        mv = new ModelAndView(redirector);
        // handle user session
        User user = this.authenticationService.getSessionUser(request);
        if (user == null) {
        	throw new NotFoundUserException("signin.user.not.login");
        } else {
        	JSONObject obj = getUserConfigurations(user);
        	org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
            String jsonData = objectMap.writeValueAsString(obj);
            logger.debug(jsonData);
            mv.addObject("returnArr",jsonData);
            mv.addObject("mainTitle", obj.getString("mainTitle"));
        }

        return mv;
    }
    
    @RequestMapping(value = {"/spreadsheet.do"})
    private ModelAndView requestSpreadsheetView(HttpServletRequest request, Model model) throws Exception {
    	String redirector = "reportSpreadsheet";
        ModelAndView mv = new ModelAndView(redirector);

        String browserType = BrowserUtils.getType(request);
        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
        
        // handle user session
        User user = this.authenticationService.getSessionUser(request);
        if (user == null) {
        	throw new NotFoundUserException();
        } else {
        	JSONObject obj = getUserConfigurations(user);
        	org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper();
            String jsonData = objectMap.writeValueAsString(obj);
            logger.debug(jsonData);
            
			WebConfigMasterVO webConfig = this.authenticationService.getWebConfigMstr();
			mv.addObject("spreadJsLicense", webConfig.getSPREAD_JS_LICENSE());
            mv.addObject("returnArr",jsonData);
            mv.addObject("mainTitle", obj.getString("mainTitle"));
        }
        
        return mv;
    }
    
    @RequestMapping(value = {"/{pid}/view.do"}, method = RequestMethod.GET)
    public ModelAndView viewPage(HttpServletRequest request, @PathVariable("pid")int pid, Model model) throws Exception {
        String redirector;
        ModelAndView mv;

        if (!Configurator.getInstance().getConfigBooleanValue("wise.ds.report.view.support.restful")) {
            throw new UnSupportedRequestException("by restful");
        }
        
        redirector = this.requestPage(pid, request, model);
        
        mv = new ModelAndView(redirector);
        // handle user session
        User user = this.authenticationService.getSessionUser(request);
        if (user == null) {
        	throw new NotFoundUserException("signin.user.not.login");
        } else {
        	JSONObject obj = getUserConfigurations(user);
        	org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
            String jsonData = objectMap.writeValueAsString(obj);
            logger.debug(jsonData);
            mv.addObject("returnArr",jsonData);
            mv.addObject("mainTitle", obj.getString("mainTitle"));
        }

        return mv;
    }
    @RequestMapping(value = {"/view.do"}, method = RequestMethod.POST)
    public ModelAndView viewPageByParam(HttpServletRequest request, Model model) throws Exception {
        String redirector;
        ModelAndView mv= null;

        if (!Configurator.getInstance().getConfigBooleanValue("wise.ds.report.view.support.parameter")) {
				throw new UnSupportedRequestException("by parameter");
        }
        
        String pidParam = SecureUtils.getParameter(request, "pid");
        
        if ("".equals(pidParam)) {
            throw new EmptyReportIdException();
        }
        
        int pid = Integer.valueOf(pidParam).intValue();
        
        redirector = this.requestPage(pid, request, model);
        mv = new ModelAndView(redirector);
        // handle user session
        User user = this.authenticationService.getSessionUser(request);
        if (user == null) {
        	throw new NotFoundUserException("signin.user.not.login");
        } else {
        	JSONObject obj = getUserConfigurations(user);
        	org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
            String jsonData;
			jsonData = objectMap.writeValueAsString(obj);
			
            logger.debug(jsonData);
            mv.addObject("returnArr",jsonData);
            mv.addObject("mainTitle", obj.getString("mainTitle"));
        }

        return mv;
    }
    
    @RequestMapping(value = {"/viewer.do"})
    private ModelAndView requestPageViewer(HttpServletRequest request, Model model) throws Exception {
    	String pramPid = SecureUtils.getParameter(request, "reportId");
    	if(pramPid != null && !pramPid.equals("1001")) {
    		String redirector;
        	ModelAndView mv = null;

        	String stringPid = pramPid;
        	//String stringPid = pid;
        	
        	//2020.02.04 MKSONG KERIS ????????? ????????? ?????? DOGFOOT
        	String F_DT = SecureUtils.getParameter(request, "F_DT");
        	String U_DT = SecureUtils.getParameter(request, "U_DT");
        	//2020.03.03 mksong KERIS ?????? ????????? ?????? dogfoot
        	String srcFolderNm = SecureUtils.getParameter(request, "srcFolderNm");
        	/* goyong ktkang EIS?????? ???????????? ????????? ????????? ?????? ????????? ?????? ??????  20210604 */
        	String dataScroll = SecureUtils.getParameter(request, "dataScroll");
        	String closYm = SecureUtils.getParameter(request, "closYm");
        	
        	/* DOGFOOT ktkang KERIS SSO??????  20200308 */
//            	String user_id = SecureUtils.getParameter(request, "USER");
//            	
//            	SPApiManager.makeNoCache(request,response);
//            	SPApiManager spApiManager 	= new SPApiManager(request, response);
    //
//            	if(spApiManager.existSPUserSession()){
//            		String retURL = WebSecurityUtils.getContinueParameter(request,"retURL");
//            		String userId = spApiManager.getUserID();
//            		if(!userId.equals(user_id)) {
//            			response.sendRedirect(request.getContextPath() + "/");
//            		}
//            	} else {
//            		throw new Exception("Not Found SSO Login Session");
//            	}
        	
        	/* DOGFOOT ktkang ??????????????? ??????  20200107 */
        	String reportType = "";
        	ReportMasterVO reportInfo = null;
        	try {
        		reportInfo = this.reportService.selectReportType(stringPid);
            
            	reportType = reportInfo.getREPORT_TYPE();
        	}  catch (Exception e1) {
            	mv = new ModelAndView("redirect:/error/session/expired.do");
            }
//                if(reportType.equals("Excel")) {
//                	redirector = "reportExcel";
//                } else {
            	redirector = "listView";
//                }
           
            mv = new ModelAndView(redirector);
            
            String browserType = BrowserUtils.getType(request);
            List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
           /* for (String deny : denyBrowser) {
                if (deny.equalsIgnoreCase(browserType)) {
                    model.addAttribute("BROWSER_TYPE", browserType);
                    throw new UnSupportedBrowserException();
                }
            }*/
            redirector = this.requestPage(Integer.parseInt(stringPid), request, model,redirector,reportType);
            
            mv = new ModelAndView(redirector);
            
           	/* goyong ktkang ?????? ?????? ????????? ??????  20210604 */
            try {
            	//String userId = URLDecoder.decode(SecureUtils.getParameter(request, "USER"));
            	//userId = ariaCryptService.decryptString(userId);
            	//String userId = SecureUtils.getParameter(request, "USER");
            	
    			//User user = this.authenticationService.getRepositoryUser(userId);
            	User user = byPassSessionEncode(request);

            	if (user == null) {
            		mv = new ModelAndView("redirect:/error/invalid/user.do");
            	} else {
            		JSONObject obj = getUserConfigurations(user);
            		if(dataScroll == null && dataScroll.equals("1001")) {
            			dataScroll = "N";
            		}
            		if(closYm == null || closYm.equals("1001") || closYm.equals("") || closYm.equalsIgnoreCase("undefined")) {
            			SimpleDateFormat format = new SimpleDateFormat("yyyyMM");
            	        Calendar cal = Calendar.getInstance();
            	        cal.add(cal.MONTH, -1);
            			closYm = format.format(cal.getTime());
            		}
            		
            		obj.put("dataScroll", dataScroll);
            		obj.put("closYm", closYm);
            		org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
            		String jsonData = objectMap.writeValueAsString(obj);
            		logger.debug(jsonData);
            		mv.addObject("returnArr",jsonData);

            		//2020.02.04 MKSONG KERIS ????????? ????????? ?????? DOGFOOT
            		ReportMasterVO reportMasterVo = this.reportService.selectReportBasicInformation(Integer.parseInt(stringPid), reportType, reportInfo.getFLD_TYPE());
            		String mainTitle = obj.getString("mainTitle");

            		if(!reportMasterVo.getREPORT_NM().equals("")&&!reportMasterVo.getREPORT_NM().equals(null)) {
            			mainTitle = reportMasterVo.getREPORT_NM();
            		}

            		/* DOGFOOT mksong KERIS UNDEFINED??? ?????? ?????? 2020021 */
            		if(!F_DT.equalsIgnoreCase("undefined") && !F_DT.equals("") && !F_DT.equals(null) && !F_DT.equals("1001")) {
            			mainTitle += "  (??????????????? ???????????????:" + F_DT + ")";
            		}

            		if(!U_DT.equalsIgnoreCase("undefined") && !U_DT.equals("") && !U_DT.equals(null) && !U_DT.equals("1001")) {
            			mainTitle += "(????????? ?????????:" + U_DT + ")                                            ";
            		}

            		//2020.03.03 mksong KERIS ?????? ????????? ?????? dogfoot
            		if(!srcFolderNm.equalsIgnoreCase("undefined") && !srcFolderNm.equals("") && !srcFolderNm.equals(null) && !srcFolderNm.equals("1001")) {
            			mv.addObject("srcFolderNm", URLDecoder.decode(srcFolderNm,"UTF-8"));
            		}

            		mainTitle += "\t\t\t\t\t\t\t\t";
            		mv.addObject("mainTitle", mainTitle);
            		//2020.02.04 mksong ????????? ???????????? ?????? ????????? ?????? ???????????? ??????????????? ??????
            		mv.addObject("pidReport", true);

            		WebConfigMasterVO webConfig = this.authenticationService.getWebConfigMstr();
            		mv.addObject("spreadJsLicense", webConfig.getSPREAD_JS_LICENSE());
            		/* DOGFOOT syjin kakao map ?????? ?????? ??????  20200819 */
            		mv.addObject("kakaoMapApi", webConfig.getKAKAO_MAP_API_KEY());
            	}
            } catch (NotFoundUserException e) {
            	mv = new ModelAndView("redirect:/error/invalid/user.do");
            } catch (Exception e1) {
            	mv = new ModelAndView("redirect:/error/session/expired.do");
            }

            return mv;
    	} else {
    		String redirector = "listView";
            ModelAndView mv = new ModelAndView(redirector);
            /*?????? ???????????? URL ??????*/
            String referer = (String)request.getHeader("REFERER");
//            System.out.println("referer \t  "+referer);

        	//2020.01.22 KERIS MKSONG ?????? ?????? ?????? ????????? DOGFOOT
        	logger.debug("SERVER STARTS CONNECT");
            String browserType = BrowserUtils.getType(request);
            List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
           /* for (String deny : denyBrowser) {
                if (deny.equalsIgnoreCase(browserType)) {
                    model.addAttribute("BROWSER_TYPE", browserType);
                    throw new UnSupportedBrowserException();
                }
            }*/
            User user = null;
            String adhocView = SecureUtils.getParameter(request, "adhocView");
            if(adhocView != null && !adhocView.equals("1001")) {
            	adhocView = adhocView;
            	user = this.authenticationService.getSessionUser(request);
            } else {
            	String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
                String userId = SecureUtils.getParameter(request, authnKey);
                String byPassKeyEncrypted = request.getParameter("assign_name");
                if(userId != null && !"1001".equals(userId) && byPassKeyEncrypted != null && !"1001".equals(byPassKeyEncrypted)) {
            		user = byPassSession(request);
                }
                
                if(user == null) {
            		logger.debug("?????? ?????? ?????? ?????????");
            		user = byPassSessionEncode(request);
            	}
            }
            // handle user session
//                String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
//                String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
//                String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
            
//                Object user = request.getSession(false).getAttribute(sessionUserKey);
            if (user == null) {
            /* DOGFOOT ktkang ?????? ?????? ???????????? ??????????????????  20200620 */
            	mv = new ModelAndView("redirect:/error/invalid/user.do");
            } else {
            	JSONObject obj = getUserConfigurations(user);
                org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
                obj.put("adhocView", adhocView);
                String jsonData = objectMap.writeValueAsString(obj);
                logger.debug(jsonData);
                
    			WebConfigMasterVO webConfig = this.authenticationService.getWebConfigMstr();
    			mv.addObject("kakaoMapApi", webConfig.getKAKAO_MAP_API_KEY());
    			mv.addObject("spreadJsLicense", webConfig.getSPREAD_JS_LICENSE());
                mv.addObject("returnArr",jsonData);
                mv.addObject("mainTitle", obj.getString("mainTitle"));
            }
            
            return mv;
    	}
    }
    
//    /* DOGFOOT ktkang KERIS SSO??????  20200308 */
//    @RequestMapping(value = {"/{pid}/viewer.do"})
//    private ModelAndView requestPageViewerNewWindow(HttpServletRequest request, @PathVariable("pid")String pid, Model model, HttpServletResponse response) throws Exception {
//    	String redirector;
//    	ModelAndView mv = null;
//
//    	String stringPid = ariaCryptService.decryptString(pid);
//    	//String stringPid = pid;
//    	
//    	//2020.02.04 MKSONG KERIS ????????? ????????? ?????? DOGFOOT
//    	String F_DT = SecureUtils.getParameter(request, "F_DT");
//    	String U_DT = SecureUtils.getParameter(request, "U_DT");
//    	//2020.03.03 mksong KERIS ?????? ????????? ?????? dogfoot
//    	String srcFolderNm = SecureUtils.getParameter(request, "srcFolderNm");
//    	/* goyong ktkang EIS?????? ???????????? ????????? ????????? ?????? ????????? ?????? ??????  20210604 */
//    	String dataScroll = SecureUtils.getParameter(request, "dataScroll");
//    	String closYm = SecureUtils.getParameter(request, "closYm");
//    	
//    	/* DOGFOOT ktkang KERIS SSO??????  20200308 */
////        	String user_id = SecureUtils.getParameter(request, "USER");
////        	
////        	SPApiManager.makeNoCache(request,response);
////        	SPApiManager spApiManager 	= new SPApiManager(request, response);
////
////        	if(spApiManager.existSPUserSession()){
////        		String retURL = WebSecurityUtils.getContinueParameter(request,"retURL");
////        		String userId = spApiManager.getUserID();
////        		if(!userId.equals(user_id)) {
////        			response.sendRedirect(request.getContextPath() + "/");
////        		}
////        	} else {
////        		throw new Exception("Not Found SSO Login Session");
////        	}
//    	
//    	/* DOGFOOT ktkang ??????????????? ??????  20200107 */
//    	String reportType = "";
//    	ReportMasterVO reportInfo = null;
//    	try {
//    		reportInfo = this.reportService.selectReportType(stringPid);
//        
//        	reportType = reportInfo.getREPORT_TYPE();
//    	}  catch (Exception e1) {
//        	mv = new ModelAndView("redirect:/error/session/expired.do");
//        }
////            if(reportType.equals("Excel")) {
////            	redirector = "reportExcel";
////            } else {
//        	redirector = "listView";
////            }
//       
//        mv = new ModelAndView(redirector);
//        
//        String browserType = BrowserUtils.getType(request);
//        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
//       /* for (String deny : denyBrowser) {
//            if (deny.equalsIgnoreCase(browserType)) {
//                model.addAttribute("BROWSER_TYPE", browserType);
//                throw new UnSupportedBrowserException();
//            }
//        }*/
//        redirector = this.requestPage(Integer.parseInt(stringPid), request, model,redirector,reportType);
//        
//        mv = new ModelAndView(redirector);
//        
//       	/* goyong ktkang ?????? ?????? ????????? ??????  20210604 */
//        try {
//        	//String userId = URLDecoder.decode(SecureUtils.getParameter(request, "USER"));
//        	//userId = ariaCryptService.decryptString(userId);
//        	//String userId = SecureUtils.getParameter(request, "USER");
//        	
//			//User user = this.authenticationService.getRepositoryUser(userId);
//        	User user = byPassSessionEncode(request);
//
//        	if (user == null) {
//        		mv = new ModelAndView("redirect:/error/invalid/user.do");
//        	} else {
//        		JSONObject obj = getUserConfigurations(user);
//        		if(dataScroll == null && dataScroll.equals("1001")) {
//        			dataScroll = "N";
//        		}
//        		if(closYm == null || closYm.equals("1001") || closYm.equals("") || closYm.equalsIgnoreCase("undefined")) {
//        			SimpleDateFormat format = new SimpleDateFormat("yyyyMM");
//        	        Calendar cal = Calendar.getInstance();
//        	        cal.add(cal.MONTH, -1);
//        			closYm = format.format(cal.getTime());
//        		}
//        		obj.put("dataScroll", dataScroll);
//        		obj.put("closYm", closYm);
//        		org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
//        		String jsonData = objectMap.writeValueAsString(obj);
//        		logger.debug(jsonData);
//        		mv.addObject("returnArr",jsonData);
//
//        		//2020.02.04 MKSONG KERIS ????????? ????????? ?????? DOGFOOT
//        		ReportMasterVO reportMasterVo = this.reportService.selectReportBasicInformation(Integer.parseInt(stringPid), reportType, reportInfo.getFLD_TYPE());
//        		String mainTitle = obj.getString("mainTitle");
//
//        		if(!reportMasterVo.getREPORT_NM().equals("")&&!reportMasterVo.getREPORT_NM().equals(null)) {
//        			mainTitle = reportMasterVo.getREPORT_NM();
//        		}
//
//        		/* DOGFOOT mksong KERIS UNDEFINED??? ?????? ?????? 2020021 */
//        		if(!F_DT.equalsIgnoreCase("undefined") && !F_DT.equals("") && !F_DT.equals(null) && !F_DT.equals("1001")) {
//        			mainTitle += "  (??????????????? ???????????????:" + F_DT + ")";
//        		}
//
//        		if(!U_DT.equalsIgnoreCase("undefined") && !U_DT.equals("") && !U_DT.equals(null) && !U_DT.equals("1001")) {
//        			mainTitle += "(????????? ?????????:" + U_DT + ")                                            ";
//        		}
//
//        		//2020.03.03 mksong KERIS ?????? ????????? ?????? dogfoot
//        		if(!srcFolderNm.equalsIgnoreCase("undefined") && !srcFolderNm.equals("") && !srcFolderNm.equals(null) && !srcFolderNm.equals("1001")) {
//        			mv.addObject("srcFolderNm", URLDecoder.decode(srcFolderNm,"UTF-8"));
//        		}
//
//        		mainTitle += "\t\t\t\t\t\t\t\t";
//        		mv.addObject("mainTitle", mainTitle);
//        		//2020.02.04 mksong ????????? ???????????? ?????? ????????? ?????? ???????????? ??????????????? ??????
//        		mv.addObject("pidReport", true);
//
//        		WebConfigMasterVO webConfig = this.authenticationService.getWebConfigMstr();
//        		mv.addObject("spreadJsLicense", webConfig.getSPREAD_JS_LICENSE());
//        		/* DOGFOOT syjin kakao map ?????? ?????? ??????  20200819 */
//        		mv.addObject("kakaoMapApi", webConfig.getKAKAO_MAP_API_KEY());
//        	}
//        } catch (NotFoundUserException e) {
//        	mv = new ModelAndView("redirect:/error/invalid/user.do");
//        } catch (Exception e1) {
//        	mv = new ModelAndView("redirect:/error/session/expired.do");
//        }
//
//        return mv;
//    }
    
    /* DOGFOOT ktkang KERIS SSO??????  20200308 */
    @RequestMapping(value = {"/{pid}/viewer.do"})
    private ModelAndView requestPageViewerNewWindow(HttpServletRequest request, @PathVariable("pid")int pid, Model model, HttpServletResponse response) throws Exception {
    	String redirector;
    	ModelAndView mv = null;

    	String stringPid = Integer.toString(pid);
    	//2020.02.04 MKSONG KERIS ????????? ????????? ?????? DOGFOOT
    	String F_DT = SecureUtils.getParameter(request, "F_DT");
    	String U_DT = SecureUtils.getParameter(request, "U_DT");
    	//2020.03.03 mksong KERIS ?????? ????????? ?????? dogfoot
    	String srcFolderNm = SecureUtils.getParameter(request, "srcFolderNm");
    	
    	/* DOGFOOT ktkang KERIS SSO??????  20200308 */
//        	String user_id = SecureUtils.getParameter(request, "USER");
//        	
//        	SPApiManager.makeNoCache(request,response);
//        	SPApiManager spApiManager 	= new SPApiManager(request, response);
//
//        	if(spApiManager.existSPUserSession()){
//        		String retURL = WebSecurityUtils.getContinueParameter(request,"retURL");
//        		String userId = spApiManager.getUserID();
//        		if(!userId.equals(user_id)) {
//        			response.sendRedirect(request.getContextPath() + "/");
//        		}
//        	} else {
//        		throw new Exception("Not Found SSO Login Session");
//        	}
    	
    	/* DOGFOOT ktkang ??????????????? ??????  20200107 */
        ReportMasterVO reportInfo = this.reportService.selectReportType(stringPid);
        
        String reportType = reportInfo.getREPORT_TYPE();
        
//            if(reportType.equals("Excel")) {
//            	redirector = "reportExcel";
//            } else {
        	redirector = "listView";
//            }
       
        mv = new ModelAndView(redirector);
        
        String browserType = BrowserUtils.getType(request);
        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
       /* for (String deny : denyBrowser) {
            if (deny.equalsIgnoreCase(browserType)) {
                model.addAttribute("BROWSER_TYPE", browserType);
                throw new UnSupportedBrowserException();
            }
        }*/
        redirector = this.requestPage(pid, request, model,redirector,reportType);
        
        mv = new ModelAndView(redirector);
        
        // handle user session
        User user = byPassSession(request);
//            User user = getSessionUser(request);
        
        if (user == null) {
        /* DOGFOOT ktkang ?????? ?????? ???????????? ??????????????????  20200620 */
        	mv = new ModelAndView("redirect:/login.do");
        } else {
        	JSONObject obj = getUserConfigurations(user);
        	org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
            String jsonData = objectMap.writeValueAsString(obj);
            logger.debug(jsonData);
            mv.addObject("returnArr",jsonData);
            
            //2020.02.04 MKSONG KERIS ????????? ????????? ?????? DOGFOOT
//            ReportMasterVO reportMasterVo = this.reportService.selectReportBasicInformation(pid, reportType, reportInfo.getFLD_TYPE());
            String mainTitle = obj.getString("mainTitle");
            
//            if(!reportMasterVo.getREPORT_NM().equals("")&&!reportMasterVo.getREPORT_NM().equals(null)) {
//            	mainTitle = reportMasterVo.getREPORT_NM();
//            }
            if(!reportInfo.getREPORT_NM().equals("")&&!reportInfo.getREPORT_NM().equals(null)) {
            	mainTitle = reportInfo.getREPORT_NM();
            }
            
            /* DOGFOOT mksong KERIS UNDEFINED??? ?????? ?????? 2020021 */
            if(!F_DT.equalsIgnoreCase("undefined") && !F_DT.equals("") && !F_DT.equals(null) && !F_DT.equals("1001")) {
            	mainTitle += "  (??????????????? ???????????????:" + F_DT + ")";
            }
            
            if(!U_DT.equalsIgnoreCase("undefined") && !U_DT.equals("") && !U_DT.equals(null) && !U_DT.equals("1001")) {
            	mainTitle += "(????????? ?????????:" + U_DT + ")                                            ";
            }
            
          //2020.03.03 mksong KERIS ?????? ????????? ?????? dogfoot
            if(!srcFolderNm.equalsIgnoreCase("undefined") && !srcFolderNm.equals("") && !srcFolderNm.equals(null) && !srcFolderNm.equals("1001")) {
            	mv.addObject("srcFolderNm", URLDecoder.decode(srcFolderNm,"UTF-8"));
            }
            
            mainTitle += "\t\t\t\t\t\t\t\t";
            mv.addObject("mainTitle", mainTitle);
            //2020.02.04 mksong ????????? ???????????? ?????? ????????? ?????? ???????????? ??????????????? ??????
            mv.addObject("pidReport", true);
            
//			WebConfigMasterVO webConfig = this.authenticationService.getWebConfigMstr();
      
			mv.addObject("spreadJsLicense", obj.getString("spreadLisence"));
			/* DOGFOOT syjin kakao map ?????? ?????? ??????  20200819 */
			/* DOGFOOT syjin ??????????????? kakaoApi ????????????  20210802 */
			if(obj.has("kakaoApi")) {
				mv.addObject("kakaoMapApi", obj.getString("kakaoApi"));
			}
			
			ConfigMasterVO configVo = authenticationService.getConfigMstr();
			
			mv.addObject("site_nm", configVo.getSITE_NM());
			mv.addObject("rpt_type", reportType);
        }

        return mv;
    }
    
    @RequestMapping(value = {"/config.do"})
    private ModelAndView changeConfigurations(HttpServletRequest request, Model model) throws Exception {
        String redirector = "configMaster";
        ModelAndView mv = new ModelAndView(redirector);

        String browserType = BrowserUtils.getType(request);
        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
       /* for (String deny : denyBrowser) {
            if (deny.equalsIgnoreCase(browserType)) {
                model.addAttribute("BROWSER_TYPE", browserType);
                throw new UnSupportedBrowserException();
            }
        }*/
        
        // handle user session
        User user = this.authenticationService.getSessionUser(request);
        UserGroupVO runMode = this.authenticationService.selectUserGroupRunMode(user);
        if (user == null) {
        	/* DOGFOOT ktkang ?????? ?????? ???????????? ??????????????????  20200620 */
        	mv = new ModelAndView("redirect:/login.do");
        } else if (!("ADMIN".equals(runMode.getUSER_RUN_MODE())) && !("ADMIN".equals(runMode.getGRP_RUN_MODE()))) {
        	throw new PermissionDeniedReportViewException();
        } else {
        	JSONObject obj = getUserConfigurations(user);
            org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
            String jsonData = objectMap.writeValueAsString(obj);
            logger.debug(jsonData);
            mv.addObject("returnArr",jsonData);
            mv.addObject("mainTitle", obj.getString("mainTitle"));
        }
        
        return mv;
    }
    
    @RequestMapping(value = {"/account.do"})
    private ModelAndView openMyAccountSettings(HttpServletRequest request, Model model) throws Exception {
        String redirector = "accountMaster";
        ModelAndView mv = new ModelAndView(redirector);

        String browserType = BrowserUtils.getType(request);
        List<String> denyBrowser = Configurator.getInstance().getListConfig("wise.ds.deny.browser");
       /* for (String deny : denyBrowser) {
            if (deny.equalsIgnoreCase(browserType)) {
                model.addAttribute("BROWSER_TYPE", browserType);
                throw new UnSupportedBrowserException();
            }
        }*/
        
        // handle user session
        User user = this.authenticationService.getSessionUser(request);
        UserGroupVO runMode = this.authenticationService.selectUserGroupRunMode(user);
        if (user == null) {
        	throw new NotFoundUserException("signin.user.not.login");
        } else {
        	JSONObject obj = getUserConfigurations(user);
            org.codehaus.jackson.map.ObjectMapper objectMap = new org.codehaus.jackson.map.ObjectMapper(); 
            String jsonData = objectMap.writeValueAsString(obj);
            logger.debug(jsonData);
            mv.addObject("returnArr",jsonData);
            mv.addObject("mainTitle", obj.getString("mainTitle"));
        }

        return mv;
    }
    
	@RequestMapping(value = {"/{pid}/info/json.do"}, method = RequestMethod.GET)
    public @ResponseBody JSONObject getReportInformation(@PathVariable("pid") int pid, HttpServletRequest request, HttpServletResponse response) throws Exception {
		Timer timer = new Timer();
	    JSONObject json = null;
	    String reportTime = "";
	    String status = "50";
	    String logReportType = "";
	    long startMili = System.currentTimeMillis();
	    long checkMili = 0;
//	    boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);

//	        String shapeFileLocation = request.getSession(false).getServletContext().getRealPath(Configurator.Constants.WISE_REPORT_SHAPEFILE_LOCATION);
	    	timer.start();
	    	String reportType = SecureUtils.getParameter(request, "reportType");
	    	String fldType = SecureUtils.getParameter(request, "fldType");
	    	/* DOGFOOT ktkang ????????? ???????????? ?????? ??????  20200903 */
	    	String reportSeq = SecureUtils.getParameter(request, "reportSeq");
	    	String closYm = SecureUtils.getParameter(request, "closYm");
	    	
	    	if(closYm == null || closYm.equals("1001") || closYm.equals("") || closYm.equalsIgnoreCase("undefined")) {
	    		SimpleDateFormat format = new SimpleDateFormat("yyyyMM");
    	        Calendar cal = Calendar.getInstance();
    	        cal.add(cal.MONTH, -1);
    			closYm = format.format(cal.getTime());
    		}
    		
	        StringBuilder sbxml = new StringBuilder();
	        
	        boolean connectSVC = Configurator.getInstance().getConfigBooleanValue("wise.ds.repository.url.connection.UseSVC", false);
	        ReportMasterVO reportMasterVo = null;
	        
	        if(connectSVC) {
	        	String reportURL = Configurator.getInstance().getConfig("wise.ds.repository.url.connection.SVC.location")+"/"+pid+".xml";
	        	logger.debug(reportURL);
	        	URL url = new URL(reportURL);
	        	URLConnection conn = url.openConnection();
	        	try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"))) {
    	        	String i;
    	        	while((i = br.readLine()) != null) {
    	        		sbxml.append(i);
    	        	}
	        	}
//	        	reportMasterVo = this.reportService.selectReportBasicInformationExceptLayout(pid, Configurator.Constants.WISE_REPORT_TYPE);
	        	if(reportSeq != null && !reportSeq.equals("1001")) {
	        		reportMasterVo = this.reportService.selectReportBasicInformationExceptLayoutHis(pid, reportType, reportSeq);
	        	} else {
	        		reportMasterVo = this.reportService.selectReportBasicInformationExceptLayout(pid, reportType);
	        	}
	        	reportMasterVo.setLAYOUT_XML(sbxml.toString());
	        }
	        else {
//	        	reportMasterVo = this.reportService.selectReportBasicInformation(pid, Configurator.Constants.WISE_REPORT_TYPE);
	        	/* DOGFOOT ktkang ??????????????? ??????  20200107 */
	        	if(reportSeq != null && !reportSeq.equals("1001")) {
	        		reportMasterVo = this.reportService.selectReportBasicInformationHis(pid, reportType, fldType, reportSeq);
	        	} else {
	        		reportMasterVo = this.reportService.selectReportBasicInformation(pid, reportType, fldType);
	        	}
	        	
		        if (reportMasterVo == null) {
		            throw new UnRegisterdReportException();
		        }
	        }
	        
	        checkMili = System.currentTimeMillis();
	        double checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("json.do ???????????? reportmstr select ????????? : " + checkMin + "???");
	        startMili = System.currentTimeMillis();
	        ReportLogMasterVO logVO = new ReportLogMasterVO();
        	
	        if(reportType.equals("DashAny")) {
        		logReportType = "DashAny";
        	} else if(reportType.equals("AdHoc")){
        		logReportType = "AdHoc";
        	} else if(reportType.equals("StaticAnal")){ /*dogfoot ?????? ?????? ?????? shlim 20201102*/
        		logReportType = "StaticAnal";
        	} else if(reportType.equals("DSViewer")){ /*dogfoot ???????????? ?????? ?????? ajkim 20210511*/
        		logReportType = "DSViewer";
        	} else {
        		logReportType = "Excel";
        	}
        	
//        	logger.info(sessionUser.getId());
        	
        	boolean sessionCheck = Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication.viewer.session.check", false);
        	User user = new User();
        	if(sessionCheck) {
	        	user = this.authenticationService.getSessionUser(request);
        	} else {
        		String userId = SecureUtils.getParameter(request, "userId");
        		user = this.authenticationService.getRepositoryUser(userId);
        	}
        	
        	checkMili = System.currentTimeMillis();
	        checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("json.do ???????????? user  ?????? ????????? : " + checkMin + "???");
	        startMili = System.currentTimeMillis();
	        
	        String iscd = "yyyy";
    		String auth_cd = "00000";
    		String wnet_cd = "00000";
    		String octr_cd = "00000";
    		Map<String, String> relCodeMap = new HashMap<String, String>();
    		if(user.getUSER_REL_CD() != null && !user.getUSER_REL_CD().equals("1001") && !user.getUSER_REL_CD().equals("")) {
//    			String[] relCode = user.getUSER_REL_CD().split(",");
    			String[] relCode = {"", "", "", ""};
    			if(!relCode[0].equals("N")) {
    				iscd = relCode[0];
    			}
    			
    			if(!relCode[1].equals("N")) {
    				auth_cd = relCode[1];
    			}
    			
    			if(!relCode[2].equals("N")) {
    				wnet_cd = relCode[2];
    			}
    			
    			if(!relCode[3].equals("N")) {
    				octr_cd = relCode[3];
    			}
    		}
    		
    		relCodeMap.put("iscd", iscd);
    		relCodeMap.put("auth_cd", auth_cd);
    		relCodeMap.put("wnet_cd", wnet_cd);
    		relCodeMap.put("octr_cd", octr_cd);
        	
        	boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
        	/* goyong ktkang ???????????? ?????? ??????????????? ??????  20210603 */
        	if(logUse) {
//        		String ip = new WiseResource().getClientIP(request);
	        	String ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
	        	logVO.setReportUseLog(String.valueOf(Timer.formatTime(timer.getStartTime())),pid,reportMasterVo.getREPORT_NM(),logReportType,user.getUSER_ID(),user.getUSER_NM(),user.getUSER_NO(),user.getGRP_ID(),""/*user.getGrpnm()*/,ip,Timer.formatTime(timer.getStartTime()),Timer.formatTime(0),status,"DT");
	        	reportTime = String.valueOf(Timer.formatTime(timer.getStartTime()));
	        	this.reportService.enrollReportUseLog(logUse,logVO);
        	}
        	
	        FolderMasterVO fld_info = this.dataSetServiceImpl.selectReportFld("2",reportMasterVo.getFLD_ID(), fldType);
	        
	        checkMili = System.currentTimeMillis();
	        checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("json.do folder select : " + checkMin + "???");
	        startMili = System.currentTimeMillis();
	        
//	        String allFldNm = "";
//	        List<FolderMasterVO> fld_info_list = new ArrayList<FolderMasterVO>();
//	        if(fldType.equals("PUBLIC")) {
//		        fld_info_list = this.dataSetServiceImpl.selectAllReportFolderList();
//	        } else {
//	        	String userNo = String.valueOf(user.getUSER_NO());
//	        	fld_info_list = this.dataSetServiceImpl.selectAllMyReportFolderList(userNo);
//	        }
//		        
//	        //20200506 ajkim ?????? ?????? ?????? ?????? dogfoot
//	        int t_fldId = fld_info.getFLD_ID();
//	        while(t_fldId != 0) {
//	        	int prev = -1;
//	        	for(FolderMasterVO vo : fld_info_list) {
//	        		if(vo.getFLD_ID() != prev) {
//	        			if(t_fldId == vo.getFLD_ID()) {
//		        			if(allFldNm.equals("")) {
//		        				allFldNm = vo.getFLD_NM();
//		        			}else {
//		        				allFldNm = vo.getFLD_NM() + " > " + allFldNm;
//		        			}
//		        			t_fldId = vo.getPARENT_FLD_ID();
//		        			break;
//		        		}
//	        		}
//	        		prev = vo.getFLD_ID();
//	        	}
//	        }
	        
	        String reportMasterVO;
	        /*dogfoot ?????? ?????? ?????? shlim 20201102*/
	        if(reportType.equals("DashAny") || reportType.equals("StaticAnal")) {
	        	reportMasterVO = reportMasterVo.getLAYOUT_XML();
	        }else {
	        	reportMasterVO = reportMasterVo.getREPORT_XML();
	        }
	        
	        
	        if(reportMasterVO.length() > 0) {
	        	int l = 0,n = 0;
	        	while(l+1 < reportMasterVO.length() && n+1 < reportMasterVO.length() && l != -1 && n != -1) {
		        	l = reportMasterVO.indexOf("{\\rtf1",l+1);
		        	n = reportMasterVO.indexOf("</Text>",n+1); // TextBox -> Text
		        	if(l != -1 && n != -1) {
		        		
		        		JEditorPane p = new JEditorPane();
		        		p.setContentType("text/rtf");
		        		EditorKit kitRtf = p.getEditorKitForContentType("text/rtf");
		        		kitRtf.read(new StringReader(reportMasterVO.substring(l,n)), p.getDocument(), 0);
		        		kitRtf = null;
		        		EditorKit kitHtml = p.getEditorKitForContentType("text/html");
		        		Writer writer = new StringWriter();
		        		kitHtml.write(writer, p.getDocument(), 0, p.getDocument().getLength());
				        
				        StringBuilder sb = new StringBuilder(reportMasterVO);
				        String t = writer.toString();
						t = t.substring(t.indexOf("<p"),t.lastIndexOf("</p>")+4);
						t = t.replaceAll("  ", "");
						t = t.replaceAll("</p>", "<br></p>");
						t = t.replaceAll("<", "&lt;");
						t = t.replaceAll(">", "&gt;");
						
				        sb.replace(l, n, t);
				        
				        reportMasterVO = sb.toString();
		        	}
		        	
	        	}
	        }
	        
	        this.xml2Json.setXmlBodyText(reportMasterVO);
	        this.xml2Json.setMapJSON(reportMasterVo.getChartJson());
	        /*dogfoot ?????? ?????? ?????? shlim 20201102*/
	        if(reportType.equals("DashAny")|| reportType.equals("StaticAnal")) {
	        	this.xml2Json.arrange(pid, "");
	        	json = this.xml2Json.parseJSON(pid);
	        	
	        	String jsonTemp = json.toString().replaceAll("DefaultId", "UniqueName");
	 	        jsonTemp = jsonTemp.replaceAll("dashboardObjectDataSource", "dataSource");
	 	        jsonTemp = jsonTemp.replaceAll("ObjectDataSource", "dataSource");
//	 	        jsonTemp = jsonTemp.replaceAll("DataSource", "dataSource");
	 	        json = JSONObject.fromObject(JSONSerializer.toJSON(jsonTemp));
	        }
	        checkMili = System.currentTimeMillis();
	        checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("json.do xml ?????? ?????? : " + checkMin + "???");
	        
	        /* DOGFOOT ktkang ????????? ???????????? ?????? ??????  20201109 */
	        ConfigMasterVO configVo = authenticationService.getConfigMstr();
	        UserGrpAuthReportListVO ugaReportList = new UserGrpAuthReportListVO();
	        if(configVo.getAUTH_REPORT_DETAIL_YN().equals("Y")) {
	        	ugaReportList = reportService.userAuthByReport(user.getUSER_NO(), reportMasterVo.getREPORT_ID());
	        	if(ugaReportList == null) {
	        		ugaReportList = reportService.grpAuthByReport(user.getGRP_ID(), reportMasterVo.getREPORT_ID());
	        	}
	        } else {
	        	ugaReportList = reportService.userAuthByFolder(user.getUSER_NO(), reportMasterVo.getFLD_ID());
	        	if(ugaReportList == null) {
	        		ugaReportList = reportService.grpAuthByFolder(user.getGRP_ID(), reportMasterVo.getFLD_ID());
	        	}
	        }
	        
	        checkMili = System.currentTimeMillis();
	        checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("json.do ???????????? ?????? ?????? : " + checkMin + "???");
	        startMili = System.currentTimeMillis();
	        	
	        JSONObject info;
	        CubeMember cubeInfo = null;
	        if(reportMasterVo.getDATASRC_TYPE() != null && reportMasterVo.getDATASRC_TYPE().equals("CUBE")) {
	        	 cubeInfo = this.dataSetServiceImpl.selectCubeInfomationOne(Integer.parseInt(reportMasterVo.getDATASRC_ID()));
        		info = reportMasterVo.getDataSourceAndParameterJson(cubeInfo.getName());
        	} else {
        		info = reportMasterVo.getDataSourceAndParameterJson("");
        	}
	        
	        JSONObject reportMasterInfo = JSONObject.fromObject(info);
        	this.sqlStorage.store(reportMasterInfo); // store sql to sql storage & remove sql[DATASET_QUERY] from reportMasterInfo
        	reportMasterInfo.put("description",reportMasterVo.getREPORT_DESC());
        	reportMasterInfo.put("tag",reportMasterVo.getREPORT_TAG());
        	reportMasterInfo.put("report_sub_title",reportMasterVo.getREPORT_SUB_TITLE());
        	reportMasterInfo.put("fld_id", reportMasterVo.getFLD_ID());
        	reportMasterInfo.put("fld_type", reportMasterVo.getFLD_TYPE());
        	reportMasterInfo.put("report_xml", reportMasterVo.getREPORT_XML()); 
        	reportMasterInfo.put("fld_nm", fld_info.getFLD_NM());
//        	reportMasterInfo.put("all_fld_nm", allFldNm);
        	/* DOGFOOT ktkang ???????????? LAYOUT_CONFIG ?????? ??????  20200812 */
        	reportMasterInfo.put("layout_config", reportMasterVo.getLAYOUT_CONFIG());
        	if(reportMasterVo.getDIRECT_VIEW() == null) {
        		reportMasterInfo.put("direct_view", "N");
        	} else {
        		reportMasterInfo.put("direct_view", reportMasterVo.getDIRECT_VIEW());
        	}
        	
        	/* DOGFOOT ktkang ?????? ?????? ?????? ?????? ??????  20200922 */
        	reportMasterInfo.put("log_seq", reportTime);
        	/* DOGFOOT ktkang ??????????????? ???????????? ?????? ??????  20210112 */
        	if(reportMasterVo.getFLD_TYPE().equals("MY")) {
        		reportMasterInfo.put("export_yn", "Y");
        		reportMasterInfo.put("dataitem_use_yn", "Y");
        	} else {
        		// 2021-03-23 yyb ????????? ???????????? ?????? null ??????
        		if (ugaReportList == null) {
        			reportMasterInfo.put("export_yn", "N");
        			reportMasterInfo.put("dataitem_use_yn", "N");
        			//20210726 AJKIM ?????? ???????????? ?????? ?????? ?????? ?????? ?????? ?????? dogfoot
        			reportMasterInfo.put("publish_yn", "N");
        		}
        		else {
        			reportMasterInfo.put("export_yn", ugaReportList.getAUTH_EXPORT());
        			reportMasterInfo.put("dataitem_use_yn", ugaReportList.getAUTH_DATAITEM());
        			//20210726 AJKIM ?????? ???????????? ?????? ?????? ?????? ?????? ?????? ?????? dogfoot
        			reportMasterInfo.put("publish_yn", ugaReportList.getAUTH_PUBLISH());
        		}
        	}
        	
        	// ????????? ???????????? ??????
        	if (ugaReportList != null) {
        		reportMasterInfo.put("publish_yn", ugaReportList.getAUTH_PUBLISH());
        	}
        	else {
        		reportMasterInfo.put("publish_yn", "N");
        	}
        	/*dogfoot ?????? ?????? ?????? shlim 20201102*/
        	if(!reportType.equals("DashAny") || !reportType.equals("StaticAnal")) {
        		reportMasterInfo.put("reportJson", reportMasterVo.getReportJson());
            	reportMasterInfo.put("chartJson", reportMasterVo.getChartJson());	
            	reportMasterInfo.put("layout", reportMasterVo.getREPORT_LAYOUT());
        	}
        	
        	if(reportMasterVo.getDATASRC_TYPE() != null && reportMasterVo.getDATASRC_TYPE().equals("CUBE")) {
        		reportMasterInfo.put("cube_nm", cubeInfo.getName());
        	} else {
        		reportMasterInfo.put("cube_nm", "");
        	}
        	
        	reportMasterInfo.put("ordinal", reportMasterVo.getREPORT_ORDINAL());
        	
        	checkMili = System.currentTimeMillis();
	        checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("json.do ?????? ?????? ?????? : " + checkMin + "???");
	        startMili = System.currentTimeMillis();
	        // for sql default values
        	JSONObject paramLIST = reportMasterInfo.getJSONObject("paramJson");
            Iterator<String> paramKey = paramLIST.keys();
        	while (paramKey.hasNext()) {
				String paramKeyName = paramKey.next().toString();
				JSONObject param = paramLIST.getJSONObject(paramKeyName);
				/* dogfoot WHATIF ?????? ???????????? ?????? & ???????????? shlim 20201022 */
				if(!param.has("CALC_PARAM_YN")) {
					String defaultValueQueryString = param.getString("DEFAULT_VALUE");
	                Object defaultValue = null;
	                
	                if(param.getString("PARAM_TYPE").equalsIgnoreCase("BETWEEN_CAND") || 
	                		param.getString("PARAM_TYPE").equalsIgnoreCase("BETWEEN_LIST") || 
	                		param.getString("PARAM_TYPE").equalsIgnoreCase("BETWEEN_INPUT"))
		            {
	                	
//	                	if(param.getString("CAND_DEFAULT_TYPE").equalsIgnoreCase("QUERY") && param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
//	                		
//	                		String tmp = "";
//	                		String tmpQeury[] = defaultValueQueryString.split("\\,");
//	                		int dataSourceId = param.getInt("DS_ID");
//	                		
//	                		defaultValue =  tmpQeury;
//	                	}
//	                	else if(param.getString("CAND_DEFAULT_TYPE").equalsIgnoreCase("QUERY") && param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y"))
//	                	{
	                	if(param.getString("CAND_DEFAULT_TYPE").equalsIgnoreCase("QUERY") && param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y"))
	                	{
	                		try {
	                			String tmp = "";
		                		String tmpQeury[] = defaultValueQueryString.split("\\,");
		                		int dataSourceId = param.getInt("DS_ID");
		                		
		                		byte decod_sql[] = Base64Coder.decode(tmpQeury[0]);
		                		tmpQeury[0] = new String(decod_sql,"utf-8");
		                		
		                		decod_sql = Base64Coder.decode(tmpQeury[1]);
			                	tmpQeury[1] = new String(decod_sql,"utf-8");
			                	
			                	defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, tmpQeury, closYm, relCodeMap);
	                		}
	                		catch(IllegalArgumentException ill) {
	                			String tmpQeury[] = defaultValueQueryString.split("\\,");
	                			defaultValue =  tmpQeury;
	                		}
	                		
	                	}else if(param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y"))
	                	{
	                		try {
	                			String tmp = "";
		                		String tmpQeury[] = defaultValueQueryString.split("\\,");
		                		int dataSourceId = param.getInt("DS_ID");
		                		
		                		byte decod_sql[] = Base64Coder.decode(tmpQeury[0]);
		                		tmpQeury[0] = new String(decod_sql,"utf-8");
		                		
		                		decod_sql = Base64Coder.decode(tmpQeury[1]);
			                	tmpQeury[1] = new String(decod_sql,"utf-8");
			                	
			                	defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, tmpQeury, closYm, relCodeMap);
	                		}
	                		catch(IllegalArgumentException ill) {
	                			String tmpQeury[] = defaultValueQueryString.split("\\,");
	                			defaultValue =  tmpQeury;
	                		}
	                		
	                	}
	                	else if(param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
//	                		try {
//	                			String tmp = "";
//	                    		String tmpQeury[] = defaultValueQueryString.split("\\,");
//	                    		int dataSourceId = param.getInt("DS_ID");
//	                    		
//	                    		byte decod_sql[] = Base64Coder.decode(tmpQeury[0]);
//	                    		tmpQeury[0] = new String(decod_sql,"utf-8");
//	                    		
//	                    		decod_sql = Base64Coder.decode(tmpQeury[1]);
//	    	                	tmpQeury[1] = new String(decod_sql,"utf-8");
//	    	                	
//	    	                	defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, tmpQeury);
//	                		}
//		            		catch(IllegalArgumentException ill){
//		            			String tmpQeury[] = defaultValueQueryString.split("\\,");
//		            			int dataSourceId = param.getInt("DS_ID");
//		            			defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, tmpQeury);
//		            		}
	                		
	                		String tmp = "";
	                		String tmpQeury[] = defaultValueQueryString.split("\\,");
	                		int dataSourceId = param.getInt("DS_ID");
	                		
	                		defaultValue =  tmpQeury;
	                	}
		            }
	                
	                else
	                {
	                	/* DOGFOOT ktkang KERIS ?????? ????????? ????????? ???????????? ???????????? ???????????? ????????? ?????? ?????? 20200123 */
	                	//KERIS
	                	defaultValueQueryString = CoreUtils.ifNull(defaultValueQueryString).trim();
	                	if (defaultValueQueryString.indexOf("select") > -1 || defaultValueQueryString.indexOf("Select") > -1 || defaultValueQueryString.indexOf("SELECT") > -1) {
	                		int dataSourceId = param.getInt("DS_ID");
	                		defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, defaultValueQueryString, closYm, relCodeMap);
	               			param.put("DEFAULT_VALUE", defaultValue);
	                		param.put("HIDDEN_VALUE",defaultValueQueryString);
	                	}
	                	
	                	//ORIGIN
//	                	 defaultValueQueryString = CoreUtils.ifNull(defaultValueQueryString).toLowerCase().trim();
//	                	 
//	                	if (defaultValueQueryString.indexOf("select") > -1) {
//		                    int dataSourceId = param.getInt("DS_ID");
//		                    defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, defaultValueQueryString);
//		                    param.put("DEFAULT_VALUE", defaultValue);
//		                    param.put("HIDDEN_VALUE",defaultValueQueryString);
//		                }
	                }
	                if(defaultValue != null) {
	                	//max?????? db??? resultset??? ?????? ?????? null??? ?????? ?????? ???????????? ?????? 
	                	if (defaultValue instanceof ArrayList) {
		                	ArrayList<Object> arrObj = (ArrayList<Object>)defaultValue;
		                	if(arrObj.size()>0) {
		                		Object obj = arrObj.get(0); 
		                		if(obj!=null) {
		                			param.put("DEFAULT_VALUE", defaultValue);
		                		} else {
		                			ArrayList<Object> arrObj1 = new ArrayList<Object>();
		                			arrObj1.add("[All]");
		                			param.put("DEFAULT_VALUE", arrObj1);
		                		}
		                	}
	                	} else {
	                		param.put("DEFAULT_VALUE", defaultValue);
	                	}                	
	                }
	                
	                if(param.getString("DATASRC_TYPE").equals("QUERY")) {
	                	String sql = SecureUtils.decSeed(Configurator.Constants.SEED_CBC_ENCRIPTION_KEY, param.getString("DATASRC"));
	                	param.put("DATASRC", sql);
	                }
				}
				
			}
//	        JSONArray parameterInfos = reportMasterInfo.getJSONArray("paramJson");
//	        if (parameterInfos.size() > 0) {
//	            for (int i = 0; i < parameterInfos.size(); i++) {
//	            	
//	                JSONObject paramLIST = parameterInfos.getJSONObject(i);
//	                Iterator<String> paramKey = paramLIST.keys();
//	    			
//	    			while (paramKey.hasNext()) {
//	    				String paramKeyName = paramKey.next().toString();
//	    				JSONObject param = paramLIST.getJSONObject(paramKeyName);
//	    				String defaultValueQueryString = param.getString("DEFAULT_VALUE");
//		                Object defaultValue = null;
//		                
//		                if(param.getString("PARAM_TYPE").equalsIgnoreCase("BETWEEN_CAND") || 
//		                		param.getString("PARAM_TYPE").equalsIgnoreCase("BETWEEN_LIST") || 
//		                		param.getString("PARAM_TYPE").equalsIgnoreCase("BETWEEN_INPUT"))
//			            {
//		                	
////		                	if(param.getString("CAND_DEFAULT_TYPE").equalsIgnoreCase("QUERY") && param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
////		                		
////		                		String tmp = "";
////		                		String tmpQeury[] = defaultValueQueryString.split("\\,");
////		                		int dataSourceId = param.getInt("DS_ID");
////		                		
////		                		defaultValue =  tmpQeury;
////		                	}
////		                	else if(param.getString("CAND_DEFAULT_TYPE").equalsIgnoreCase("QUERY") && param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y"))
////		                	{
//		                	if(param.getString("CAND_DEFAULT_TYPE").equalsIgnoreCase("QUERY") && param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y"))
//		                	{
//		                		try {
//		                			String tmp = "";
//			                		String tmpQeury[] = defaultValueQueryString.split("\\,");
//			                		int dataSourceId = param.getInt("DS_ID");
//			                		
//			                		byte decod_sql[] = Base64Coder.decode(tmpQeury[0]);
//			                		tmpQeury[0] = new String(decod_sql,"utf-8");
//			                		
//			                		decod_sql = Base64Coder.decode(tmpQeury[1]);
//				                	tmpQeury[1] = new String(decod_sql,"utf-8");
//				                	
//				                	defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, tmpQeury);
//		                		}
//		                		catch(IllegalArgumentException ill) {
//		                			String tmpQeury[] = defaultValueQueryString.split("\\,");
//		                			defaultValue =  tmpQeury;
//		                		}
//		                		
//		                	}else if(param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y"))
//		                	{
//		                		try {
//		                			String tmp = "";
//			                		String tmpQeury[] = defaultValueQueryString.split("\\,");
//			                		int dataSourceId = param.getInt("DS_ID");
//			                		
//			                		byte decod_sql[] = Base64Coder.decode(tmpQeury[0]);
//			                		tmpQeury[0] = new String(decod_sql,"utf-8");
//			                		
//			                		decod_sql = Base64Coder.decode(tmpQeury[1]);
//				                	tmpQeury[1] = new String(decod_sql,"utf-8");
//				                	
//				                	defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, tmpQeury);
//		                		}
//		                		catch(IllegalArgumentException ill) {
//		                			String tmpQeury[] = defaultValueQueryString.split("\\,");
//		                			defaultValue =  tmpQeury;
//		                		}
//		                		
//		                	}
//		                	else if(param.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
////		                		try {
////		                			String tmp = "";
////		                    		String tmpQeury[] = defaultValueQueryString.split("\\,");
////		                    		int dataSourceId = param.getInt("DS_ID");
////		                    		
////		                    		byte decod_sql[] = Base64Coder.decode(tmpQeury[0]);
////		                    		tmpQeury[0] = new String(decod_sql,"utf-8");
////		                    		
////		                    		decod_sql = Base64Coder.decode(tmpQeury[1]);
////		    	                	tmpQeury[1] = new String(decod_sql,"utf-8");
////		    	                	
////		    	                	defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, tmpQeury);
////		                		}
////			            		catch(IllegalArgumentException ill){
////			            			String tmpQeury[] = defaultValueQueryString.split("\\,");
////			            			int dataSourceId = param.getInt("DS_ID");
////			            			defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, tmpQeury);
////			            		}
//		                		
//		                		String tmp = "";
//		                		String tmpQeury[] = defaultValueQueryString.split("\\,");
//		                		int dataSourceId = param.getInt("DS_ID");
//		                		
//		                		defaultValue =  tmpQeury;
//		                	}
//			            }
//		                
//		                else
//		                {
//		                	 defaultValueQueryString = CoreUtils.ifNull(defaultValueQueryString).toLowerCase().trim();
//		                	 
//		                	if (defaultValueQueryString.indexOf("select") > -1) {
//			                    int dataSourceId = param.getInt("DS_ID");
//			                    defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, defaultValueQueryString);
//			                    param.put("DEFAULT_VALUE", defaultValue);
//			                    param.put("HIDDEN_VALUE",defaultValueQueryString);
//			                }
//		                }
//		                if(defaultValue != null)
//		                	param.put("DEFAULT_VALUE", defaultValue);
//		                
//		                if(param.getString("DATASRC_TYPE").equals("QUERY")) {
//		                	String sql = SecureUtils.decSeed(Configurator.Constants.SEED_CBC_ENCRIPTION_KEY, param.getString("DATASRC"));
//		                	param.put("DATASRC", sql);
//		                }
//	    			}
//	            }
//	        }
        	
        	checkMili = System.currentTimeMillis();
	        checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("json.do ???????????? ?????? ?????? : " + checkMin + "???");
	        startMili = System.currentTimeMillis();
	        
	        List<ReportSubLinkVO> linkReport = this.reportService.selectReportLink(pid);
	        List<ReportSubLinkVO> subLinkReport = this.reportService.selectReportSubLink(pid);
	        /*dogfoot ?????? ?????? ?????? shlim 20201102*/
	        if(reportType.equals("DashAny") || reportType.equals("StaticAnal")) {
	        	json.getJSONObject("Dashboard").put("linkReport", JSONArray.fromObject(linkReport));
	        	json.getJSONObject("Dashboard").put("subLinkReport", JSONArray.fromObject(subLinkReport));
		        json.getJSONObject("Dashboard").put("ReportMasterInfo", reportMasterInfo);	
	        }else {
	        	json = new JSONObject();
	        	
	        	if(!(reportType.equals("Spread") || reportType.equals("Excel")) && reportMasterVo.getDATASRC_TYPE().equals("CUBE")) {
	        		int cubeId = Integer.parseInt(reportMasterVo.getDATASRC_ID());
		        	List<DrillThruColumnVO> drillThruCategoryList = this.reportService.selectDrillThruCategoryList(cubeId);
		            
		        	json.put("drillThru", JSONArray.fromObject(drillThruCategoryList));
	        	}
	            
	        	json.put("linkReport", JSONArray.fromObject(linkReport));
	        	json.put("subLinkReport", JSONArray.fromObject(subLinkReport));
	        	
		        json.put("ReportMasterInfo", reportMasterInfo);
	        }
	        
	        logger.debug("REPORT JSON DATA -> " + json);
	        status = "60";

        	timer.stop();
        	
	        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
            Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
            logger.debug("info/json start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
            logger.debug("info/json finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
            logger.debug("info/json elapse time: " + timer.getInterval());
            
            /* DOGFOOT ktkang ?????? ?????? ?????? ?????? ??????  20200922 */
			Timestamp queryEndTimestamp = Timer.formatTime(timer.getFinishTime());
			
//			ReportLogMasterVO vo = new ReportLogMasterVO();
//			vo.setLOG_SEQ(reportTime);
//			vo.setED_DT(queryEndTimestamp);
//			vo.setSTATUS_CD(status);
//			
//			if (logUse) {
//				this.reportService.updateReportUseLog(logUse, vo);
//			}

        return json;
    }
	
	@RequestMapping(value = {"/connect.do"}, method = RequestMethod.POST)
    public @ResponseBody String connectDataBase(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
	    String responseBody;
	    String dataSourceType = "";

        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        dataSourceType = SecureUtils.getParameter(request, "dstype");
        
       	String[] multiDsId = dataSourceIdStr.split(",");
       	for(String dsid:multiDsId) {
            int dataSourceId = Integer.parseInt(dsid);
            this.dataSetServiceImpl.connect(dataSourceId, dataSourceType);
        }
        
        responseBody = "{\"code\":200, \"message\":\"CONNECTED\"}";
        return responseBody;
    }
	
	@RequestMapping(value = {"/cube/queries.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject queryCubeAdhocSql(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	request.setCharacterEncoding("utf-8");
        User sessionUser = this.authenticationService.getSessionUser(request);

       /* if (!Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication")) { 
            sessionUser = null;
            logger.error(this.messageSource.getMessage("request.report.cube.non-authn-mode"));
        }
        
        if (sessionUser == null) {
            response.setStatus(401);
            return new AjaxMessageConverter(401, "Not Authenticated User").toJson();
        }*/
        
        Timer timer = new Timer();
        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        /* DOGFOOT ktkang ???????????? ????????? ???????????? ?????? ??????  20191220 */
        if(dataSourceIdStr.equals("0")) {
        	dataSourceIdStr = SecureUtils.getParameter(request, "cubeId");
        }
        /* DOGFOOT ktkang ???????????? ???????????? ?????? ??????  20200618 */
        String reportType = SecureUtils.getParameter(request, "reportType");
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        String onlyQuery = SecureUtils.getParameter(request, "onlyQuery");
        JSONObject ret = new JSONObject();
        int sqlTimeout = Integer.parseInt(SecureUtils.getParameter(request, "sqlTimeout"));
        String skipQuery = SecureUtils.getParameter(request,"skipQuery");
        String schId = SecureUtils.getParameter(request, "schId");
        /* DOGFOOT hsshim 2020-01-15 ???????????? ?????? ????????? ???????????? ?????? */
        String mapId = SecureUtils.getParameter(request, "mapid");
        /* DOGFOOT ktkang SQL ?????? ??????  20200721 */
        String userId = SecureUtils.getParameter(request,"userId");
        logger.debug("skipQuery == "+ skipQuery);

    	if(skipQuery != null && skipQuery.equals("Y")) {
    		// read scheduled data file
    		File folder = WebFileUtils.getWebFolder(request, true, "DataFiles");
    		String fileName = this.dataSetServiceImpl.selectSCHForSkip(schId, dataSourceIdStr);
    		File file = new File(folder, fileName);
        	try (InputStream is = new FileInputStream(file)) {
        		String jsonText = IOUtils.toString(is, "UTF-8");
        		ret = (JSONObject) JSONSerializer.toJSON(jsonText);
        	} catch (IOException e) {
        		logger.error("Cannot read json data from file at {}", file.getPath(), e);
        	}
    	}
    	else {
    		int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
            JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
            JSONObject cols = SecureUtils.getJSONObjectParameter(request, "cols");
            JSONArray dimensions = cols.getJSONArray("dim");
            JSONArray measures = cols.getJSONArray("mea");

            JSONArray filters = SecureUtils.getJSONArrayParameter(request, "filters");
            JSONArray subquery = SecureUtils.getJSONArrayParameter(request, "subquery");
            
//                JSONObject topBottomParam = SecureUtils.getJSONObjectParameter(request, "topBottomParam");
            
            timer.start();
            
            /* DOGFOOT ktkang ???????????? ???????????? ?????? ??????  20200618 */
            ret = this.dataSetServiceImpl.queryCubeSql2(sessionUser, dataSourceId, dataSourceType, params, dimensions, measures, filters, subquery,sqlTimeout, false, reportType, onlyQuery);
            /* DOGFOOT hsshim 2020-01-15 ???????????? ?????? ????????? ???????????? ?????? */
            ret.put("mapid", mapId);
            ret.put("dataSrcId", dataSourceId);
    	}

        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
        /* DOGFOOT ktkang SQL ?????? ??????  20200721 */
        boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
        if (logUse) {
        	if (reportType.equals("AdHoc")) {
        		int dataSourceID = Integer.valueOf(dataSourceIdStr);		// 2021-07-16 ??????????????????
				String pidString = SecureUtils.getParameter(request, "pid");
				String reportTypeForWeb = "";
				ReportLogMasterVO LogVo = new ReportLogMasterVO();
				User user = this.authenticationService.getSessionUser(request); 					// 2021-07-16 ??????????????????
	
				reportTypeForWeb = "AdHoc";
	
				String sql = new String(Base64.decode(ret.getString("sql")));
	
				String ip = "";
					ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
					if(ip==null) ip = "127.0.0.1";
					logger.debug("remoteADDR : " + ip);
					if (pidString.equals("")) {
						LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), 0, "", reportTypeForWeb,
								user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "",
								/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
								new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceID, timer.getInterval(), "WB");
					} else {
						int pid = Integer.parseInt(SecureUtils.getParameter(request, "pid"));
						LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), pid, "", reportTypeForWeb,
								user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "",
								/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
								new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceID, timer.getInterval(), "WB");
					}
	
				logger.debug("query log ----" + LogVo.toString());
				this.reportService.enrollReportQueryLog(logUse, LogVo);
			}
        }
        
        return ret;
    }
	@RequestMapping(value = {"/datasetcube/queries.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject queryCubeSql(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	request.setCharacterEncoding("utf-8");
        User sessionUser = this.authenticationService.getSessionUser(request);

       /* if (!Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication")) { 
            sessionUser = null;
            logger.error(this.messageSource.getMessage("request.report.cube.non-authn-mode"));
        }
        
        if (sessionUser == null) {
            response.setStatus(401);
            return new AjaxMessageConverter(401, "Not Authenticated User").toJson();
        }*/
        
        Timer timer = new Timer();
        String pidParam = SecureUtils.getParameter(request, "pid");
        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        String UserId = SecureUtils.getParameter(request, "userId");
        String reportNm = request.getParameter("reportNm");
        JSONObject ret = new JSONObject();
        String query = SecureUtils.unsecure(SecureUtils.getParameter(request,"query"));
        String skipQuery = SecureUtils.getParameter(request,"skipQuery");
        String schId = SecureUtils.getParameter(request, "schId");
        logger.debug("skipQuery == "+ skipQuery);

    	if(skipQuery.equals("Y")) {
    		// read scheduled data file
    		File folder = WebFileUtils.getWebFolder(request, true, "DataFiles");
    		String fileName = this.dataSetServiceImpl.selectSCHForSkip(schId, dataSourceIdStr);
    		File file = new File(folder, fileName);
        	try (InputStream is = new FileInputStream(file)) {
        		String jsonText = IOUtils.toString(is, "UTF-8");
        		ret = (JSONObject) JSONSerializer.toJSON(jsonText);
        	} catch (IOException e) {
        		logger.error("Failed to read json file at {}", file, e);
        	}
    	}
    	else {
    		int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
            JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");

            JSONArray filters = SecureUtils.getJSONArrayParameter(request, "filters");
            JSONObject subquery = SecureUtils.getJSONObjectParameter(request, "subquery");
            JSONObject subtarget = subquery.getJSONObject("TARGET");
            
            String subquerysql = subquery.getString("QUERY");
            
            timer.start();
            if(query != null) {
            	ret = this.dataSetServiceImpl.queryDatasetCubeSql(sessionUser, dataSourceId, dataSourceType, params, query, filters, subquerysql, subtarget);
            	
            	ret.put("mapid", "dataSource1");
            }
    	}

        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
        
        return ret;
    }
	
//	@RequestMapping(value = {"/getdatalist.do"}, method = RequestMethod.POST)
//    public @ResponseBody JSONObject getDataByTableColumn(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
//    	request.setCharacterEncoding("utf-8");
//        User sessionUser = this.authenticationService.getSessionUser(request);
//
//       /* if (!Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication")) { 
//            sessionUser = null;
//            logger.error(this.messageSource.getMessage("request.report.cube.non-authn-mode"));
//        }
//        
//        if (sessionUser == null) {
//            response.setStatus(401);
//            return new AjaxMessageConverter(401, "Not Authenticated User").toJson();
//        }*/
//        
//        Timer timer = new Timer();
//        JSONObject subtarget = SecureUtils.getJSONObjectParameter(request, "subtarget");
//        JSONObject ret = new JSONObject();
//        try {
//            
//            timer.start();
//            
//           	ret = this.dataSetServiceImpl.queryDatasetCubeSql(sessionUser, dataSourceId, dataSourceType, params, query, filters, subquerysql, subtarget);
//        }
//        catch (SqlTimeoutException e) {
//			// TODO: handle exception
//        	logger.error("ReportController#getDataList - ", e);
//        	response.setStatus(930);
//		}
//        catch (SQLException e) {
//			// TODO: handle exception
//        	logger.error("ReportController#getDataList - ", e);
//        	response.setStatus(930);
//		}
//         catch (Exception e) {
//            logger.error("ReportController#getDataList - ", e);
//            response.setStatus(500);
//            ret = new AjaxMessageConverter(930, "Can Not Query SQL. See Server Log. - " + dataSourceType).toJson();
//            e.printStackTrace();
//        }
//        finally {
//            timer.stop();
//            
//            Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
//            Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
//            
//            logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
//            logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
//            logger.debug("query elapse time: " + timer.getInterval());
//            boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
//        }
//        
//        return ret;
//    }
	
	@RequestMapping(value = {"/queries.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject querySql(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        Timer timer = new Timer();
        
        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        
        /* DOGFOOT ktkang KERIS ???????????? ?????? ??? ?????? ??? ?????????  20200123 */
        String dataSourceNm = SecureUtils.getParameter(request, "dsnm");
        
        String reportType = SecureUtils.getParameter(request, "reportType");
        String fldType = SecureUtils.getParameter(request, "fldType");
        
        String sqlId = SecureUtils.getParameter(request, "sqlid");
        String UserId = SecureUtils.getParameter(request, "userId");
        
        String join2 = SecureUtils.getParameter(request, "join");
        
        // 2021-07-16 ?????? ?????? ??????
        String rptNm = SecureUtils.getParameter(request, "rptNm"); // ????????????
        
        boolean join = false;
        if(join2.equals("true")) {
        	join = true;
        }
        
        int sqlTimeout = Integer.parseInt(SecureUtils.getParameter(request, "sqlTimeout"));
        JSONObject ret = new JSONObject();
        String status = "50";

        String dataSetId = SecureUtils.getParameter(request, "mapid");
        
        logger.debug("dataset id => " + dataSetId);
        
        JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");

        boolean multiDbQuery = (dataSourceIdStr.indexOf(",")>-1);
        if(multiDbQuery) {
        	String[] multiDsId = dataSourceIdStr.split(",");
        	dataSourceIdStr = multiDsId[0];
        }
        int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
        
        timer.start();
        String pidforLog = SecureUtils.getParameter(request, "pid");
        boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
        
        // 2021-07-16 ?????? ?????? ??????
        User user = this.authenticationService.getSessionUser(request);
		if (!pidforLog.equals("")) {
			String reportTypeForWeb = "";
			Timestamp queryStartTimestamp = Timer.formatTime(System.currentTimeMillis());
//				String scriptTime = String.valueOf(timer.getFinishTime());
			
			String keyTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS").format(new Date(timer.getStartTime()));
			
			//20210908 AJKIM ?????? ????????? ?????? ?????? dogfoot
			if (reportType.equals("AdHoc")) {
				reportTypeForWeb = "AdHoc";
			} else if(reportType.equals("Spread") || reportType.equals("Excel")){
				reportTypeForWeb = "Spread";
			} else if(reportType.equals("DSViewer")){
				reportTypeForWeb = "DSViewer";
			} else if(reportType.equals("StaticAnalysis") || reportType.equals("StaticAnal")) {
				reportTypeForWeb = "StaticAnalysis";
			} else {
				reportTypeForWeb = "DashAny";
			}
			String getSql = this.sqlStorage.getSql(sqlId);
			JSONObject paramsJson = SecureUtils.getJSONObjectParameter(request, "params");

			if (getSql == null) {
				/* DOGFOOT ktkang ?????? ????????? ??????  20200721 */
				getSql = new String(Base64.decode(SecureUtils.getParameter(request, "sql_query_nosqlid")));
			}
			String sqlforLog = this.sqlMapper.mapParameter(getSql, params);
			sqlforLog = this.sqlConvertor.convert(sqlforLog);
			try {
				sqlforLog = new String(sqlforLog.getBytes(), "UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			
			ReportLogDetailMasterVO logdetail = new ReportLogDetailMasterVO(keyTime,
					String.valueOf(timer.getStartTime()), "QUERY", pidforLog, rptNm,
					reportTypeForWeb, user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "",
					/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
					request.getRemoteAddr(), new String(java.util.Base64.getEncoder().encode(sqlforLog.getBytes())), queryStartTimestamp,
					null, status, dataSourceId, "WB");

			this.reportService.insertReportDetail(logUse, logdetail);
		}

        String getSql = this.sqlStorage.getSql(sqlId);
        
        /* DOGFOOT ktkang KERIS ???????????? ?????? ??? ?????? ??? ?????????  20200308 */
        String queryParam = "nullData";
        if(dataSourceNm.equals("????????????")) {
        	queryParam = "dataCut";
        } else if(join) {
        	queryParam = "nullData";
        }
        
        if(getSql != null) {
    		String pidParam = SecureUtils.getParameter(request, "pid");
            int pid = Integer.valueOf(pidParam).intValue();
            /* DOGFOOT ktkang ??????????????? ??????  20200107 */
            ReportMasterVO reportMasterVo = this.reportService.selectReportBasicInformation(pid, reportType, fldType);
            JSONObject info = reportMasterVo.getDataSourceAndParameterJson("");
            JSONObject reportMasterInfo = JSONObject.fromObject(info);
            
            this.sqlStorage.store(reportMasterInfo); // store sql to sql storage & remove sql[DATASET_QUERY] from reportMasterInfo
            if(reportType.equals("Spread")  || reportType.equals("Excel")  ) {
            	try {
            		// ????????? - ?????? ?????? ??????  20210913
                    List<JSONObject> result = this.dataSetServiceImpl.querySqlById(dataSourceId, dataSourceType, sqlId, params, sqlTimeout, queryParam);
                    ret.put("data", result);
            	} catch (Exception e){
            		e.printStackTrace();
            	}
            	   
            }
            ret.put("mapid", dataSetId);
    	}else {
    		/* DOGFOOT ktkang ?????? ????????? ??????  20200721 */
    		String sql_query_nosqlid = new String(Base64.decode(request.getParameter("sql_query_nosqlid")));
            if(reportType.equals("Spread")  || reportType.equals("Excel")) {
            	try {
            		// ????????? - ?????? ?????? ??????  20210913
                    List<JSONObject> result;
                    if(multiDbQuery) {
                    	JSONArray tbllist = SecureUtils.getJSONArrayParameter(request, "tbllist");
        		        ArrayList<Integer> dsid = new ArrayList<Integer>();
        		        ArrayList<String> tblnm = new ArrayList<String>();
        		        for(int i=0;i<tbllist.size();i++) {
        		        	JSONObject jobj = (JSONObject) tbllist.get(i);
        		        	dsid.add((int)jobj.get("dsid"));
        		        	tblnm.add((String)jobj.get("tblnm"));
        		        }                    	
                    	
                    	result = this.dataSetServiceImpl.sparkSql(dsid, tblnm, dataSourceType, sql_query_nosqlid, params, sqlTimeout, queryParam);
                    } else {                    
                    	result = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql_query_nosqlid, params, sqlTimeout, queryParam);
                    }
                    ret.put("data", result);
            	} catch (Exception e){
            		e.printStackTrace();
            	}
            	   
            }
            
    		ret.put("mapid", dataSetId);
    	}
        status = "60";
        timer.stop();
        
    	Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());

		if (logUse) {
			String pidString = SecureUtils.getParameter(request, "pid");
			String reportTypeForWeb = "";
			ReportLogMasterVO LogVo = new ReportLogMasterVO();
			
			//20210908 AJKIM ?????? ????????? ?????? ?????? dogfoot
			if (reportType.equals("AdHoc")) {
				reportTypeForWeb = "AdHoc";
			} else if(reportType.equals("Spread") || reportType.equals("Excel")){
				reportTypeForWeb = "Spread";
			} else if(reportType.equals("DSViewer")){
				reportTypeForWeb = "DSViewer";
			} else if(reportType.equals("StaticAnalysis") || reportType.equals("StaticAnal")) {
				reportTypeForWeb = "StaticAnalysis";
			} else {
				reportTypeForWeb = "DashAny";
			}

			String sql;
			getSql = this.sqlStorage.getSql(sqlId);
			params = SecureUtils.getJSONObjectParameter(request, "params");

			if (getSql == null) {
				/* DOGFOOT ktkang ?????? ????????? ??????  20200721 */
				getSql = new String(Base64.decode(request.getParameter("sql_query_nosqlid")));
			}
			sql = this.sqlMapper.mapParameter(getSql, params);
			sql = this.sqlConvertor.convert(sql);
			sql = new String(sql.getBytes(), "UTF-8");
			logger.debug("sql mappinged : " + sql);
			
			String ip = "";
			ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
			if(ip==null) ip = "127.0.0.1";
			logger.debug("remoteADDR : " + ip);
			if (pidString.equals("")) {
				LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), 0, "", reportTypeForWeb,
						user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "",
						/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
						new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceId, timer.getInterval(), "WB");
			} else {
				int pid = Integer.parseInt(SecureUtils.getParameter(request, "pid"));
				LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), pid, "", reportTypeForWeb,
						user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "",
						/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
						new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceId, timer.getInterval(), "WB");
			}

			logger.debug("query log ----" + LogVo.toString());
			this.reportService.enrollReportQueryLog(logUse, LogVo);
			String keyTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS").format(new Date(timer.getStartTime()));
			Timestamp queryEndTimestamp = Timer.formatTime(timer.getFinishTime());
			
			ReportLogMasterVO vo = new ReportLogMasterVO();
			vo.setLOG_SEQ(keyTime);
			vo.setED_DT(queryEndTimestamp);
			vo.setSTATUS_CD(status);
			
			if (logUse) {
				this.reportService.updateReportLogDetail(logUse, vo);
			}
		}
            
        return ret;
    }
	
	@RequestMapping(value = {"/countqueries.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject countquerySql(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        Timer timer = new Timer();
        
        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        String reportType = SecureUtils.getParameter(request, "reportType");
        /* DOGFOOT ktkang ??????????????? ??????  20200107 */
        String fldType = SecureUtils.getParameter(request, "fldType");
        
        String sqlId = SecureUtils.getParameter(request, "sqlid");
        /* DOGFOOT ktkang ?????? ????????? ??????  20200721 */
        String sql_query_nosqlid = new String(Base64.decode(SecureUtils.getParameter(request, "sql_query_nosqlid")));
        
        String UserId = SecureUtils.getParameter(request, "userId");
        String searchCount = SecureUtils.getParameter(request, "searchCount");
        
        String pidParam = SecureUtils.getParameter(request, "pid");
        String keyTime = request.getParameter("keyTime");
        String reportNm = request.getParameter("reportNm");
        
        int sqlTimeout = Integer.parseInt(SecureUtils.getParameter(request, "sqlTimeout"));
        
        JSONObject ret = new JSONObject();
        String status = "60";
        
        String dataSetId = SecureUtils.getParameter(request, "mapid");
        
        logger.debug("dataset id => " + dataSetId);
        
        JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
        
        int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
        
        timer.start();
        
        boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
        if (logUse) {
            User user = this.authenticationService.getRepositoryUser(UserId);
            Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
            int dataSourceID = this.dataSetServiceImpl.getDSIDforLog(Integer.parseInt(dataSourceIdStr), dataSourceType);
            
//            ReportLogDetailMasterVO logdetail = new ReportLogDetailMasterVO(
//            		keyTime,
//            		String.valueOf(System.currentTimeMillis()),
//            		"QUERY",
//            		pidParam,
//            		reportNm,
//            		"Dash[WB]",
//            		user.getId(),
//            		user.getName(),
//            		(user.getNo()),
//            		user.getGRP_ID(),
//            		"",
//            		request.getRemoteAddr(),
//            		Base64.encode(this.sqlStorage.getSql(sqlId).getBytes()),
//            		queryStartTimestamp,
//            		null,
//            		"50",
//            		dataSourceID,
//            		"WB");
//            
//            this.reportService.insertReportDetail(logUse,logdetail);
        }
        
        String getSql = this.sqlStorage.getSql(sqlId);
        if(getSql != null) {
            int pid = Integer.valueOf(pidParam).intValue();
            /* DOGFOOT ktkang ??????????????? ??????  20200107 */
            ReportMasterVO reportMasterVo = this.reportService.selectReportBasicInformation(pid, reportType, fldType);
            JSONObject info = reportMasterVo.getDataSourceAndParameterJson("");
            JSONObject reportMasterInfo = JSONObject.fromObject(info);
            
            this.sqlStorage.store(reportMasterInfo); // store sql to sql storage & remove sql[DATASET_QUERY] from reportMasterInfo
            
            // ????????? - ?????? ?????? ??????  20210913
            List<JSONObject> result = this.dataSetServiceImpl.queryCountSqlById(dataSourceId, dataSourceType, sqlId, params, sqlTimeout);
            ret.put("mapid", dataSetId);
            ret.put("data", result);
    	}else {
    		// ????????? - ?????? ?????? ??????  20210913
    		List<JSONObject> result = this.dataSetServiceImpl.queryCountSql(dataSourceId, dataSourceType, sql_query_nosqlid, params, sqlTimeout);
    		
    		ret.put("mapid", dataSetId);
    		ret.put("data", result);
    	}

        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
//            boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
//            if (logUse) {
//            	ReportLogMasterVO logdetail = new ReportLogMasterVO();
//	            logdetail.setLOG_SEQ(keyTime);
//	            logdetail.setED_DT(queryFinishTimestamp);
//	            logdetail.setSTATUS_CD(status);
//					
//				try {
//					this.reportService.updateReportLogDetail(logUse, logdetail);
//				} catch (Exception e) {
//					e.printStackTrace();
//				}
//			}
        
        return ret;
    }
	
	@RequestMapping(value = {"/condition/defaultQueries.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject queryDefaultValue(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		int dataSourceId = Integer.parseInt(SecureUtils.getParameter(request, "dsid"));
		String sql = SecureUtils.getParameter(request, "defaultSql");
		String closYm = SecureUtils.getParameter(request, "closYm");
		String userId = SecureUtils.getParameter(request, "userId");
		
		if(closYm == null || closYm.equals("1001") || closYm.equals("") || closYm.equalsIgnoreCase("undefined")) {
			SimpleDateFormat format = new SimpleDateFormat("yyyyMM");
	        Calendar cal = Calendar.getInstance();
	        cal.add(cal.MONTH, -1);
			closYm = format.format(cal.getTime());
		}
		
		User user = this.authenticationService.getRepositoryUser(userId);
		
		String iscd = "yyyy";
		String auth_cd = "00000";
		String wnet_cd = "00000";
		String octr_cd = "00000";
		Map<String, String> relCodeMap = new HashMap<String, String>();
		if(user.getUSER_REL_CD() != null && !user.getUSER_REL_CD().equals("1001") && !user.getUSER_REL_CD().equals("")) {
			String[] relCode = {"", "", "", ""};
			if(!relCode[0].equals("N")) {
				iscd = relCode[0];
			}
			
			if(!relCode[1].equals("N")) {
				auth_cd = relCode[1];
			}
			
			if(!relCode[2].equals("N")) {
				wnet_cd = relCode[2];
			}
			
			if(!relCode[3].equals("N")) {
				octr_cd = relCode[3];
			}
		}
		
		relCodeMap.put("iscd", iscd);
		relCodeMap.put("auth_cd", auth_cd);
		relCodeMap.put("wnet_cd", wnet_cd);
		relCodeMap.put("octr_cd", octr_cd);
		
		/* DOGFOOT ktkang ?????? ????????? ??????  20200721 */
		if(sql != null && !sql.equals("")) {
			sql = new String(Base64.decode(sql));
		}
		Object defaultValue = null;
		JSONObject ret = new JSONObject();
		defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, sql, closYm, relCodeMap);
		ret.put("data", defaultValue);
		return ret;
	}
	
	@RequestMapping(value = {"/condition/queries.do"}, method = RequestMethod.POST)
	// DOGFOOT hsshim 1220 ????????? ?????? ?????? ?????? ?????? ??????
    public @ResponseBody JSONObject queryReportCondition(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        String dataSourceIdStr = SecureUtils.getParameter(request, "DS_ID");
        String dataSourceIdType = SecureUtils.getParameter(request, "DS_TYPE");
        /* DOGFOOT ktkang ???????????? ?????? ????????? ?????? ??????  20200806 */
        int cubeId = Integer.parseInt(SecureUtils.getParameter(request, "cubeId"));
        String userId = SecureUtils.getParameter(request, "userId");
        User user = this.authenticationService.getRepositoryUser(userId);
        int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
        
        String closYm = SecureUtils.getParameter(request, "closYm");
        
        if(closYm == null || closYm.equals("1001") || closYm.equals("") || closYm.equalsIgnoreCase("undefined")) {
        	SimpleDateFormat format = new SimpleDateFormat("yyyyMM");
	        Calendar cal = Calendar.getInstance();
	        cal.add(cal.MONTH, -1);
			closYm = format.format(cal.getTime());
		}
        
        String iscd = "yyyy";
		String auth_cd = "00000";
		String wnet_cd = "00000";
		String octr_cd = "00000";
		Map<String, String> relCodeMap = new HashMap<String, String>();
		if(user.getUSER_REL_CD() != null && !user.getUSER_REL_CD().equals("1001") && !user.getUSER_REL_CD().equals("")) {
//			String[] relCode = user.getUSER_REL_CD().split(",");
			String[] relCode = {"","","",""};
			if(!relCode[0].equals("N")) {
				iscd = relCode[0];
			}
			
			if(!relCode[1].equals("N")) {
				auth_cd = relCode[1];
			}
			
			if(!relCode[2].equals("N")) {
				wnet_cd = relCode[2];
			}
			
			if(!relCode[3].equals("N")) {
				octr_cd = relCode[3];
			}
		}
		
		relCodeMap.put("iscd", iscd);
		relCodeMap.put("auth_cd", auth_cd);
		relCodeMap.put("wnet_cd", wnet_cd);
		relCodeMap.put("octr_cd", octr_cd);
        
        JSONArray result = null;
        JSONObject ret = new JSONObject();
        
        Timer timer = new Timer();

        timer.start();
        
        String conditionType = SecureUtils.getParameter(request, "PARAM_TYPE");
        /* DOGFOOT ktkang ?????? ????????? ??????  20200721 */
        String hiddenValue = SecureUtils.getParameter(request, "HIDDEN_VALUE");
        if(hiddenValue != null && !hiddenValue.equals("") && !conditionType.contains("BETWEEN")) {
        	hiddenValue = new String(Base64.decode(hiddenValue));
        }
        String defaultValueUseSqlScript = SecureUtils.getParameter(request, "DEFAULT_VALUE_USE_SQL_SCRIPT");
        String selectedParamValues = SecureUtils.getParameter(request, "parameterValues", null);
        /*dogfoot ???????????? ????????? ?????? ?????? ????????? ?????? ?????? ?????? shlim 20210408*/
		String uni_nm = SecureUtils.getParameter(request, "UNI_NM");
		List<CubeTableColumn> cubeTableColList = new LinkedList<CubeTableColumn>();
		if(cubeId != 1001 && cubeId != 0) {
			CubeTableVO cubeTable = new CubeTableVO();
			cubeTable.setCubeId(cubeId);
			cubeTable.setUniqueName(uni_nm);
				            
			cubeTableColList = this.reportService.selectCubeColumnInfomationList(cubeTable);
		}
        
		
        String whereClause = SecureUtils.getParameter(request, "WHERE_CLAUSE");
        if ("list".equalsIgnoreCase(conditionType) || "BETWEEN_LIST".equalsIgnoreCase(conditionType)) {
            String dataSourceType = SecureUtils.getParameter(request, "DATASRC_TYPE");
            if(dataSourceType.equals("QUERY")) dataSourceIdType = "QUERY";
            String dataSource = SecureUtils.getParameter(request, "DATASRC");
            String valueColumn = SecureUtils.getParameter(request, "KEY_VALUE_ITEM");
            String textColumn = SecureUtils.getParameter(request, "CAPTION_VALUE_ITEM");
        	if(!cubeTableColList.isEmpty() && cubeTableColList != null) {
        		for(CubeTableColumn cubeInfo:cubeTableColList) {
                	if(cubeInfo.getExpression() != null && !cubeInfo.getExpression().isEmpty()) {
                		valueColumn = cubeInfo.getExpression();
                        textColumn = cubeInfo.getExpression();
                	}
                }
        	}
            
            String sortType = SecureUtils.getParameter(request, "SORT_TYPE");
            String sortColumn = SecureUtils.getParameter(request, "SORT_VALUE_ITEM");
            /*dogfoot ?????? ????????? ????????? ?????? ?????? shlim 20210329 */
            String orderByKeyColumn = SecureUtils.getParameter(request, "ORDERBY_KEY");
            logger.debug("whereClause : "+whereClause);
            /* DOGFOOT ktkang ???????????? ?????? ????????? ?????? ??????  20200806 */
            /*dogfoot ?????? ????????? ????????? ?????? ?????? shlim 20210329 */
            result = this.reportConditionService.queryComboCondition(dataSourceId, dataSourceIdType, dataSource, textColumn, valueColumn, selectedParamValues, sortType,whereClause,sortColumn, user, cubeId,orderByKeyColumn, closYm);
        } else if ("LVL".equalsIgnoreCase(conditionType)){ 
        	
        	String dataSourceType = "LVL";
            String dataSource = SecureUtils.getParameter(request, "LVL_QUERY");
            String valueColumn = SecureUtils.getParameter(request, "KEY_VALUE_ITEM");
            String textColumn = SecureUtils.getParameter(request, "CAPTION_VALUE_ITEM");
            String sortType = SecureUtils.getParameter(request, "SORT_TYPE");
            /* DOGFOOT ktkang ???????????? ?????? ????????? ?????? ??????  20200806 */
            /*dogfoot ?????? ????????? ????????? ?????? ?????? shlim 20210329 */
            result = this.reportConditionService.queryComboCondition(dataSourceId, dataSourceIdType, dataSource, textColumn, valueColumn, selectedParamValues, sortType,"","", user, cubeId,"", closYm);
        	
        }
        else if ("CAND".equalsIgnoreCase(conditionType) || "BETWEEN_CAND".equalsIgnoreCase(conditionType) || "INPUT".equalsIgnoreCase(conditionType) || "BETWEEN_INPUT".equalsIgnoreCase(conditionType))
        {
        	result = new JSONArray();
        }
    	else {
    		response.setStatus(400);
    		ret = new AjaxMessageConverter(951, "Parameter Should Be LIST Type For Quering Parameter-Sql").toJson();
        }
        
        ret.put("data", result);
        
        // ???????????? SQL_SCRIPT?????? defaultValue??? return?????? 
        if(defaultValueUseSqlScript.equals("Y")) {
        	if(conditionType.contains("BETWEEN")) {
        		/*dogfoot ??????????????? ?????????????????? ?????? ?????? shlim 20210507*/
        		String[] hiddenValueArray = SecureUtils.getParameter(request, "HIDDEN_VALUE").split(",");

        		ArrayList<Object> defaultValues = new ArrayList<Object>();
        		for(int i=0;i<hiddenValueArray.length;i++) {
//    	        	String query = hiddenValueArray[i];
    	        	String query =  new String(Base64.decode(hiddenValueArray[i]));
    				if (selectedParamValues != null) {
    					selectedParamValues = this.sqlConvertor.convert(selectedParamValues);
    	
    					JSONObject jsonParameterValues = JSONObject.fromObject(selectedParamValues);
    					logger.debug("param Val : "+jsonParameterValues.toString());
    					/*dogfoot shlim 20210414*/
    					query = this.sqlMapper.mapParameter(query, jsonParameterValues, whereClause,user);
    					logger.debug("parameter query(param) : " + query);
    				}        	
    	    		Object defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, query, closYm, relCodeMap);
    	    		defaultValues.add(defaultValue);
        		}
	        	hiddenValue = "";
	    		ret.put("defaultValue", defaultValues);
        	} else {
        		/*dogfoot USE_SCRIPT Y ?????? ????????? ????????? ?????? ?????? shlim 20200708*/
        		if(hiddenValue.equals("")) {
        			hiddenValue = SecureUtils.getParameter(request, "DEFAULT_VALUE");
        		}
	        	String query = hiddenValue;
				if (selectedParamValues != null) {
					selectedParamValues = this.sqlConvertor.convert(selectedParamValues);
	
					JSONObject jsonParameterValues = JSONObject.fromObject(selectedParamValues);
					logger.debug("param Val : "+jsonParameterValues.toString());
					/*dogfoot shlim 20210414*/
					query = this.sqlMapper.mapParameter(query, jsonParameterValues, whereClause,user);
					logger.debug("parameter query(param) : " + query);
				}        	
	        	
	        	hiddenValue = "";
	    		Object defaultValue = this.conditionDefaultValueQueryService.queryDefaultSql(dataSourceId, query, closYm, relCodeMap);
	    		ret.put("defaultValue", defaultValue);
        	}
        }
        
        // DOGFOOT hsshim 1220 sql ??????
    	String sql;
    	String dataSourceType = SecureUtils.getParameter(request, "DATASRC_TYPE");
    	if ("QUERY".equalsIgnoreCase(dataSourceType) || "LVL".equalsIgnoreCase(dataSourceType)) {
			sql = SecureUtils.getParameter(request, "DATASRC");
		} else {
			sql = "SELECT ";
            sql += SecureUtils.getParameter(request, "CAPTION_VALUE_ITEM") + " AS CAPTION_VALUE, ";
            sql += SecureUtils.getParameter(request, "KEY_VALUE_ITEM") + " AS  KEY_VALUE ";
            sql += " FROM " + SecureUtils.getParameter(request, "DATASRC") + " ";
            sql += " GROUP BY " + SecureUtils.getParameter(request, "CAPTION_VALUE_ITEM") +" , "+ SecureUtils.getParameter(request, "KEY_VALUE_ITEM");
            sql += " ORDER BY CAPTION_VALUE, KEY_VALUE";
		}

		sql = this.sqlConvertor.convert(sql);

		if (SecureUtils.getParameter(request, "parameterValues", null) != null) {
			String parameterValues = this.sqlConvertor.convert(SecureUtils.getParameter(request, "parameterValues", null));

			JSONObject jsonParameterValues = JSONObject.fromObject(parameterValues);
			/*dogfoot shlim 20210414*/
			sql = this.sqlMapper.mapParameter(sql, jsonParameterValues, SecureUtils.getParameter(request, "WHERE_CLAUSE"),user);
		}
		logger.debug("sql : "+sql);
        
        model.addAttribute("OUT_DATA", ret);

        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        int resultSize = result == null ? 0 : result.size();
        logger.debug("data size : " + resultSize);
        logger.debug("condition query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("condition query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("condition query elapse time: " + timer.getInterval());
        
        return ret;
    }
	@RequestMapping(value = {"/condition/paramqueries.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject queryParamCondition(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		String dataSourceIdStr = SecureUtils.getParameter(request, "DS_ID");
        int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
		String Caption_Value = SecureUtils.getParameter(request,"Caption_Value");
		String Key_Value = SecureUtils.getParameter(request,"Key_Value");
		String dataTable = SecureUtils.getParameter(request,"dataTable");
		String queryOption = SecureUtils.getParameter(request,"queryOption");
		String queryType = SecureUtils.getParameter(request,"queryType");
		String queryValue = SecureUtils.getParameter(request,"queryValue");
		
		Timer timer = new Timer();
		
		JSONArray result = null;
		JSONObject ret = new JSONObject();

		timer.start();
		result = this.reportConditionService.queryParamCondition(dataSourceId,Caption_Value,Key_Value,dataTable,queryOption,queryType,queryValue);

		timer.stop();
		Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
		Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());

		int resultSize = result == null ? 0 : result.size();
		logger.debug("data size : " + resultSize);
		logger.debug("condition query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
		logger.debug("condition query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
		logger.debug("condition query elapse time: " + timer.getInterval());
		ret.put("data", result);
		
		return ret;
	}

	/* DOGFOOT hsshim 200107
	 * ???????????? ?????? ?????? ??????
	 */
	@RequestMapping(value = {"/exportLog.do"}, method = RequestMethod.POST)
	public void exportLog(HttpServletRequest request, HttpServletResponse response, Model model) {
		boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
		String userId = SecureUtils.getParameter(request, "userId");
		String reportIdStr = SecureUtils.getParameter(request, "pid");
		
		String reportType = SecureUtils.getParameter(request, "reportType");
		String itemID = SecureUtils.getParameter(request, "itemid");
		String itemNm = SecureUtils.getParameter(request, "itemNm");
		String reportTypeForWeb = "";
		//20210908 AJKIM ?????? ????????? ?????? ?????? dogfoot
		if (reportType.equals("AdHoc")) {
			reportTypeForWeb = "AdHoc";
		} else if(reportType.equals("Spread") || reportType.equals("Excel")){
			reportTypeForWeb = "Spread";
		} else if(reportType.equals("DSViewer")){
			reportTypeForWeb = "DSViewer";
		} else if(reportType.equals("StaticAnalysis") || reportType.equals("StaticAnal")) {
			reportTypeForWeb = "StaticAnalysis";
		} else {
			reportTypeForWeb = "DashAny";
		}
        if(logUse) {
        	Timer time = new Timer();
        	time.start();
        	time.stop();
        	User user = this.authenticationService.getRepositoryUser(userId);
        	ReportLogMasterVO logVO = new ReportLogMasterVO();
        	String ip = "";
        	try {
        		ip = (String) request.getSession().getAttribute("IP_ADDRESS");
        	}catch (NullPointerException e) {
        		e.printStackTrace();
        		return;
			}
        	
        	if(reportIdStr.equals("")) {
        		/*dogfoot ????????? ???????????? log ?????? ?????? ?????? shlim 20210219*/
        		logVO.setReportUtilLog(Timer.formatTime(time.getStartTime()),0, "??? ?????????",  reportTypeForWeb, user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "", "WB",itemID,itemNm);
        	}
        	else {
        		int reportId = Integer.parseInt(SecureUtils.getParameter(request, "pid"));
        		ReportMasterVO reportMasterVo = this.reportService.selectReportForLog(reportId, reportType);
        		logVO.setReportUtilLog(Timer.formatTime(time.getStartTime()),reportId, reportMasterVo.getREPORT_NM(), reportTypeForWeb, user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "", "WB",itemID,itemNm);
        	}
          	this.reportService.enrollReportExportLog(logUse,logVO);
        }
	}
	/* DOGFOOT hsshim 200107 ??? */
	
	@RequestMapping(value = {"/printLog.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject printLog(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception{
		boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
		String userId = SecureUtils.getParameter(request, "userId");
		int reportId = Integer.parseInt(SecureUtils.getParameter(request, "pid"));
        
        if(logUse) {
        	Timer time = new Timer();
        	time.start();
        	ReportMasterVO reportMasterVo = this.reportService.selectReportForLog(reportId, Configurator.Constants.WISE_REPORT_TYPE);
        	time.stop();
        	ReportLogMasterVO logVO = new ReportLogMasterVO();
//        	String ip = new WiseResource().getClientIP(request);
        	String ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
        	if(userId ==null || userId.isEmpty()) {
        		logVO.setReportUtilLog(Timer.formatTime(time.getStartTime()), reportId, reportMasterVo.getREPORT_NM(),  "DashAny", "", "", 0, 0, "", ip, "", "WB");
        	}
        	else {
        		User user = this.authenticationService.getRepositoryUser(userId);
        		logVO.setReportUtilLog(Timer.formatTime(time.getStartTime()), reportId, reportMasterVo.getREPORT_NM(),  "DashAny", user.getId(), user.getName(), user.getNo(), user.getGRP_ID(), "", ip, "", "WB");
        	}
          	this.reportService.enrollReportPrintLog(logUse,logVO);
        }
		
		return null;
	}
	
	/**
	 * Get list of user/group authenticated data sources.
	 * @param request
	 * @param response
	 * @param model
	 * @throws Exception
	 */
	@RequestMapping(value = { "/datasourceList.do" }, method = RequestMethod.GET)
	public @ResponseBody JSONObject getAuthDSList(HttpServletRequest request, HttpServletResponse response, Model model) {
		JSONObject result = new JSONObject();

		try {
			response.setCharacterEncoding("utf-8");
			String userNo = SecureUtils.getParameter(request, "userNo");
			
			// Get user authenticated databases. If none, get group authenticated databases.
			List<SubjectMasterVO> dsList = this.dataSetServiceImpl.selectUserAuthDsList(userNo);
			if(dsList == null || dsList.size() == 0) {
				dsList = this.dataSetServiceImpl.selectGrpAuthDsList(userNo);
			}
			// This line gets all databases, whether the user/group is authenticated or not.
//			dsList = this.dataSetServiceImpl.selectSubjectList();
			
			// Add results to a JSONObject.
			if(dsList != null) {
				JSONArray data = new JSONArray();
				for(int i = 0; i < dsList.size(); i++) {
					SubjectMasterVO vo = dsList.get(i);
					JSONObject row = new JSONObject();
	    			
					row.put("ID", i);
					row.put("DS_ID", vo.getDS_ID());
					row.put("DS_NM", vo.getDS_NM());
					row.put("DB_NM", vo.getDB_NM());
	    			row.put("DBMS_TYPE", vo.getDBMS_TYPE());
	    			row.put("IP", vo.getIP());
	    			row.put("USER_AREA_YN", vo.getUSER_AREA_YN());
	    			row.put("PORT", vo.getPORT());
	    			row.put("OWNER_NM", vo.getOWNER_NM());
	    			row.put("USER_ID", vo.getUSER_ID());
	    			row.put("DS_DESC", vo.getDS_DESC());
	    			
	    			data.add(row);
				}
				result.put("data", data);
				result.put("status", 200);
			}
		} catch (Exception e) {
			e.printStackTrace();
			result = new JSONObject();
			result.put("status", 500);
		}
		
		return result;
	}
	
	@RequestMapping(value = { "/cubeDatasourceList.do" }, method = RequestMethod.GET)
	public @ResponseBody JSONObject getAuthCubeList(HttpServletRequest request, HttpServletResponse response, Model model) {
		JSONObject result = new JSONObject();
        try {
			response.setCharacterEncoding("utf-8");
			String userNo = SecureUtils.getParameter(request, "userNo");
        	   	
			List<SubjectCubeMasterVO> dsList = this.dataSetServiceImpl.selectUserAuthCubeList(userNo);
            if(dsList == null || dsList.size() == 0) {
            	dsList = this.dataSetServiceImpl.selectGrpAuthCubeList(userNo);
            }
        	
            if (dsList != null) {
            	JSONArray data = new JSONArray();
            	for(int i = 0; i < dsList.size(); i++) {
            		SubjectCubeMasterVO vo = dsList.get(i);
					JSONObject row = new JSONObject();
					
                	row.put("ID", i);
                	row.put("DS_ID", vo.getCUBE_ID());
                	row.put("DS_NM", vo.getDS_NM());
                	row.put("DB_NM", vo.getDB_NM());
                	row.put("DBMS_TYPE", vo.getDBMS_TYPE());
                	row.put("IP", vo.getIP());
                	row.put("USER_AREA_YN", vo.getUSER_AREA_YN());
                	row.put("USER_ID", vo.getUSER_ID());
                	row.put("PORT", vo.getPORT());
                	row.put("OWNER_NM", vo.getOWNER_NM());
                	row.put("DS_DESC", vo.getDS_DESC());
                	row.put("WF_YN", vo.getWF_YN());
                	row.put("DS_VIEW_ID", vo.getDS_VIEW_ID());
                	row.put("DS_VIEW_NM", vo.getDS_VIEW_NM());
                	row.put("CUBE_ID", vo.getCUBE_ID());
                	row.put("CUBE_NM", vo.getCUBE_NM());
                	row.put("ORG_DS_ID", vo.getDS_ID());
                	
                	data.add(row);
                }
            	result.put("data", data);
				result.put("status", 200);
            }
        } catch (Exception e) {
        	e.printStackTrace();
        	result = new JSONObject();
			result.put("status", 500);
		}
        
        return result;
	}
	
	// ????????? - ?????? ?????? ??????  20210913
 	@RequestMapping(value = {"/getCubeDatasetTableColumns.do"}, method = RequestMethod.GET)
    public @ResponseBody List<JSONObject> getCubeDatasetTableColumns(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
        
        Integer cubeId = Integer.parseInt(SecureUtils.getParameter(request, "cubeId"));
        List<JSONObject> cubeTableInfo = this.dataSetServiceImpl.getCubeTableColumnList(cubeId);

        return cubeTableInfo;
	}
	
	@RequestMapping(value = {"/getTableList.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getTableList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		int dataSourceId = Integer.parseInt(SecureUtils.getParameter(request, "dsid"));
		String dataSourceType = SecureUtils.getParameter(request, "dstype");
		
		DataSetMasterVO dataSetInfo = this.dataSetServiceImpl.getDataSourceInfo(dataSourceId,dataSourceType);
		
		SqlForEachMartDbType sqlFor = new SqlForEachMartDbType();
		String sql = sqlFor.SqlForEachDbType(dataSetInfo.getDatabaseType(), "TABLE", dataSetInfo.getDatabaseOwner(), dataSetInfo.getDatabaseName(), "", null);
		
		JSONObject params = new JSONObject();
		
		// ????????? - ?????? ?????? ??????  20210913
		List<JSONObject> ret = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql, params, 0, null);
		//ORIGIN
		//JSONArray ret = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql, params, 0, false);
		
//			System.out.println(ret);
		
//			List<UserUploadMstrVO> uploadMstrVO = this.reportService.selectUserUpload(dataSourceId);
//			for(int i=0;i<ret.size();i++) {
//				JSONObject obj = ret.getJSONObject(i);
//				for(UserUploadMstrVO vo : uploadMstrVO) {
//					if(vo.getTBL_NM().equals(obj.getString("TBL_NM"))) {
//						obj.put("TBL_NM", vo.getDATA_NM()+"("+vo.getTBL_NM()+")");
//						break;
//					}
//				}
//			}
		
		JSONObject returnObj = new JSONObject();
		if(dataSetInfo.getDatabaseType().equals("IMPALA")) {
			//TBL_CAPTION ?????????
			JSONArray ret2 = new JSONArray();
			for(int i=0;i<ret.size();i++) {
				// ????????? - ?????? ?????? ??????  20210913
				JSONObject obj = ret.get(i);
				JSONObject obj2 = new JSONObject();
				obj2.put("TBL_NM", obj.get("name"));
				obj2.put("TBL_CAPTION", obj.get("name"));
				ret2.add(obj2);
			}
			returnObj.put("data", ret2);
		} else {
			//TBL_CAPTION ?????????
			JSONArray ret2 = new JSONArray();
			for(int i=0;i<ret.size();i++) {
				// ????????? - ?????? ?????? ??????  20210913
				JSONObject obj = ret.get(i);
				JSONObject obj2 = new JSONObject();
				obj2.put("TBL_NM", obj.get("TBL_NM"));
				String TBL_CAPTION = obj.get("TBL_CAPTION").toString();
				if(TBL_CAPTION.equals("")) {
					obj2.put("TBL_CAPTION", obj.get("TBL_NM"));
				} else {
					obj2.put("TBL_CAPTION", obj.get("TBL_CAPTION"));
				}
				ret2.add(obj2);
			}
			returnObj.put("data", ret2);
		}
		return returnObj;
	}
	@RequestMapping(value = {"/getViewTableList.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getViewTableList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception{
		int dataSourceId = Integer.parseInt(SecureUtils.getParameter(request, "dsid"));
		String dataSourceType = SecureUtils.getParameter(request, "dstype");
		
		List<CubeTable> dataSetInfo = this.dataSetServiceImpl.selectDsViewTableList(dataSourceId);
		JSONArray ret = new JSONArray();
		
		for(CubeTable vo : dataSetInfo) {
			JSONObject obj = new JSONObject();
			obj.put("TBL_NM", vo.getName());
			obj.put("TBL_CAPTION", vo.getAlias());
			ret.add(obj);
		}
		JSONObject returnObj = new JSONObject();
		returnObj.put("data", ret);
		return returnObj;
	}
	
	
	@RequestMapping(value = {"/getColumnList.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getColumnList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception{
		int dataSourceId = Integer.parseInt(SecureUtils.getParameter(request, "dsid"));
		String dataSourceType = SecureUtils.getParameter(request, "dstype");
		String TableName = SecureUtils.getParameter(request, "tableNm");

		DataSetMasterVO dataSetInfo = this.dataSetServiceImpl.getDataSourceInfo(dataSourceId,dataSourceType);
		
		SqlForEachMartDbType sqlFor = new SqlForEachMartDbType();
		String sql = sqlFor.SqlForEachDbType(dataSetInfo.getDatabaseType(), "COLUMN", dataSetInfo.getDatabaseOwner(), dataSetInfo.getDatabaseName(), TableName, null);
		
		JSONObject params = new JSONObject();
		
		// ????????? - ?????? ?????? ??????  20210913
		List<JSONObject> ret = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql, params, 0, null);
		//ORIGIN
		//JSONArray ret = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql, params, 0, false);
		JSONObject returnObj = new JSONObject();
		
//			System.out.println(ret);
//			List<UserUploadMstrVO> uploadMstrVO = this.reportService.selectUserUpload(dataSourceId);
//			for(int i=0;i<ret.size();i++) {
//				JSONObject obj = ret.getJSONObject(i);
//				for(UserUploadMstrVO vo : uploadMstrVO) {
//					if(vo.getTBL_NM().equals(obj.getString("TBL_NM"))) {
//						obj.put("TBL_NM", vo.getDATA_NM()+"("+vo.getTBL_NM()+")");
//						break;
//					}
//				}
//			}
		
		if(dataSetInfo.getDatabaseType().equals("IMPALA")) {
			JSONArray ret2 = new JSONArray();
			for(int i=0;i<ret.size();i++) {
				// ????????? - ?????? ?????? ??????  20210913
				JSONObject obj = ret.get(i);
				JSONObject obj2 = new JSONObject();
				obj2.put("TBL_NM", TableName);
				obj2.put("COL_NM", obj.get("name"));
				obj2.put("DATA_TYPE", obj.get("type"));
				obj2.put("LENGTH", 0);
				obj2.put("COL_ID", i++);
				obj2.put("PK_YN", "N");
				String COL_CAPTION = obj.get("comment").toString();
				if(COL_CAPTION.equals("")) {
					obj2.put("COL_CAPTION", obj.get("name"));
				} else {
					obj2.put("COL_CAPTION", obj.get("comment"));
				}
				ret2.add(obj2);
			}
			
			returnObj.put("data", ret2);
		} else {
			//COL_CAPTION ?????????
			JSONArray ret2 = new JSONArray();
			for(int i=0;i<ret.size();i++) {
				// ????????? - ?????? ?????? ??????  20210913
				JSONObject obj = ret.get(i);
				JSONObject obj2 = new JSONObject();
				obj2.put("TBL_NM", obj.get("TBL_NM"));
				obj2.put("COL_NM", obj.get("COL_NM"));
				obj2.put("DATA_TYPE", obj.get("DATA_TYPE"));
				obj2.put("LENGTH", obj.get("LENGTH"));
				obj2.put("COL_ID", obj.get("COL_ID"));
				obj2.put("PK_YN", obj.get("PK_YN"));
				String COL_CAPTION = obj.get("COL_CAPTION").toString();
				if(COL_CAPTION.equals("")) {
					obj2.put("COL_CAPTION", obj.get("COL_NM"));
				} else {
					obj2.put("COL_CAPTION", obj.get("COL_CAPTION"));
				}
				ret2.add(obj2);
			}
			
			returnObj.put("data", ret2);
		}
		return returnObj;
	}
	
	@RequestMapping(value = {"/getDsViewColumnList.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getDsViewColumnList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception{
		int dataSourceId = Integer.parseInt(SecureUtils.getParameter(request, "dsid"));
		String dataSourceType = SecureUtils.getParameter(request, "dstype");
		String TableName = SecureUtils.getParameter(request, "tableNm");
		JSONObject returnObj = new JSONObject();
		
		List<DSViewColVO> dsViewColumnList = this.dataSetServiceImpl.getDsViewColumnList(dataSourceId,TableName);
		JSONArray ret = new JSONArray();
		for(DSViewColVO vo : dsViewColumnList) {
			JSONObject obj = new JSONObject();
			obj.put("TBL_NM",vo.getTBL_NM());
			obj.put("COL_NM",vo.getCOL_NM());
			obj.put("COL_CAPTION",vo.getCOL_CAPTION());
			obj.put("DATA_TYPE",vo.getDATA_TYPE());
			obj.put("LENGTH",vo.getLENGTH());
			obj.put("COL_ID",vo.getCOL_ID());
			obj.put("PK_YN",vo.getPK_YN());
			obj.put("COL_CAPTION",vo.getCOL_CAPTION());
			ret.add(obj);
		}
		returnObj.put("data", ret);
		return returnObj;
	}
	
	
	@RequestMapping(value = {"/getConstraintList.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getConstraintList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		int dataSourceId = Integer.parseInt(SecureUtils.getParameter(request, "dsid"));
		String dataSourceType = SecureUtils.getParameter(request, "dstype");
		
		DataSetMasterVO dataSetInfo = this.dataSetServiceImpl.getDataSourceInfo(dataSourceId,dataSourceType);
		
		SqlForEachMartDbType sqlFor = new SqlForEachMartDbType();
		String sql = sqlFor.SqlForEachDbType(dataSetInfo.getDatabaseType(), "CONSTRAINT", dataSetInfo.getDatabaseOwner(), dataSetInfo.getDatabaseName(), "", null);
		
		JSONObject params = new JSONObject();
		
		// ????????? - ?????? ?????? ??????  20210913
		List<JSONObject> ret = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql, params, 0, null);
		//ORIGIN
		//JSONArray ret = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql, params, 0, false);
		
		returnObj.put("data", ret);
		return returnObj;
	}

	@RequestMapping(value = {"/getMultiConstraintList.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getMultiConstraintList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		String dataSourceIdArr[] = SecureUtils.getParameter(request, "dsid").split(",");
		String dataSourceType = SecureUtils.getParameter(request, "dstype");
		JSONArray ret = new JSONArray();
		
		for(String dataSourceIdStr:dataSourceIdArr) {
			int dataSourceId = Integer.parseInt(dataSourceIdStr);
			DataSetMasterVO dataSetInfo = this.dataSetServiceImpl.getDataSourceInfo(dataSourceId,dataSourceType);
			
			SqlForEachMartDbType sqlFor = new SqlForEachMartDbType();
			String sql = sqlFor.SqlForEachDbType(dataSetInfo.getDatabaseType(), "CONSTRAINT", dataSetInfo.getDatabaseOwner(), dataSetInfo.getDatabaseName(), "", null);
			
			JSONObject params = new JSONObject();
			
			List<JSONObject> retArr = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql, params, 0, null);
			for(int i=0;i<retArr.size();i++) {
				JSONObject jObj = (JSONObject)retArr.get(i);
				jObj.put("DATASET_SRC", dataSourceId);
				ret.add(jObj);
			}
		}
		
		returnObj.put("data", ret);
		return returnObj;
	}
	
	@RequestMapping(value = {"/getCubeConstraintList.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getCubeConstraintList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		int cubeId = Integer.parseInt(SecureUtils.getParameter(request, "cubeId"));
		int dsViewId = Integer.parseInt(SecureUtils.getParameter(request, "dsViewId"));
		
		List<TableRelationVO> relations = this.dataSetServiceImpl.selectCubeRelationList(new CubeTableVO(cubeId, dsViewId));
		
		returnObj.put("data", relations);
		return returnObj;
	}
	
	
	@RequestMapping(value = {"/subjectView.do"}, method = RequestMethod.POST)
    public void subjectView(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
        Timer timer = new Timer();
        
        /* DOGFOOT ktkang ???????????? ?????? ??????  20200120 */
        String userId = SecureUtils.getParameter(request, "userId");
        ArrayList<JSONObject> subjectViews = new ArrayList<JSONObject>();
        JSONObject subjectInfos = new JSONObject();
		
        List<SubjectViewMasterVO> listSubjectView = new ArrayList<SubjectViewMasterVO>();
        Map<String,List<CubeTableVO>> cubeTableList = new HashMap<String, List<CubeTableVO>>();
        
        JSONObject ret = new JSONObject();
        
        timer.start();
        
        /* DOGFOOT ktkang ???????????? ?????? ??????  20200120 */
        listSubjectView = this.dataSetServiceImpl.selectSubjectUserViewList(userId);
        if(listSubjectView == null || listSubjectView.size() == 0) {
        	listSubjectView = this.dataSetServiceImpl.selectSubjectGrpViewList(userId);
        }
        int i = 0;
        for (SubjectViewMasterVO subjectViewMasterVO : listSubjectView) {
			JSONObject subjectView = new JSONObject();
			JSONObject subjectInfo = new JSONObject();
			
			subjectInfo.put("??????????????? ???", subjectViewMasterVO.getDS_VIEW_NM());
			subjectInfo.put("????????? ??????", subjectViewMasterVO.getDS_NM());
			subjectInfo.put("?????? ??????(???)", subjectViewMasterVO.getIP());
			subjectInfo.put("DB ???", subjectViewMasterVO.getDB_NM());
			subjectInfo.put("DB ??????", subjectViewMasterVO.getDBMS_TYPE());
			subjectInfo.put("Port", subjectViewMasterVO.getPORT());
			subjectInfo.put("?????????", subjectViewMasterVO.getOWNER_NM());
			subjectInfo.put("?????? ID", subjectViewMasterVO.getUSER_ID());
			subjectInfo.put("??????", subjectViewMasterVO.getDS_VIEW_DESC());
			
			subjectView.put("DS_ID", subjectViewMasterVO.getDS_ID());
			subjectView.put("DS_VIEW_ID", subjectViewMasterVO.getDS_VIEW_ID());
			subjectView.put("ID", i);
			subjectView.put("??????????????? ??? ???", subjectViewMasterVO.getDS_VIEW_NM());
			subjectView.put("??????????????? ???", subjectViewMasterVO.getDB_NM());
			subjectView.put("DB ??????", subjectViewMasterVO.getDBMS_TYPE());
			subjectView.put("?????? ??????(???)", subjectViewMasterVO.getIP());
			
			subjectViews.add(subjectView);
			subjectInfos.put(i , subjectInfo);
			i++;
		}
        
        ret.put("subjectViews", subjectViews);
        ret.put("subjectInfos", subjectInfos);
        ret.put("cubeTableList", cubeTableList);

        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
        
        out.print(ret);
		out.flush();
		out.close();   
		return;
    }

	/* DOGFOOT ktkang KERIS ???????????? ?????? ???????????? ??????  20200120 */
	@RequestMapping(value = {"/subjectViewAndCube.do"}, method = RequestMethod.POST)
    public void subjectViewAndCube(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
        Timer timer = new Timer();
        
        String userId = SecureUtils.getParameter(request, "userId");
        ArrayList<JSONObject> subjectViews = new ArrayList<JSONObject>();
        ArrayList<JSONObject> cubeInfos = new ArrayList<JSONObject>();
		
        List<SubjectViewMasterVO> listSubjectView = new ArrayList<SubjectViewMasterVO>();
        List<CubeVO> cubeList = new ArrayList<CubeVO>();
        
        JSONObject ret = new JSONObject();
        
        timer.start();
        
        listSubjectView = this.dataSetServiceImpl.selectSubjectUserViewList(userId);
        if(listSubjectView == null || listSubjectView.size() == 0) {
        	listSubjectView = this.dataSetServiceImpl.selectSubjectGrpViewList(userId);
        }
        /* DOGFOOT ktkang ???????????? ?????? ??????  20200810 */
        User user = this.authenticationService.getSessionUser(request);
        List<DataAuthentication> userDataAuthentications;
        ReportDataPermission userGroupDataPermission = this.authenticationDAO.selectDataAuthnByUserGroup(user.getGRP_ID());
        if (userGroupDataPermission == null || userGroupDataPermission.getDataAuthnXml().equals("")) {
        	userDataAuthentications = new ArrayList<DataAuthentication>();
        }
        else {
        	userDataAuthentications = userGroupDataPermission.getAuthnCubes();
        }
        
        if(userDataAuthentications.size() == 0) {
            ReportDataPermission userDataPermission = this.authenticationDAO.selectDataAuthnByUser(user.getUSER_NO());
            if (userDataPermission == null  || userDataPermission.getDataAuthnXml().equals("")) {
                userDataAuthentications = new ArrayList<DataAuthentication>();
            }
            else {
                userDataAuthentications = userDataPermission.getAuthnCubes();
            }
        }
        
        ArrayList<Integer> cubeIdList = new ArrayList<Integer>();
        for(DataAuthentication da : userDataAuthentications){
        	cubeIdList.add(da.getCubeId());
        }
        
        cubeList = this.dataSetDAO.selectCubeList();
        
        for (int j = 0; j < cubeList.size(); j++) {
			JSONObject cubeInfo = new JSONObject();

			if(cubeIdList.contains(cubeList.get(j).getCUBE_ID())) {
				cubeInfo.put("CUBE_ID", cubeList.get(j).getCUBE_ID());
				cubeInfo.put("CUBE_NM", cubeList.get(j).getCUBE_NM());
				cubeInfo.put("DS_VIEW_ID", cubeList.get(j).getDS_VIEW_ID());
				cubeInfo.put("CUBE_ORDINAL", cubeList.get(j).getCUBE_ORDINAL());
				cubeInfo.put("CUBE_DESC", cubeList.get(j).getCUBE_DESC());

				cubeInfos.add(cubeInfo);
			}
		}
        
        int i = 0;
        for (SubjectViewMasterVO subjectViewMasterVO : listSubjectView) {
			JSONObject subjectView = new JSONObject();
			
			subjectView.put("DS_ID", subjectViewMasterVO.getDS_ID());
			subjectView.put("DS_VIEW_ID", subjectViewMasterVO.getDS_VIEW_ID());
			subjectView.put("ID", i);
			subjectView.put("??????????????? ??? ???", subjectViewMasterVO.getDS_VIEW_NM());
			subjectView.put("??????????????? ???", subjectViewMasterVO.getDB_NM());
			subjectView.put("DB ??????", subjectViewMasterVO.getDBMS_TYPE());
			subjectView.put("?????? ??????(???)", subjectViewMasterVO.getIP());
			
			subjectViews.add(subjectView);
			i++;
		}
        
        ret.put("subjectViews", subjectViews);
        ret.put("cubeInfos", cubeInfos);

        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
        
        out.print(ret);
		out.flush();
		out.close();   
		return;
    }
	
	@RequestMapping(value = {"/subjectList.do"}, method = RequestMethod.POST)
    public void subjectList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
        Timer timer = new Timer();
//        String userId = SecureUtils.getParameter(request, "userId");
        ArrayList<JSONObject> subjects = new ArrayList<JSONObject>();
        JSONObject subjectInfos = new JSONObject();
		
        List<SubjectMasterVO> listSubject = new ArrayList<SubjectMasterVO>();
        
        JSONObject ret = new JSONObject();
        
        timer.start();
        
        listSubject = this.dataSetServiceImpl.selectSubjectList();
        int i = 0;
        for (SubjectMasterVO subjectMasterVO : listSubject) {
			JSONObject subject = new JSONObject();
			JSONObject subjectInfo = new JSONObject();
			
			subjectInfo.put("????????? ?????? ???", subjectMasterVO.getDS_NM());
			subjectInfo.put("?????? ??????(???)", subjectMasterVO.getIP());
			subjectInfo.put("DB ???", subjectMasterVO.getDB_NM());
			subjectInfo.put("DB ??????", subjectMasterVO.getDBMS_TYPE());
			subjectInfo.put("Port", subjectMasterVO.getPORT());
			subjectInfo.put("?????????", subjectMasterVO.getOWNER_NM());
			subjectInfo.put("?????? ID", subjectMasterVO.getUSER_ID());
			subjectInfo.put("??????", subjectMasterVO.getDS_DESC());
			
			subject.put("DS_ID", subjectMasterVO.getDS_ID());
			subject.put("ID", i);
			subject.put("??????????????? ???", subjectMasterVO.getDS_NM());
			subject.put("DB ??????", subjectMasterVO.getDBMS_TYPE());
			subject.put("?????? ??????(???)", subjectMasterVO.getIP());
			subject.put("????????? ?????????", subjectMasterVO.getUSER_AREA_YN());
			
			subjects.add(subject);
			subjectInfos.put(i , subjectInfo);
			i++;
		}
        
        ret.put("subjects", subjects);
        ret.put("subjectInfos", subjectInfos);

        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
        
        out.print(ret);
		out.flush();
		out.close();   
		return;
    }
	
	@RequestMapping(value = {"/subjectDataSet.do"}, method = RequestMethod.POST)
    public void subjectDataSet(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
        Timer timer = new Timer();
        
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        String ds_Id = SecureUtils.getParameter(request, "ds_id");
        String userId = SecureUtils.getParameter(request, "userId");
        
        int ds_id = Integer.parseInt(ds_Id);
        
        int cubeId = this.dataSetServiceImpl.selectCubeIdByDsId(ds_id);;
        
        Map<String,List<CubeTableVO>> cubeTableList = new HashMap<String, List<CubeTableVO>>();
        JSONObject ret = new JSONObject();
        
        timer.start();
        
        cubeTableList = this.dataSetServiceImpl.selectCubeReportTableInfoList(cubeId,userId);
        
        ret.put("cubeTableList", cubeTableList);
        ret.put("cubeID", cubeId);

        timer.stop();
            
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
        
        out.print(ret);
		out.flush();
		out.close();   
		return;
    }
	
	@RequestMapping(value = {"/dataSetInfo.do"}, method = RequestMethod.POST)
    public void dataSetInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		try {
			response.setCharacterEncoding("utf-8");
			PrintWriter out = response.getWriter();
	        DataSetInfoMasterVO dataSetInfo = new DataSetInfoMasterVO();
	        Timer timer = new Timer();
	        
	        String dsId = SecureUtils.getParameter(request, "DATASET_ID");
	        int ds_id = Integer.parseInt(dsId);
	        
	        // ????????? - ?????? ?????? ??????  20210913
	        List<JSONObject> sqldata = null;
	        
	        dataSetInfo = this.dataSetServiceImpl.selectDataSetInfo(ds_id);
	        User user = this.authenticationService.getSessionUser(request);
	        
	        List<Object> cubeRelInfo = new ArrayList<Object>();
	        
	        String sql = dataSetInfo.getSQL_QUERY();
	        
	        JSONObject ret = new JSONObject();
	        
	        timer.start();
	        
	        cubeRelInfo = this.dataSetServiceImpl.getCubeRelationInfo(user, dataSetInfo.getDATASRC_ID());
	
	        timer.stop();
	            
	        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
	        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
	        
	        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
	        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
	        logger.debug("query elapse time: " + timer.getInterval());
	        
	        ret.put("CUBE_REL_INFO", cubeRelInfo);
	        ret.put("DATASET_NM", dataSetInfo.getDATASET_NM());
	        ret.put("DATASET_TYPE", dataSetInfo.getDATASET_TYPE());
	        ret.put("DATASRC_ID", dataSetInfo.getDATASRC_ID());
	        ret.put("DATASRC_TYPE", dataSetInfo.getDATASRC_TYPE());
        	ret.put("DATASET_QUERY", sql);
        // DEPRECATED
	        ret.put("SQL_QUERY", sql);
	        
	        String dataSetType = dataSetInfo.getDATASET_TYPE();
	        String datasetXml = dataSetInfo.getDatasetXml();
	        
	        DataSetMasterVO dataSetMaster;
	        if (DataSetConst.DataSetType.DS.equals(dataSetInfo.getDATASRC_TYPE()) || DataSetConst.DataSetType.DS_SQL.equals(dataSetInfo.getDATASRC_TYPE())) {
	            dataSetMaster = this.dataSetDAO.selectDataSetMaster(dataSetInfo.getDATASRC_ID());
	        } 
	        else if (DataSetConst.DataSetType.VIEW.equals(dataSetInfo.getDATASRC_TYPE())) {
	            dataSetMaster = this.dataSetDAO.selectDataSetViewMaster(dataSetInfo.getDATASRC_ID());
	        } 
	        else if (DataSetConst.DataSetType.CUBE.equals(dataSetInfo.getDATASRC_TYPE())) {
	            dataSetMaster = this.dataSetDAO.selectCubeMaster(dataSetInfo.getDATASRC_ID());
	        } 
	        else {
	            throw new NotFoundDataSetTypeException();
	        }
	        if (dataSetMaster == null) {
	            throw new EmptyDataSetInformationException();
	        }
	        /* DOGFOOT ktkang ????????? ??????????????? ?????? ??????  20200629 */
	        sql = this.sqlConvertor.convertTopN(sql, dataSetMaster.getDatabaseType(), 1);
	        
	        if ("".equals(CoreUtils.ifNull(datasetXml))) {
	        } else {
	        	if(dataSetType.equals("DataSetCube")||dataSetType.equals("DataSetDs")) {
	        		
	        		Object sel_element = null;
	                JSONArray param_element;
	                Object rel_element = null;
	                Object where_element = null;
	                /* DOGFOOT ktkang ????????? ?????? ?????? ?????? ???????????? ??????  20200713 */
	                Object order_element = null;
	                Object etc_element = null;
	                
	                int paramint = 0;
	                if(sql.contains("@")) {
	                	paramint = 1;
	                	
	                	sql = sql.substring(0, sql.indexOf("WHERE")) + sql.substring(sql.indexOf("GROUP"));
	                }
	
	                if(paramint == 1) {
	                	try {
	                		org.json.JSONObject DATASET_XML = XML.toJSONObject(datasetXml);
	                		org.json.JSONObject DATA_SET = DATASET_XML.getJSONObject("DATA_SET");
	                		sel_element = DATA_SET.get("SEL_ELEMENT");
	                		org.json.JSONObject PARAM_XML = DATA_SET.getJSONObject("PARAM_ELEMENT");
	                		Object PARAM = PARAM_XML.get("PARAM");
	                		if(dataSetType.equals("DataSetDs")) {
	                			if(DATA_SET.has("REL_ELEMENT")) {
	                				rel_element = DATA_SET.get("REL_ELEMENT");
	                			}
	                			if(DATA_SET.has("WHERE_ELEMENT")) {
	                				where_element = DATA_SET.get("WHERE_ELEMENT");
	                			}
	                			/* DOGFOOT ktkang ????????? ?????? ?????? ?????? ???????????? ??????  20200713 */
	                			if(DATA_SET.has("ORDER_ELEMENT")) {
	                				order_element = DATA_SET.get("ORDER_ELEMENT");
	                			}
	                			if(DATA_SET.has("ETC_ELEMENT")) {
	                				etc_element = DATA_SET.get("ETC_ELEMENT");
	                			}
	                		}
	
	                		String PARAM_JSON_STR;
	                		if (PARAM instanceof org.json.JSONObject) {
	                			PARAM_JSON_STR = PARAM_XML.getJSONObject("PARAM").toString();
	                			JSONObject tempJson = JSONObject.fromObject(PARAM_JSON_STR);
	                			param_element = new JSONArray();
	                			param_element.add(tempJson);
	                		} else {
	                			PARAM_JSON_STR = PARAM_XML.getJSONArray("PARAM").toString();
	                			param_element = JSONArray.fromObject(PARAM_JSON_STR);
	                		}
	                	} catch (org.json.JSONException e) {
	                		param_element = new JSONArray();
	                	}
	
	            		String plainSql = null;
	            		String encSql = null;
	            		String paramName = null;
	            		for (int x0 = 0; x0 < param_element.size(); x0++) {
	            			JSONObject paramMetadata = param_element.getJSONObject(x0);
	            			paramMetadata.put("wiseVariables", new JSONArray());
	
	            			if ("QUERY".equalsIgnoreCase(paramMetadata.getString("DATASRC_TYPE"))) {
	            				plainSql = CoreUtils.ifNull(paramMetadata.getString("DATASRC"));
	
	            				for (int x1 = 0; x1 < param_element.size(); x1++) {
	            					paramName = param_element.getJSONObject(x1).getString("PARAM_NM");
	            					if (plainSql.indexOf(paramName) > -1) {
	            						paramMetadata.getJSONArray("wiseVariables").add(paramName);
	            					}
	            				}
	
	            				encSql = SecureUtils.encSeed(Configurator.Constants.SEED_CBC_ENCRIPTION_KEY, plainSql);
	            				paramMetadata.put("DATASRC", encSql);
	            			}
	            		}
	
	                	JSONObject params = new JSONObject();
	                	
	                	/* DOGFOOT ktkang KERIS ???????????? ?????? ??? ?????? ??? ?????????  20200123 */
	                	//KERIS
	                	sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, null);
	                	//ORIGIN
	                	//sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, false);
	
	                	ret.put("data", sqldata);
	                	ret.put("SEL_ELEMENT", sel_element.toString());
	                	ret.put("PARAM_ELEMENT", param_element.toString());
	                	if(dataSetType.equals("DataSetDs")) {
	                		
	                		ret.put("REL_ELEMENT",rel_element.toString());
	                		ret.put("WHERE_ELEMENT",where_element.toString());
	                		ret.put("ORDER_ELEMENT",order_element.toString());
	                		ret.put("ETC_ELEMENT",etc_element.toString());
	                		logger.debug(ret.toString());
	                	}
	                } else {
	                	try {
	                		org.json.JSONObject DATASET_XML = XML.toJSONObject(datasetXml);
	                		org.json.JSONObject DATA_SET = DATASET_XML.getJSONObject("DATA_SET");
	                		sel_element = DATA_SET.get("SEL_ELEMENT");
	                		if(dataSetType.equals("DataSetDs")) {
	                			if(DATA_SET.has("REL_ELEMENT")) {
	                				rel_element = DATA_SET.get("REL_ELEMENT");
	                			}
	                			if(DATA_SET.has("WHERE_ELEMENT")) {
	                				where_element = DATA_SET.get("WHERE_ELEMENT");
	                			}
	                			if(DATA_SET.has("ORDER_ELEMENT")) {
	                				order_element = DATA_SET.get("ORDER_ELEMENT");
	                			}
	                			if(DATA_SET.has("ETC_ELEMENT")) {
	                				etc_element = DATA_SET.get("ETC_ELEMENT");
	                			}
	                		}
	
	                		JSONObject params = new JSONObject();
	                		/* DOGFOOT ktkang KERIS ???????????? ?????? ??? ?????? ??? ?????????  20200123 */
	                		//KERIS
	                		sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, null);
	                		//ORIGIN
	//                		sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, false);
	
	                		param_element = new JSONArray();
	                		ret.put("data", sqldata);
	                		ret.put("SEL_ELEMENT", sel_element.toString());
	                		ret.put("param_element", param_element);
	                		if(dataSetType.equals("DataSetDs")) {
	                    		ret.put("REL_ELEMENT",rel_element.toString());
	                    		ret.put("WHERE_ELEMENT",where_element.toString());
		                		ret.put("ORDER_ELEMENT",order_element.toString());
		                		ret.put("ETC_ELEMENT",etc_element.toString());
	                    		logger.debug(ret.toString());
	                    	}
	                	} catch (org.json.JSONException e) {
	                		param_element = new JSONArray();
	                	}
	                }
	            /* DOGFOOT ktkang ??????????????? ?????? ??????????????? ?????? ??????  20201112 */
	        	} else if(dataSetType.equals("DataSetSingleDs") || dataSetType.equals("DataSetSingleDsView")) {
	        		JSONArray param_element = null;
	        		int paramint = 0;
	                if(sql.contains("@")) {
	                	paramint = 1;
	                	/*DOGFOOT cshan 20200113 - GROUP BY ????????? ????????? ?????? ????????? ?????? ??????*/
	//                	sql = sql.substring(0, sql.indexOf("WHERE")) + sql.substring(sql.indexOf("GROUP"));
	                }
	
	        		if(paramint == 1) {
	        			try {
	            			org.json.JSONObject DATASET_XML = XML.toJSONObject(datasetXml);
	            			org.json.JSONObject DATA_SET = DATASET_XML.getJSONObject("DATA_SET");
	            			org.json.JSONObject PARAM_XML = DATA_SET.getJSONObject("PARAM_ELEMENT");
	            			Object PARAM = PARAM_XML.get("PARAM");
	
	            			String PARAM_JSON_STR;
	            			if (PARAM instanceof org.json.JSONObject) {
	            				PARAM_JSON_STR = PARAM_XML.getJSONObject("PARAM").toString();
	            				JSONObject tempJson = JSONObject.fromObject(PARAM_JSON_STR);
	            				param_element = new JSONArray();
	            				param_element.add(tempJson);
	            			} else {
	            				PARAM_JSON_STR = PARAM_XML.getJSONArray("PARAM").toString();
	            				param_element = JSONArray.fromObject(PARAM_JSON_STR);
	            			}
	            			/*DOGFOOT cshan 20200113 - GROUP BY ????????? ????????? ?????? ????????? ?????? ??????*/
	            			JSONObject param_JSON = new JSONObject();
	            			for(int i=0;i<param_element.size();i++) {
	            				JSONObject param_item = param_element.getJSONObject(i);
	        					param_item.put("value", new JSONArray());
	        					param_item.put("defaultValue", param_item.getString("DEFAULT_VALUE"));
	        					param_item.put("whereClause", param_item.getString("WHERE_CLAUSE"));
	        					
	            				param_JSON.put(param_element.getJSONObject(i).getString("PARAM_NM"), param_item);
	            			}
	            			
	            			JSONObject params = new JSONObject();
	            			/* DOGFOOT ktkang KERIS ???????????? ?????? ??? ?????? ??? ?????????  20200123 */
	            			//KERIS
	            			/* DOGFOOT ktkang ????????? ?????? ????????? USE_SQL ??? ???????????? ??? ?????? ??????  20200701 */
	            			sqldata = dataSetServiceImpl.queryTableSql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, param_JSON, 0, false, "dataset");
	            			
	            			//ORIGIN
	//                		sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, false);
	//            			sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, param_JSON, 0, false);
	                		
	                		ret.put("data", sqldata);
	                		ret.put("PARAM_ELEMENT", param_element.toString());
	            		} catch (org.json.JSONException e) {
	            			param_element = new JSONArray();
	            		}
	
	        		} else {
	        			try {
	        				JSONObject params = new JSONObject();
	        				/* DOGFOOT ktkang KERIS ???????????? ?????? ??? ?????? ??? ?????????  20200123 */
	        				//KERIS
	        				/* DOGFOOT ktkang ????????? ?????? ????????? USE_SQL ??? ???????????? ??? ?????? ??????  20200701 */
	        				sqldata = dataSetServiceImpl.queryTableSql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, false, null);
	        				//ORIGIN
	//        				sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, false);
	
	        				param_element = new JSONArray();
	        				ret.put("data", sqldata);
	        				ret.put("PARAM_ELEMENT", param_element);
	        			} catch (org.json.JSONException e) {
	        				param_element = new JSONArray();
	        			}
	        		}
	        		Object col_element = null;
	        		Object etc_element = null;
	        		Object tbl_element = null;
	        		
	        		try {
	        			org.json.JSONObject DATASET_XML = XML.toJSONObject(datasetXml);
	        			org.json.JSONObject DATA_SET = DATASET_XML.getJSONObject("DATA_SET");
	        			col_element = DATA_SET.get("COL_ELEMENT");
	        			etc_element = DATA_SET.get("ETC_ELEMENT");
	        			tbl_element = DATA_SET.get("TBL_ELEMENT");
	        		} catch (org.json.JSONException e) {
	        			col_element = new JSONArray();
	        			etc_element = new JSONArray();
	        			tbl_element = new JSONArray();
	        		}
	        		
	        		ret.put("col_element", col_element.toString());
	        		ret.put("etc_element", etc_element.toString());
	        		ret.put("tbl_element", tbl_element.toString());
	        	} else 
	        	{
	        		JSONArray param_element = null;
	        		int paramint = 0;
	                if(sql.contains("@")) {
	                	paramint = 1;
	                	/*DOGFOOT cshan 20200113 - GROUP BY ????????? ????????? ?????? ????????? ?????? ??????*/
	//                	sql = sql.substring(0, sql.indexOf("WHERE")) + sql.substring(sql.indexOf("GROUP"));
	                }
	
	        		if(paramint == 1) {
	        			try {
	            			org.json.JSONObject DATASET_XML = XML.toJSONObject(datasetXml);
	            			org.json.JSONObject DATA_SET = DATASET_XML.getJSONObject("DATA_SET");
	            			org.json.JSONObject PARAM_XML = DATA_SET.getJSONObject("PARAM_ELEMENT");
	            			Object PARAM = PARAM_XML.get("PARAM");
	
	            			String PARAM_JSON_STR;
	            			if (PARAM instanceof org.json.JSONObject) {
	            				PARAM_JSON_STR = PARAM_XML.getJSONObject("PARAM").toString();
	            				JSONObject tempJson = JSONObject.fromObject(PARAM_JSON_STR);
	            				param_element = new JSONArray();
	            				param_element.add(tempJson);
	            			} else {
	            				PARAM_JSON_STR = PARAM_XML.getJSONArray("PARAM").toString();
	            				param_element = JSONArray.fromObject(PARAM_JSON_STR);
	            			}
	            			/*DOGFOOT cshan 20200113 - GROUP BY ????????? ????????? ?????? ????????? ?????? ??????*/
	            			JSONObject param_JSON = new JSONObject();
	            			for(int i=0;i<param_element.size();i++) {
	            				JSONObject param_item = param_element.getJSONObject(i);
	        					param_item.put("value", new JSONArray());
	        					param_item.put("defaultValue", param_item.getString("DEFAULT_VALUE"));
	        					param_item.put("whereClause", param_item.getString("WHERE_CLAUSE"));
	        					
	            				param_JSON.put(param_element.getJSONObject(i).getString("PARAM_NM"), param_item);
	            			}
	            			
	            			JSONObject params = new JSONObject();
	            			/* DOGFOOT ktkang KERIS ???????????? ?????? ??? ?????? ??? ?????????  20200123 */
	            			//KERIS
	            			/* DOGFOOT ktkang ????????? ?????? ????????? USE_SQL ??? ???????????? ??? ?????? ??????  20200701 */
	            			sqldata = dataSetServiceImpl.queryTableSql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, param_JSON, 0, false, "dataset");
	            			
	            			//ORIGIN
	//                		sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, false);
	//            			sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, param_JSON, 0, false);
	                		
	                		ret.put("data", sqldata);
	                		ret.put("PARAM_ELEMENT", param_element.toString());
	            		} catch (org.json.JSONException e) {
	            			param_element = new JSONArray();
	            		}
	
	        		} else {
	        			try {
	        				JSONObject params = new JSONObject();
	        				/* DOGFOOT ktkang KERIS ???????????? ?????? ??? ?????? ??? ?????????  20200123 */
	        				//KERIS
	        				/* DOGFOOT ktkang ????????? ?????? ????????? USE_SQL ??? ???????????? ??? ?????? ??????  20200701 */
	        				sqldata = dataSetServiceImpl.queryTableSql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, false, null);
	        				//ORIGIN
	//        				sqldata = dataSetServiceImpl.querySql(dataSetInfo.getDATASRC_ID(), dataSetInfo.getDATASRC_TYPE(), sql, params, 0, false);
	
	        				param_element = new JSONArray();
	        				ret.put("data", sqldata);
	        				ret.put("PARAM_ELEMENT", param_element);
	        			} catch (org.json.JSONException e) {
	        				param_element = new JSONArray();
	        			}
	        		}
	        	}
	        }
	        
	        out.print(ret);
	        out.flush();
	        out.close();
		} catch(Exception e) {
			//????????????????????? ??????????????? ??????????????? ??????
			//MSSQL???????????? ????????????
	        if (e instanceof SQLException) {
                String stateCode = ((SQLException)e).getSQLState();
                if(!stateCode.equals("HY008")) throw e;
	        } else {
	        	throw e;
	        }
		}
        return;
	}
	
	@RequestMapping(value = {"/dataSetList.do"}, method = RequestMethod.POST)
    public void dataSetList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
        Timer timer = new Timer();
        
        String dsTypeStr = SecureUtils.getParameter(request, "dsType");
        List<String> dataSourceType = Arrays.asList(dsTypeStr.split(","));
        String userId = SecureUtils.getParameter(request, "userId");
        
        ArrayList<JSONObject> dataSetFolders = new ArrayList<JSONObject>();
		
        List<FolderMasterVO> listDataSetFolder = new ArrayList<FolderMasterVO>();
        List<DataSetInfoMasterVO> listDataSetInfo = new ArrayList<DataSetInfoMasterVO>();
        
        JSONObject ret = new JSONObject();
        
        timer.start();
        
        listDataSetFolder = this.dataSetServiceImpl.selectUserAuthDataSetFolderList(userId);
        if(listDataSetFolder.size() == 0) {
        	listDataSetFolder = this.dataSetServiceImpl.selectGrpAuthDataSetFolderList(userId);
        }
        //if(dsTypeStr.equals(""))
        	listDataSetInfo = this.dataSetServiceImpl.selectDataSetInfoList();
        //else
        //	listDataSetInfo = this.dataSetServiceImpl.selectDataSetInfoList(dataSourceType);
        for (FolderMasterVO dataSetFolder : listDataSetFolder) {
        	JSONObject datasetfld = new JSONObject();

        	datasetfld.put("FLD_ID", dataSetFolder.getFLD_ID());
        	datasetfld.put("FLD_NM", dataSetFolder.getFLD_NM());
        	if(dataSetFolder.getPARENT_FLD_ID() == 0) {
        	} else {
        		datasetfld.put("PARENT_FLD_ID", dataSetFolder.getPARENT_FLD_ID());
        	}
        	
        	dataSetFolders.add(datasetfld);
		}
        
        for(DataSetInfoMasterVO dataSetInfo : listDataSetInfo) {
        	JSONObject datasetinfo = new JSONObject();
        	
        	datasetinfo.put("FLD_ID", "DataSet_"+dataSetInfo.getDATASET_ID());
        	datasetinfo.put("FLD_NM", dataSetInfo.getDATASET_NM());
        	datasetinfo.put("PARENT_FLD_ID", dataSetInfo.getPARENT_FLD_ID());
        	datasetinfo.put("DATASET_ID", dataSetInfo.getDATASET_ID());
        	datasetinfo.put("DATASRC_ID", dataSetInfo.getDATASRC_ID());
        	datasetinfo.put("DATASRC_TYPE", dataSetInfo.getDATASRC_TYPE());
        	
        	dataSetFolders.add(datasetinfo);
        }
        
        ret.put("dataSetFolders", dataSetFolders);

        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
        
        out.print(ret);
		out.flush();
		out.close();   
		return;
    }
	
	@RequestMapping(value = {"/saveReport.do"}, method = RequestMethod.POST)
    public void saveReport(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject result = new JSONObject();
		response.setCharacterEncoding("utf-8");
		String port = request.getLocalPort() + "";
		PrintWriter out = null;

			request.setCharacterEncoding("utf-8");
			out = response.getWriter();
			String reportMeta = SecureUtils.unsecure(SecureUtils.getParameter(request, "JSON_REPORT"));
			if(reportMeta != null) {
				org.json.JSONObject obj = new org.json.JSONObject(reportMeta);
				
				request.setCharacterEncoding("utf-8");
				response.setCharacterEncoding("utf-8");
				String reportNm = obj.getString("report_nm");
				String isNew = obj.get("isNew")+"";
				String fld_id = obj.getString("fld_id");
				//20210909 AJKIM ????????? ?????? ?????? ?????? ?????? ?????? dogfoot
				boolean allowDuplication = false;
				if(obj.has("allowDuplication") && obj.getBoolean("allowDuplication")) {
					allowDuplication = true;
				}
				
				int reportId = 0,reportOrdinal = 0;
				String retNm = this.reportService.checkReport(reportNm,fld_id);
				logger.debug(retNm);
				if(isNew.equals("true")) { // ??????, ???????????? ??????
					if(retNm != null) {
						if(retNm.equals("") || allowDuplication) {
							org.json.JSONObject ret = this.reportService.callUpReportMstrACT(obj, "http://"+(String) request.getSession(false).getAttribute("IP_ADDRESS")+":"+port);
							/* DOGFOOT ktkang ????????? ???????????? ?????? ??????  20200903 */
							List<ReportMasterHisVO> hisList = this.reportService.selectReportMstrHisList(ret);
							if(hisList != null) {
								this.reportService.callUpReportMstrHisACT(obj, "http://"+(String) request.getSession(false).getAttribute("IP_ADDRESS")+":"+port, hisList.size(), ret.getString("reportId"));
							} else {
								this.reportService.callUpReportMstrHisACT(obj, "http://"+(String) request.getSession(false).getAttribute("IP_ADDRESS")+":"+port, 0, ret.getString("reportId"));
							}
							 
							File folder = WebFileUtils.getWebFolder(request, true, "UploadFiles");
							logger.debug("Upload folder: {}", folder);
							File file = new File(folder, ret.getInt("reportId") + ".xml");
							
							try (FileOutputStream fos = new FileOutputStream(file)) {
    							fos.write((ret.get("layoutXmlString")+"").getBytes());
							}
							
							String urlString = this.authenticationService.getConfigMstr().getWEB_URL();
							
							if(ret.getInt("reportId") != 0) {
								reportId = ret.getInt("reportId");
							}
							if(ret.getInt("reportOrdinal") != 0) {
								reportOrdinal = ret.getInt("reportOrdinal");
							}
							
							FolderMasterVO fld_info = this.dataSetServiceImpl.selectReportFld("2",obj.getString("fld_id"), obj.getString("fld_type"));
							User user = this.authenticationService.getSessionUser(request);
							String allFldNm = "";
					        List<FolderMasterVO> fld_info_list = new ArrayList<FolderMasterVO>();
					        if(obj.getString("fld_type").equals("PUBLIC")) {
						        fld_info_list = this.dataSetServiceImpl.selectAllReportFolderList();
						        
						        //20200611 ajkim ?????? ?????? ?????? dogfoot
						        ReportListMasterVO report = new ReportListMasterVO();
								
								Integer id = reportId;
								String text = reportNm;
								String subtitle = obj.getString("report_sub_title");
								String tag = obj.getString("report_tag");
								Integer ordinal = obj.getInt("report_ordinal");
								if(ordinal == 0)
									ordinal = ret.getInt("reportOrdinal");
								String desc = obj.getString("report_desc");
								String prompt = obj.getString("prompt_yn");
								
								report.setID(id);
								report.setTEXT(text);
								report.setSUBTITLE(subtitle);
								report.setTAG(tag);
								report.setORDINAL(ordinal);
								report.setDESCRIPTION(desc);
								report.setPROMPT(prompt);
								
								this.configService.savePublicReport(report);
					        } else {
					        	String userNo = String.valueOf(user.getUSER_NO());
					        	fld_info_list = this.dataSetServiceImpl.selectAllMyReportFolderList(userNo);
					        }
						        
					        //20200506 ajkim ?????? ?????? ?????? ?????? dogfoot
					        int t_fldId = fld_info.getFLD_ID();
					        while(t_fldId != 0) {
					        	int prev = -1;
					        	for(FolderMasterVO vo : fld_info_list) {
					        		if(vo.getFLD_ID() != prev) {
					        			if(t_fldId == vo.getFLD_ID()) {
						        			if(allFldNm.equals("")) {
						        				allFldNm = vo.getFLD_NM();
						        			}else {
						        				allFldNm = vo.getFLD_NM() + " > " + allFldNm;
						        			}
						        			t_fldId = vo.getPARENT_FLD_ID();
						        			break;
						        		}
					        		}
					        		prev = vo.getFLD_ID();
					        	}
					        }
					        
							result.put("return_status", 200);
							result.put("report_id", reportId);
							result.put("report_ordinal", obj.getInt("report_ordinal"));
							result.put("all_fld_nm", allFldNm);
						}
						else {
							result.put("return_status", 422);
							result.put("return_msg", "????????? ????????? ???????????????.<br>?????? ???????????? ???????????????.");
						}
					}
					
				}
				else {
					org.json.JSONObject ret = this.reportService.callUpReportMstrACT(obj, "http://"+(String) request.getSession(false).getAttribute("IP_ADDRESS")+":"+port);
					/* DOGFOOT ktkang ????????? ???????????? ?????? ??????  20200903 */
					List<ReportMasterHisVO> hisList = this.reportService.selectReportMstrHisList(ret);
					if(hisList != null) {
						this.reportService.callUpReportMstrHisACT(obj, "http://"+(String) request.getSession(false).getAttribute("IP_ADDRESS")+":"+port, hisList.size(), ret.getString("reportId"));
					} else {
						this.reportService.callUpReportMstrHisACT(obj, "http://"+(String) request.getSession(false).getAttribute("IP_ADDRESS")+":"+port, 0, ret.getString("reportId"));
					}
					
					File folder = WebFileUtils.getWebFolder(request, true, "UploadFiles");
					logger.debug("Upload folder: {}", folder);
					File file = new File(folder, ret.getInt("reportId") + ".xml");
					
					try (FileOutputStream fos = new FileOutputStream(file)) {
					    fos.write(ret.getString("layoutXmlString").getBytes());
					}
					
//						String urlString = this.authenticationService.getConfigMstr().getWEB_URL();
////							String urlString = Configurator.getInstance().getConfig("wise.ds.repository.url.connection.SVC.location");
//						
//						if(!urlString.contains("SVC")) {
//							//for IIS
//							try {
//								urlString += "UploadFiles/ReportFile/ReportFileUpload.aspx";
//								Http http = new Http(urlString);
//			
//								http.addParam("upload_file1", new File(
//										path+ret.getInt("reportId") + ".xml"))
//										.submit();
//								result.put("return_status", 200);
//								result.put("report_id", ret.getInt("reportId"));
//								result.put("report_ordinal", ret.getInt("reportOrdinal"));
//								out.print(result);
//							} catch (Exception e) {
//								e.printStackTrace();
//								result.put("return_status", 500);
//								out.print(result);
//							}
//						}else {
//							//for JAVA
//							urlString += "UploadFiles/ReportFile/ReportFileUpload.jsp";
//							logger.debug(urlString);
//							try {
//								Http http = new Http(urlString);
//			
//								http.addParam("upload_file1", new File(
//										path+ret.getInt("reportId") + ".xml"))
//										.submit();
//								result.put("return_status", 200);
//								result.put("report_id", ret.getInt("reportId"));
//								result.put("report_ordinal", ret.getInt("reportOrdinal"));
//								out.print(result);
//							} catch (Exception e) {
//								e.printStackTrace();
//								result.put("return_status", 500);
//								out.print(result);
//							}
//						}
					if(ret.getInt("reportId") != 0) {
						reportId = ret.getInt("reportId");
					}
					if(ret.getInt("reportOrdinal") != 0) {
						reportOrdinal = ret.getInt("reportOrdinal");
					}
					
					FolderMasterVO fld_info = this.dataSetServiceImpl.selectReportFld("2",obj.getString("fld_id"), obj.getString("fld_type"));
					User user = this.authenticationService.getSessionUser(request);
					String allFldNm = "";
			        List<FolderMasterVO> fld_info_list = new ArrayList<FolderMasterVO>();
			        if(obj.getString("fld_type").equals("PUBLIC")) {
				        fld_info_list = this.dataSetServiceImpl.selectAllReportFolderList();
			        } else {
			        	String userNo = String.valueOf(user.getUSER_NO());
			        	fld_info_list = this.dataSetServiceImpl.selectAllMyReportFolderList(userNo);
			        }
				        
			        //20200506 ajkim ?????? ?????? ?????? ?????? dogfoot
			        int t_fldId = fld_info.getFLD_ID();
			        while(t_fldId != 0) {
			        	int prev = -1;
			        	for(FolderMasterVO vo : fld_info_list) {
			        		if(vo.getFLD_ID() != prev) {
			        			if(t_fldId == vo.getFLD_ID()) {
				        			if(allFldNm.equals("")) {
				        				allFldNm = vo.getFLD_NM();
				        			}else {
				        				allFldNm = vo.getFLD_NM() + " > " + allFldNm;
				        			}
				        			t_fldId = vo.getPARENT_FLD_ID();
				        			break;
				        		}
			        		}
			        		prev = vo.getFLD_ID();
			        	}
			        }
					
					result.put("return_status", 200);
					result.put("report_id", reportId);
					result.put("report_ordinal", obj.getInt("report_ordinal"));
					result.put("all_fld_nm", allFldNm);
				}
			}

			out.print(result);
			out.flush();
			out.close();
	}
	
	@RequestMapping(value = {"/saveSpreadReport.do"}, method = RequestMethod.POST)
    public void saveSpreadReport(MultipartHttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		
		JSONObject result = new JSONObject();
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		String ip = request.getLocalAddr();
		String port = request.getLocalPort() + "";
		
		String JSON_REPORT =  request.getParameter("JSON_REPORT");
		MultipartFile file = request.getFile("file");
		
		//String reportMeta = SecureUtils.unsecure(SecureUtils.getParameter(request,"JSON_REPORT"));
		org.json.JSONObject obj = new org.json.JSONObject(JSON_REPORT);
	    logger.debug("obj : \t"+obj);
		
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		String reportNm = obj.getString("report_nm");
		String fld_id = obj.getString("fld_id");
		String isNew = obj.get("isNew")+"";
		int reportId = 0,reportOrdinal = 0;
		
		//20210909 AJKIM ????????? ?????? ?????? ?????? ?????? ?????? dogfoot
		boolean allowDuplication = false;
		if(obj.has("allowDuplication") && obj.getBoolean("allowDuplication")) {
			allowDuplication = true;
		}

		String retNm = this.reportService.checkReport(reportNm,fld_id);
		logger.debug(retNm);
		
		
		if(retNm != null) {
			
			if(isNew.equals("true") && !retNm.equals("") && !allowDuplication) {
				result.put("return_status", 422);
				result.put("return_msg", "????????? ????????? ???????????????.<br>?????? ???????????? ???????????????.");
				out.print(result);
				return;
			}

			final org.json.JSONObject ret = this.reportService.callUpSpreadReportMstrACT(obj, "http://"+(String) request.getSession(false).getAttribute("IP_ADDRESS")+":"+port);
			
			String urlString = this.authenticationService.getConfigMstr().getWEB_URL();

			urlString += "UploadFiles/ReportFile/ReportFileUpload.jsp";
			logger.debug(urlString);
			File folder = WebFileUtils.getWebFolder(request, true, "UploadFiles", "ReportFile");
			File reportFile = new File(folder, ret.getInt("reportId") + ".xlsx");
			logger.debug("reportFile: {}", reportFile);
			
			try (FileOutputStream fos = new FileOutputStream(reportFile)) {
				fos.write(file.getBytes());
		    }catch(Throwable e){
		        logger.error("Failed to write report file at {}", reportFile, e);
		    }
			
			if(ret.getInt("reportId") != 0) {
				reportId = ret.getInt("reportId");
			}
			
			if(ret.getInt("reportOrdinal") != 0) {
				reportOrdinal = ret.getInt("reportOrdinal");
			}
			
			//20200611 ajkim ?????? ?????? ?????? dogfoot
	        ReportListMasterVO report = new ReportListMasterVO();
			
			Integer id = reportId;
			String text = reportNm;
			String subtitle = obj.getString("report_sub_title");
			String tag = obj.getString("report_tag");
			Integer ordinal = obj.getInt("report_ordinal");
			if(ordinal == 0)
				ordinal = ret.getInt("reportOrdinal");
			String desc = obj.getString("report_desc");
			String prompt = obj.getString("prompt_yn");
			
			report.setID(id);
			report.setTEXT(text);
			report.setSUBTITLE(subtitle);
			report.setTAG(tag);
			report.setORDINAL(ordinal);
			report.setDESCRIPTION(desc);
			report.setPROMPT(prompt);
			
			this.configService.savePublicReport(report);
			
			result.put("return_status", 200);
			result.put("report_id", reportId);
			result.put("report_ordinal", obj.getInt("report_ordinal"));
			out.print(result);
			
			
		}
	}
	
	@RequestMapping(value="/saveAdhocReport.do", method = RequestMethod.POST)
	public void saveAdhocReport(HttpServletRequest request, HttpServletResponse response) throws Exception {
		JSONObject result = new JSONObject();
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		String ip = request.getLocalAddr();
		String port = request.getLocalPort() + "";
		PrintWriter out = response.getWriter();
		
		String reportMeta = SecureUtils.unsecure(SecureUtils.getParameter(request,"JSON_REPORT"));
		if(reportMeta != null) {
			org.json.JSONObject obj = new org.json.JSONObject(reportMeta);

			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			String reportNm = obj.getString("report_nm");
			String isNew = obj.get("isNew")+"";
			String fld_id = obj.get("fld_id").toString();
			int reportId = 0, reportOrdinal = 0;
			//20210909 AJKIM ????????? ?????? ?????? ?????? ?????? ?????? dogfoot
			boolean allowDuplication = false;
			if(obj.has("allowDuplication") && obj.getBoolean("allowDuplication")) {
				allowDuplication = true;
			}
			String retNm = this.reportService.checkReport(reportNm,fld_id);
			logger.debug(retNm);
			if(retNm != null) {
				if(isNew.equals("true")) {
					if(retNm.equals("") || allowDuplication) {
						org.json.JSONObject ret = this.reportService.callUpAdhocReportMstrACT(obj, "http://"+ip+":"+port);
						if(ret.getInt("reportId") != 0) {
							reportId = ret.getInt("reportId");
						}
						if(ret.getInt("reportOrdinal") != 0) {
							reportOrdinal = ret.getInt("reportOrdinal");
						}
						FolderMasterVO fld_info = this.dataSetServiceImpl.selectReportFld("2",fld_id, obj.getString("fld_type"));
						User user = this.authenticationService.getSessionUser(request);
						String allFldNm = "";
				        List<FolderMasterVO> fld_info_list = new ArrayList<FolderMasterVO>();
				        if(obj.getString("fld_type").equals("PUBLIC")) {
					        fld_info_list = this.dataSetServiceImpl.selectAllReportFolderList();
				        } else {
				        	String userNo = String.valueOf(user.getUSER_NO());
				        	fld_info_list = this.dataSetServiceImpl.selectAllMyReportFolderList(userNo);
				        }
					        
				        //20200506 ajkim ?????? ?????? ?????? ?????? dogfoot
				        int t_fldId = fld_info.getFLD_ID();
				        while(t_fldId != 0) {
				        	int prev = -1;
				        	for(FolderMasterVO vo : fld_info_list) {
				        		if(vo.getFLD_ID() != prev) {
				        			if(t_fldId == vo.getFLD_ID()) {
					        			if(allFldNm.equals("")) {
					        				allFldNm = vo.getFLD_NM();
					        			}else {
					        				allFldNm = vo.getFLD_NM() + " > " + allFldNm;
					        			}
					        			t_fldId = vo.getPARENT_FLD_ID();
					        			break;
					        		}
				        		}
				        		prev = vo.getFLD_ID();
				        	}
				        }
				        
				        //20200611 ajkim ?????? ?????? ?????? dogfoot
				        ReportListMasterVO report = new ReportListMasterVO();
						
						Integer id = reportId;
						String text = reportNm;
						String subtitle = obj.getString("report_sub_title");
						String tag = obj.getString("report_tag");
						Integer ordinal = obj.getInt("report_ordinal");
						if(ordinal == 0)
							ordinal = ret.getInt("reportOrdinal");
						String desc = obj.getString("report_desc");
						String prompt = obj.getString("prompt_yn");
						
						report.setID(id);
						report.setTEXT(text);
						report.setSUBTITLE(subtitle);
						report.setTAG(tag);
						report.setORDINAL(ordinal);
						report.setDESCRIPTION(desc);
						report.setPROMPT(prompt);
						
						this.configService.savePublicReport(report);
						
						result.put("all_fld_nm", allFldNm);
						result.put("return_status", 200);
						result.put("report_id", reportId);
						result.put("report_ordinal", obj.getInt("report_ordinal"));
						//								result.put("return_status", 200);
						//								result.put("report_id", ret.getInt("reportId"));
						//								result.put("report_ordinal", ret.getInt("reportOrdinal"));
						out.print(result);
					}
					else {
						result.put("return_status", 422);
						result.put("return_msg", "????????? ????????? ???????????????.<br>?????? ???????????? ???????????????.");
						out.print(result);
					}
				}
				else {
					org.json.JSONObject ret = this.reportService.callUpAdhocReportMstrACT(obj, "http://"+ip+":"+port);
					if(ret.getInt("reportId") != 0) {
						reportId = ret.getInt("reportId");
					}
					if(ret.getInt("reportOrdinal") != 0) {
						reportOrdinal = ret.getInt("reportOrdinal");
					}
					FolderMasterVO fld_info = this.dataSetServiceImpl.selectReportFld("2",obj.getString("fld_id"), obj.getString("fld_type"));
					User user = this.authenticationService.getSessionUser(request);
					String allFldNm = "";
			        List<FolderMasterVO> fld_info_list = new ArrayList<FolderMasterVO>();
			        if(obj.getString("fld_type").equals("PUBLIC")) {
				        fld_info_list = this.dataSetServiceImpl.selectAllReportFolderList();
			        } else {
			        	String userNo = String.valueOf(user.getUSER_NO());
			        	fld_info_list = this.dataSetServiceImpl.selectAllMyReportFolderList(userNo);
			        }
				        
			        //20200506 ajkim ?????? ?????? ?????? ?????? dogfoot
			        int t_fldId = fld_info.getFLD_ID();
			        while(t_fldId != 0) {
			        	int prev = -1;
			        	for(FolderMasterVO vo : fld_info_list) {
			        		if(vo.getFLD_ID() != prev) {
			        			if(t_fldId == vo.getFLD_ID()) {
				        			if(allFldNm.equals("")) {
				        				allFldNm = vo.getFLD_NM();
				        			}else {
				        				allFldNm = vo.getFLD_NM() + " > " + allFldNm;
				        			}
				        			t_fldId = vo.getPARENT_FLD_ID();
				        			break;
				        		}
			        		}
			        		prev = vo.getFLD_ID();
			        	}
			        }
					
					result.put("all_fld_nm", allFldNm);
					result.put("return_status", 200);
					result.put("report_id", reportId);
					result.put("report_ordinal", obj.getInt("report_ordinal"));
//						result.put("return_status", 200);
//					result.put("report_id", ret.getInt("reportId"));
//						result.put("report_ordinal", ret.getInt("reportOrdinal"));
					out.print(result);
				}
			}
		}
	}
	
	@RequestMapping(value = {"/getFolderList.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject getFolderList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		JSONObject ret = new JSONObject();
		List<FolderMasterVO> reportFolderList = new ArrayList<FolderMasterVO>();
		String fldType = SecureUtils.getParameter(request,"fld_type");
		String userId = SecureUtils.getParameter(request,"user_id");
		if(fldType.equals("PUBLIC")) {
			reportFolderList = this.dataSetServiceImpl.selectUserReportFolderList(userId);
			if(reportFolderList != null) {
				if(reportFolderList.size() == 0) {
					reportFolderList = this.dataSetServiceImpl.selectGrpReportFolderList(userId);
				}
				if(reportFolderList.size() == 0) {
					reportFolderList = this.dataSetServiceImpl.selectAllReportFolderList();
				}
			}
			else {
				reportFolderList = this.dataSetServiceImpl.selectAllReportFolderList();
			}
		}else {
			reportFolderList = this.dataSetServiceImpl.selectPrivateUserReportFolderList(userId);
		}
		JSONArray arr = new JSONArray();
		arr = JSONArray.fromObject(reportFolderList);
		
        ret.put("data", arr);
        
        return ret; 
	}
	
	@RequestMapping(value = {"/directSql.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject directSql(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        Timer timer = new Timer();
        
        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        
        String sql = SecureUtils.getParameter(request, "sql");
        JSONObject ret = new JSONObject();

        String dataSetId = SecureUtils.getParameter(request, "datasetid");
        
        logger.debug("dataset id => " + dataSetId);
        JSONArray param_element = null;
        JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
        
        int paramint = 0;
        if(sql.contains("@")) {
        	paramint = 1;
        }

        if(paramint == 1) {
        	param_element = new JSONArray();
			param_element.add(params);
        	ret.put("param_element", param_element.toString());
        }
        
        sql = StringEscapeUtils.unescapeHtml(sql);
        sql = StringEscapeUtils.unescapeHtml(sql);

        int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();

        //???????????? ?????? ??????
        int dsCnt = 1;
        if(request.getParameter("tbllist")!=null) {
	        JSONArray tbllist = SecureUtils.getJSONArrayParameter(request, "tbllist");
	        int tblCnt = tbllist.size();
	        if(tblCnt>0) {
		        ArrayList<Integer> dsid = new ArrayList<Integer>();
		        ArrayList<String> tblnm = new ArrayList<String>();
		        for(int i=0;i<tblCnt;i++) {
		        	JSONObject jobj = (JSONObject) tbllist.get(i);
		        	dsid.add((int)jobj.get("dsid"));
		        	tblnm.add((String)jobj.get("tblnm"));
		        }
		        
		        //dsid ?????? ??????
		        dsCnt = dsid.parallelStream().distinct().collect(Collectors.toList()).size();
		        if(dsCnt>1) {
			        timer.start();
			        // ????????? - ?????? ?????? ??????  20210913
			        List<JSONObject> result = this.dataSetServiceImpl.directSparkSql(dsid, tblnm, dataSourceType, sql, params);
			        ret.put("data", result);
			        timer.stop();
		        } else {
		        	dataSourceId = dsid.get(0); 
		        }
	        }
        }
        if(dsCnt==1) {
	        timer.start();
	        // ????????? - ?????? ?????? ??????  20210913
	        List<JSONObject> result = this.dataSetServiceImpl.directQuerySql(dataSourceId, dataSourceType, sql, params);
	        ret.put("data", result);
	        timer.stop();
        }
            
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
        
        return ret;
    }
	
	/**
	 * Generate a table/column list for a dataset for drag & drop operations.
	 * @param request
	 * @param response
	 * @param model
	 */
	@RequestMapping(value = {"/getDatasetTableColumnList.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject getDatasetTableColumnList(HttpServletRequest request, HttpServletResponse response, Model model) {
		JSONObject result = new JSONObject();
		response.setCharacterEncoding("utf-8");
        
		long startMili = System.currentTimeMillis();
		long checkMili = 0;
		double checkMin = 0;
		
		String dsIdStr = SecureUtils.getParameter(request, "DATASRC_ID");
		int dsId = 0;
		if(dsIdStr.indexOf(",")>-1) {
			String[] dsIdArr = dsIdStr.split(",");
			dsId = Integer.parseInt(dsIdArr[0]);
		} else {
			dsId = Integer.parseInt(dsIdStr);
		}
        String dsType = SecureUtils.getParameter(request, "DATASRC_TYPE");
        String sql = StringEscapeUtils.unescapeHtml(SecureUtils.getParameter(request, "SQL_QUERY"));
        JSONObject params = SecureUtils.getJSONObjectParameter(request, "PARAMS");
        //20210318 AJKIM ????????? ?????? ?????? ???????????? ?????? dogfoot
        String inMemory = SecureUtils.getParameter(request, "IN_MEMORY");
        
        // ????????? - ?????? ?????? ??????  20210913
        List<JSONObject> sqldata = null;

        try {
	        DataSetMasterVO dataSetMaster;
	        if (DataSetConst.DataSetType.DS.equals(dsType) 
	        		|| DataSetConst.DataSetType.DS_SQL.equals(dsType)
	        		|| DataSetConst.DataSetType.DS_SINGLE.equals(dsType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetMaster(dsId);
	        } 
	        else if (DataSetConst.DataSetType.VIEW.equals(dsType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetViewMaster(dsId);
	        } 
	        else if (DataSetConst.DataSetType.CUBE.equals(dsType) 
	        		|| DataSetConst.DataSetType.DS_CUBE.equals(dsType)) {
	            dataSetMaster = this.dataSetDAO.selectCubeMaster(dsId);
	        } 
	        else {
	            throw new NotFoundDataSetTypeException();
	        }
	        if (dataSetMaster == null) {
	            throw new EmptyDataSetInformationException();
	        }
	        
	        checkMili = System.currentTimeMillis();
	        checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("getDatasetTableColumnList.do ????????? ?????? ???????????? ?????? : " + checkMin + "???");
	        startMili = System.currentTimeMillis();
	        
	        String dbType = dataSetMaster.getDatabaseType();
	        /* DOGFOOT ktkang ????????? ?????? ????????? USE_SQL ??? ???????????? ??? ?????? ??????  20200701 */
	        int dsCnt = 1;
	        if(request.getParameter("TBL_LIST")!=null) {
		        JSONArray tbllist = SecureUtils.getJSONArrayParameter(request, "TBL_LIST");
		        int tblCnt = tbllist.size();
		        if(tblCnt>0) {
			        ArrayList<Integer> dsid = new ArrayList<Integer>();
			        ArrayList<String> tblnm = new ArrayList<String>();
			        for(int i=0;i<tblCnt;i++) {
			        	JSONObject jobj = (JSONObject) tbllist.get(i);
			        	dsid.add((int)jobj.get("dsid"));
			        	tblnm.add((String)jobj.get("tblnm"));
			        }
			        
			        //dsid ?????? ??????
			        dsCnt = dsid.parallelStream().distinct().collect(Collectors.toList()).size();
			        if(dsCnt>1) {
				        //datasource id??? 2??? ????????? ?????? spark??? ????????????.
				        sqldata = this.dataSetServiceImpl.querySparkSql(dsid, tblnm, dsType, sql, params, 0, false, null);
			        } else {
			        	if(inMemory.equals("true")) {
			        		 sqldata = this.dataSetServiceImpl.querySparkSql(dsid, tblnm, dsType, sql, params, 0, false, null);
			        	}
			        	dsId = dsid.get(0); 
			        }
		        }
	        }
	        
	        checkMili = System.currentTimeMillis();
	        checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("getDatasetTableColumnList.do ????????? ?????? : " + checkMin + "???");
	        startMili = System.currentTimeMillis();
	        
	        if(dsCnt==1 && !inMemory.equals("true")) {
	        	sql = this.sqlConvertor.convertTopN(sql, this.dataSetServiceImpl.getDataSourceInfo(dsId, dsType).getDatabaseType(), 1);
	        	sqldata = this.dataSetServiceImpl.queryTableSql(dsId, dsType, sql, params, 0, false, null);
	        }
	        
	        checkMili = System.currentTimeMillis();
	        checkMin = (checkMili - (double) startMili) / 1000;
	        System.out.println("getDatasetTableColumnList.do queryTableSql ?????? : " + checkMin + "???");
	        startMili = System.currentTimeMillis();
	        
        	result.put("data", sqldata);
        } catch(NotFoundDataSetTypeException | EmptyDataSetInformationException e) {
        	result.put("error", 404);
        /* DOGFOOT ktkang ?????? ????????? ??????  20201113 */
        } catch (NotFoundDatabaseConnectorException | UndefinedDataTypeForNullValueException e) {
        	result.put("error", 422);
        } catch (SQLException e) {
        	result.put("error", 428);
        } catch (Exception e) {
        	result.put("error", 500);
        }
        return result;
	}
	
	@RequestMapping(value = {"/directSqlDataSetInfo.do"}, method = RequestMethod.POST)
    public void directSqlDataSetInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
        
        String dataset_nm = SecureUtils.getParameter(request, "DATASET_NM");
        String dataset_type = SecureUtils.getParameter(request, "DATASET_TYPE");
        String dataSrc_id = SecureUtils.getParameter(request, "DATASRC_ID");
        String datasrc_type = SecureUtils.getParameter(request, "DATASRC_TYPE");
        String sql = SecureUtils.getParameter(request, "SQL_QUERY");
        JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
        int datasrc_id = Integer.parseInt(dataSrc_id);
        
        sql = StringEscapeUtils.unescapeHtml(sql);
        sql = StringEscapeUtils.unescapeHtml(sql);
        
        dataset_nm = dataset_nm.replaceAll("&lt;", "<").replaceAll("&gt;", ">");
        
        JSONObject ret = new JSONObject();
        ret.put("DATASET_NM", dataset_nm);
        ret.put("DATASET_TYPE", dataset_type);
        ret.put("DATASRC_ID", datasrc_id);
        ret.put("DATASRC_TYPE", datasrc_type);
        ret.put("SQL_QUERY", this.sqlConvertor.convert(sql));
        
        JSONArray param_element = null;
        
        int paramint = 0;
        if(sql.contains("@")) {
        	paramint = 1;
        }

        if(paramint == 1) {
        	param_element = new JSONArray();
			param_element.add(params);
        	ret.put("param_element", param_element.toString());
        }

        DataSetMasterVO dataSetMaster;
        if (DataSetConst.DataSetType.DS.equals(datasrc_type) || DataSetConst.DataSetType.DS_SQL.equals(datasrc_type)) {
            dataSetMaster = this.dataSetDAO.selectDataSetMaster(Integer.parseInt(dataSrc_id));
        } 
        else if (DataSetConst.DataSetType.VIEW.equals(datasrc_type)) {
            dataSetMaster = this.dataSetDAO.selectDataSetViewMaster(Integer.parseInt(dataSrc_id));
        } 
        else if (DataSetConst.DataSetType.CUBE.equals(datasrc_type)) {
            dataSetMaster = this.dataSetDAO.selectCubeMaster(Integer.parseInt(dataSrc_id));
        } 
        else {
            throw new NotFoundDataSetTypeException();
        }
        if (dataSetMaster == null) {
            throw new EmptyDataSetInformationException();
        }
        
        // ????????? - ?????? ?????? ??????  20210913
        List<JSONObject> sqldata = dataSetServiceImpl.queryTableSql(datasrc_id, datasrc_type, sql, params, 0, true, null);
    
    	ret.put("data", sqldata);
    	ret.put("error", false);

    	PrintWriter out = response.getWriter();
        out.print(ret);
        out.flush();
        out.close(); 
	}
	
	public List<ReportListMasterVO> folderIdUniqueGenerate(List<ReportListMasterVO> param) {
		List<ReportListMasterVO> retList = new ArrayList<ReportListMasterVO>();
		for(ReportListMasterVO report:param) {
			if(report.getTYPE().equals("FOLDER")) {
				report.setUniqueKey("F_"+String.valueOf(report.getID()));
			} else {
				report.setUniqueKey(String.valueOf(report.getID()));
			}
			report.setUpperKey("F_"+report.getUPPERID());
			retList.add(report);
		}
		return retList;
	}
	
	@RequestMapping(value="/getReportList.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject getReport(HttpServletRequest request, HttpServletResponse response) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		JSONObject ret = new JSONObject();
				
		String fld_type = SecureUtils.getParameter(request, "fld_type");
		String user_id = SecureUtils.getParameter(request, "user_id");
		String report_type = SecureUtils.getParameter(request, "report_type");
		
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");
		List<ReportListMasterVO> resultList = null;
		List<ReportListMasterVO> resultList2 = null;
		if(fld_type.equals("PUBLIC")) {
			if (report_type.equals("Spread")) {
				//?????? ?????????
				resultList = folderIdUniqueGenerate(this.dataSetServiceImpl.selectSpreadReportList(user_id));
			} else if (report_type.equals("NotSpread")) {
				//?????? ??????????????????
				resultList = folderIdUniqueGenerate(this.dataSetServiceImpl.selectNotSpreadReportList(user_id));
			} else {
				//?????? ??????
				resultList = folderIdUniqueGenerate(this.dataSetServiceImpl.selectReportList(user_id));
			}
			
			JSONArray arr = new JSONArray();
			arr = JSONArray.fromObject(resultList);
			
	        ret.put("data", arr);
		}
		/* DOGFOOT ktkang ??????????????? ?????? ??????  20200106 */
		else if(fld_type.equals("ALL")) {
			if(report_type.equals("Editor")) {
				//?????? ??????????????????
				resultList = folderIdUniqueGenerate(this.dataSetServiceImpl.selectNotSpreadReportList(user_id));
				//?????? ??????????????????
				resultList2 = folderIdUniqueGenerate(this.dataSetServiceImpl.selectNotUserSpreadReportList(user_id));
			} else {
				//?????? ??????
				resultList = folderIdUniqueGenerate(this.dataSetServiceImpl.selectReportList(user_id));
				//?????? ??????
				resultList2 = folderIdUniqueGenerate(this.dataSetServiceImpl.selectUserReportList(user_id));
				
				//????????? ????????? ??????
				File folder = WebFileUtils.getWebFolder(request, true, "DataFiles");
				File[] files = folder.listFiles();
				List<HashMap<String, String>> scheduleReportFiles = new ArrayList<HashMap<String, String>>(); 
				for (int i = 0; i < files.length; i++) {
					if (files[i].isFile()) {
						String[] fileNameArr = files[i].getName().split("-");
						if(fileNameArr.length>2) {
							String fileSchId = fileNameArr[0];
							String fileReportId = fileNameArr[1];
							String fileExecDate = fileNameArr[2];
							boolean addFlag = true;
							for(HashMap<String, String> param : scheduleReportFiles) {
								if(param.get("report_id").equals(fileReportId)) {
									addFlag = false;
									if(Integer.parseInt(param.get("sch_id")) < Integer.parseInt(fileSchId)) {
										param.put("sch_id", fileSchId);
										param.put("exec_date", fileExecDate);
									}
								}
							}
							if(addFlag) {
								HashMap<String, String> map = new HashMap<String, String>();
								map.put("sch_id", fileSchId);
								map.put("report_id", fileReportId);
								map.put("exec_date", fileExecDate);
								scheduleReportFiles.add(map);
							}
						}
					}
				}

				ArrayList<ReportListMasterVO> resultListSchedule = new ArrayList<ReportListMasterVO>();
				for(ReportListMasterVO reportVo : resultList) {
					for(HashMap<String, String> param : scheduleReportFiles) {
						String uniqueKey = reportVo.getUniqueKey();
						if(uniqueKey.equals(param.get("report_id"))) {
							ReportListMasterVO reportVo2 = (ReportListMasterVO)CloneUtils.clone(reportVo);
							reportVo2.setUniqueKey(uniqueKey+"_schedule");
							reportVo2.setSchedulePath(param.get("sch_id")+"-"+param.get("report_id")+"-"+param.get("exec_date"));
							resultListSchedule.add(reportVo2);
						}
					}
				}
				ret.put("pubScheduleReport", resultListSchedule);
				ArrayList<ReportListMasterVO> resultList2Schedule = new ArrayList<ReportListMasterVO>();
				for(ReportListMasterVO reportVo : resultList2) {
					for(HashMap<String, String> param : scheduleReportFiles) {
						String uniqueKey = reportVo.getUniqueKey();
						if(uniqueKey.equals(param.get("report_id"))) {
							ReportListMasterVO reportVo2 = (ReportListMasterVO)CloneUtils.clone(reportVo);
							reportVo2.setUniqueKey(uniqueKey+"_schedule");
							reportVo2.setSchedulePath(param.get("sch_id")+"-"+param.get("report_id")+"-"+param.get("exec_date"));
							resultList2Schedule.add(reportVo2);
						}
					}
				}
				ret.put("userScheduleReport", resultList2Schedule);
				/* DOGFOOT ktkang BMT ???????????? ???????????? ??????  20201201 */
				List<ReportScheduleVO> resultAllScheduleList = new ArrayList<ReportScheduleVO>();
				resultAllScheduleList = this.reportService.selectReportScheduleAllList2();
				ret.put("resultAllScheduleList", resultAllScheduleList);
			}

			JSONArray arr = new JSONArray();
			arr = JSONArray.fromObject(resultList);
			
			JSONArray arr2 = new JSONArray();
			arr2 = JSONArray.fromObject(resultList2);
			
	        ret.put("pubReport", arr);
	        ret.put("userReport", arr2);
		} else {
			if (report_type.equals("Spread")) {
				//?????? ??????
				resultList = folderIdUniqueGenerate(this.dataSetServiceImpl.selectUserSpreadReportList(user_id));
			} else if (report_type.equals("NotSpread")) {
				//?????? ??????????????????
				resultList = folderIdUniqueGenerate(this.dataSetServiceImpl.selectNotUserSpreadReportList(user_id));
			} else {
				//?????? ??????
				resultList = folderIdUniqueGenerate(this.dataSetServiceImpl.selectUserReportList(user_id));
			}
			
			JSONArray arr = new JSONArray();
			arr = JSONArray.fromObject(resultList);
			
	        ret.put("data", arr);
		}
		
        return ret;
	}
	
	/* DOGFOOT ktkang KERIS ???????????? ?????? ???????????? ??????  20200120 */
	@RequestMapping(value="/getCubeList.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject getCubeList(HttpServletRequest request, HttpServletResponse response) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		JSONObject ret = new JSONObject();

		String ds_view_id = SecureUtils.getParameter(request, "ds_view_id");
		
		List<CubeListMasterVO> resultList = null;
		resultList = this.dataSetServiceImpl.selectCubeFldList(ds_view_id);

		JSONArray arr = new JSONArray();
		arr = JSONArray.fromObject(resultList);

		ret.put("data", arr);

		return ret;
	}
	
	@RequestMapping(value="/uploadSHP.do", method = RequestMethod.POST)
	public void UploadSHP(HttpServletRequest request, HttpServletResponse response) throws Exception {
		MultipartHttpServletRequest multipartHttpServletRequest = (MultipartHttpServletRequest)request;
		Iterator<String> iterator = multipartHttpServletRequest.getFileNames(); 
		MultipartFile multipartFile = null; 
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");
		while(iterator.hasNext()){
			multipartFile = multipartHttpServletRequest.getFile(iterator.next()); 
			if(multipartFile.isEmpty() == false){ 
				logger.debug("------------- file start -------------"); 
				logger.debug("name : "+multipartFile.getName()); 
				logger.debug("filename : "+multipartFile.getOriginalFilename()); 
				logger.debug("size : "+multipartFile.getSize());
				
				if(multipartFile.getSize() > 1024 * 1024 * 1024) 
					throw new ServletException("??????");
				
				String filename = multipartFile.getOriginalFilename();
				if ( filename != null ) { 
				    if( filename.toLowerCase().endsWith(".shp") || filename.toLowerCase().endsWith(".dbf")) { 
				    } else 
				    	throw new ServletException("?????? ????????? ??????"); 
			    } 
				
				File folder = WebFileUtils.getWebFolder(request, true, "UploadFiles", "shp");
				File file = new File(folder, filename);
				try (FileOutputStream fos = new FileOutputStream(file)) {
				    IOUtils.write(multipartFile.getBytes(), fos);
				}
				logger.debug("-------------- file end --------------\n"); 
			} 
		}
	}
	
	@RequestMapping(value="/uploadGeoJSON.do", produces="text/plain;charset=UTF-8", method = RequestMethod.POST)
	public void uploadGeoJSON(HttpServletRequest request, HttpServletResponse response,@RequestBody String paramData) throws Exception {
		JSONObject paramMeta = JSONObject.fromObject(paramData);
		String filename =  paramMeta.getString("fileName");
		filename = filename.substring(0, filename.indexOf(".shp"));
		JSONObject obj = paramMeta.getJSONObject("geojson");
		String path = "";
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");
		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
				/*dogfoot shlim weblogic ???????????? ?????? ??? ?????? path ?????? ????????? (?????? ??????) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\"+"geojson\\";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\"+"geojson\\";
			}
			
		}else {
			if(weblogicPath) {
				/*dogfoot shlim weblogic ???????????? ?????? ??? ?????? path ?????? ????????? (?????? ??????) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/"+"geojson/";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/"+"geojson/";
			}
			
		}
		logger.debug(path);
		FileOutputStream fos = new FileOutputStream(path + filename + ".geojson");
		fos.write(obj.toString().getBytes());
		fos.close();
	}
	
	@RequestMapping(value = "/selectReportScheduleList.do", method = RequestMethod.POST)
    public void selectReportScheduleList(HttpServletRequest request, HttpServletResponse response) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");

		List<ReportScheduleVO> result = new ArrayList<ReportScheduleVO>();
		ArrayList<JSONObject> schs = new ArrayList<JSONObject>();
        JSONObject ret = new JSONObject();
        
        String user_id = SecureUtils.getParameter(request, "user_id");
        String report_id = SecureUtils.getParameter(request, "report_id");
        ReportScheduleVO param = new ReportScheduleVO();
        param.setREG_USER_NO(Integer.parseInt(user_id));
        param.setREPORT_ID(Integer.parseInt(report_id));
        
        Timer timer = new Timer();
    
        timer.start();

        result = this.reportService.selectReportScheduleList(param);
		    
        /*
		for (ReportScheduleVO reportScheduleVO : result) {
			JSONObject sch = new JSONObject();
			sch.put("?????????ID", reportScheduleVO.getSCH_ID());
			sch.put("???????????????", reportScheduleVO.getSCH_DT());
			sch.put("???????????????", reportScheduleVO.getREG_USER_NO());
			sch.put("???????????????", reportScheduleVO.getREG_DT());
			schs.add(sch);
		}

        ret.put("data", schs);
        */
        
        ret.put("data", result);
        try {
        	PrintWriter out = response.getWriter();
        	out.print(ret);
            out.flush();
            out.close();
        } catch (IOException e) {
        	e.printStackTrace();
        }
    }
    
    @RequestMapping(value = {"/insertReportSchedule.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject insertReportSchedule(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	List<ReportScheduleVO> result = new ArrayList<ReportScheduleVO>();
		ArrayList<JSONObject> schs = new ArrayList<JSONObject>();
        JSONObject ret = new JSONObject();
        
        String user_id = SecureUtils.getParameter(request, "user_id");
        String date = SecureUtils.getParameter(request, "date");
        String report_id = SecureUtils.getParameter(request, "report_id");
        ReportScheduleVO param = new ReportScheduleVO();

        Timer timer = new Timer();
        
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        
        Date date2 = format.parse(date);
        String formatted = format.format(date2);
        
        Date time = new Date();
        String time1 = format.format(time);
        		
        param.setUSER_NO(Integer.parseInt(user_id));
        param.setSCH_DT(formatted);
        param.setREPORT_ID(Integer.parseInt(report_id));
        param.setREG_USER_NO(Integer.parseInt(user_id));
        param.setSTATUS_CD(40);
        param.setDEL_YN("N");
        param.setREG_DT(time1);
        param.setEXEC_DATA("");
        
      	this.reportService.insertReportSchedule(param);
      	
      	//result = this.reportService.selectReportScheduleList(param);
	    
      	/*
		for (ReportScheduleVO reportScheduleVO : result) {
			JSONObject sch = new JSONObject();
			sch.put("?????????ID", reportScheduleVO.getSCH_ID());
			sch.put("???????????????", reportScheduleVO.getSCH_DT());
			sch.put("???????????????", reportScheduleVO.getREG_USER_NO());
			sch.put("???????????????", reportScheduleVO.getREG_DT());
			schs.add(sch);
		}
		*/

        ret.put("data", result);

        return ret;
    }
    
    @RequestMapping(value = {"/insertReportScheduleRegular.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject insertReportScheduleRegular(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	List<ReportScheduleVO> result = new ArrayList<ReportScheduleVO>();
		ArrayList<JSONObject> schs = new ArrayList<JSONObject>();
        JSONObject ret = new JSONObject();
        
        String user_id = SecureUtils.getParameter(request, "user_id");
        String report_id = SecureUtils.getParameter(request, "report_id");

        String start_date = SecureUtils.getParameter(request, "start_date");
        String end_date = SecureUtils.getParameter(request, "end_date");
        String exec_time = SecureUtils.getParameter(request, "exec_time");
        
        JSONArray regular_month = SecureUtils.getJSONArrayParameter(request, "regular_month");
        JSONArray regular_week = SecureUtils.getJSONArrayParameter(request, "regular_week");
        JSONArray regular_day = SecureUtils.getJSONArrayParameter(request, "regular_day");
        
        ReportScheduleVO param = new ReportScheduleVO();

        param.setUSER_NO(Integer.parseInt(user_id));
        param.setREPORT_ID(Integer.parseInt(report_id));
        param.setREG_USER_NO(Integer.parseInt(user_id));
        param.setSTATUS_CD(40);
        param.setDEL_YN("N");
        param.setREG_DT(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        param.setEXEC_DATA("");
        
        this.reportService.deleteReportScheduleAll(param);

        LocalDate startLocalDate = LocalDate.parse(start_date);
		LocalDate endLocalDate = LocalDate.parse(end_date);
		
		long dayCnt = ChronoUnit.DAYS.between(startLocalDate, endLocalDate);
		for(int i=0;i<=dayCnt;i++) {
			LocalDate localDate = startLocalDate.plusDays(i);
			LocalDate lastDate = localDate.with(TemporalAdjusters.lastDayOfMonth());

			String localDateFormat = localDate.format(DateTimeFormatter.ofPattern("yyyy-MM-dd"));

			//?????? ???????????????
			boolean flag1 = (regular_month.size()==0);
			//boolean flag1 = false;
			for(int r1=0;r1<regular_month.size();r1++) {
				JSONObject jobj = regular_month.getJSONObject(r1);
				if(jobj.getInt("month")==localDate.getMonthValue()) flag1 = true;
			}
			//????????? ???????????????
			boolean flag2 = (regular_week.size()==0);
			//boolean flag2 = false;
			for(int r2=0;r2<regular_week.size();r2++) {
				JSONObject jobj = regular_week.getJSONObject(r2);
				if(jobj.getInt("week")==localDate.getDayOfWeek().getValue()) flag2 = true;
			}
			//?????? ???????????????
			boolean flag3 = (regular_day.size()==0);
			//boolean flag3 = false;
			for(int r3=0;r3<regular_day.size();r3++) {
				JSONObject jobj = regular_day.getJSONObject(r3);
				int day = jobj.getInt("day");
				if(day==0) {
					//??????????????????
					if(localDate.getDayOfMonth()==lastDate.getDayOfMonth()) flag3 = true;
				}
				else {
					if(day==localDate.getDayOfMonth()) flag3 = true;
				}
			}
			
			if(flag1 && flag2 && flag3) {
		        param.setSCH_DT(localDateFormat + " " + exec_time);
		      	this.reportService.insertReportSchedule(param);
			}
		}        

      	ret.put("data", result);
        return ret;
    }    
    
    @RequestMapping(value = {"/deleteReportSchedule.do"}, method = RequestMethod.POST)
    public void deleteReportSchedule(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        
        String selectSchIds = SecureUtils.getParameter(request, "selectSchId");
        String user_id = SecureUtils.getParameter(request, "user_id");
        
        String[] selectSchIdsArr = selectSchIds.split(",");
        for(String selectSchId:selectSchIdsArr) {
	        ReportScheduleVO param = new ReportScheduleVO();
	        param.setSCH_ID(Integer.parseInt(selectSchId));
	        param.setREG_USER_NO(Integer.parseInt(user_id));
	      	this.reportService.deleteReportSchedule(param);
        }
    }
	
	@RequestMapping(value = "/getScheduledData.do", method = RequestMethod.GET)
	public void getSavedScheduledData(HttpServletRequest request, HttpServletResponse response) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		
		
		JSONArray result = new JSONArray();
		
		File folder = WebFileUtils.getWebFolder(request, true, "DataFiles");		
		File[] files = folder.listFiles();
		for (int i = 0; i < files.length; i++) {
			if (files[i].isFile()) {
				JSONObject file = new JSONObject();
				file.put("id", "0_" + Integer.toString(i));
				file.put("text", files[i].getName());
				result.add(file);
			}
		}
		
		out.print(result);
		out.flush();
		out.close();
	}
	
    @RequestMapping(value = {"/deleteSavedData.do"}, method = RequestMethod.POST)
    public void deleteSavedData(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        String schId = SecureUtils.getParameter(request, "schId");
        String reportId = SecureUtils.getParameter(request, "reportId");
        String fileName = SecureUtils.getParameter(request, "fileName");
       
        ReportScheduleVO param = new ReportScheduleVO();
        param.setSCH_ID(Integer.parseInt(schId));
        param.setREPORT_ID(Integer.parseInt(reportId));
        
      	this.reportService.deleteReportScheduleAndData(param);
      	File folder = WebFileUtils.getWebFolder(request, true, "DataFiles");
      	File file = new File(folder, fileName);
      	file.delete();
    }
    
    @RequestMapping(value = {"/loadSavedData.do"}, method = RequestMethod.GET)
    public void loadSavedData(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	request.setCharacterEncoding("utf-8");
    	response.setCharacterEncoding("utf-8");
    	PrintWriter out = response.getWriter();
    	
    	String fileName = SecureUtils.getParameter(request, "fileName");
		File folder = WebFileUtils.getWebFolder(request, true, "DataFiles");
		File file = new File(folder, fileName);

		try (InputStream is = new FileInputStream(file)) {
    		String jsonText = IOUtils.toString(is, "UTF-8");
    		JSONObject data = (JSONObject) JSONSerializer.toJSON(jsonText);
    		out.print(data);
		}

		out.flush();
		out.close();
    }
    
    @RequestMapping(value= {"/runScheduleChecker.do"}, method = RequestMethod.POST)
    public void openScheduler(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
    	
//    	int reportId = Integer.parseInt(SecureUtils.getParameter(request, "reportId"));
    	String userId = SecureUtils.getParameter(request, "userId");
    	JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
		File folder = WebFileUtils.getWebFolder(request, true, "DataFiles");
        ScheduleThread st = new ScheduleThread(this.reportService, this.sqlStorage, this.dataSetServiceImpl, Integer.parseInt(userId) , folder.getPath(), params);
        Thread t = new Thread(st, "test");
        t.start();
    }
    
    @RequestMapping(value="/cube/generateQueries.do", method = RequestMethod.POST)
	public void genCubeSql(HttpServletRequest request, HttpServletResponse response) throws Exception {
    	request.setCharacterEncoding("utf-8");
    	response.setCharacterEncoding("utf-8");
    	
		PrintWriter out = response.getWriter();
		User sessionUser = this.authenticationService.getSessionUser(request);
        
        Timer timer = new Timer();
        
        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        
        JSONObject ret = new JSONObject();
        
        int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
        JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
        JSONObject cols = SecureUtils.getJSONObjectParameter(request, "cols");
        JSONArray dimensions = cols.getJSONArray("dim");
        JSONArray measures = cols.getJSONArray("mea");
        
        JSONArray filters = SecureUtils.getJSONArrayParameter(request, "filters");
        JSONArray subquery = SecureUtils.getJSONArrayParameter(request, "subquery");
        timer.start();
        
        ret.put("CubeSql", this.dataSetServiceImpl.generateCubeQuery(sessionUser, dataSourceId, dataSourceType, params, dimensions, measures, filters,subquery));
        DataSetMasterVO dataSetMaster = this.dataSetDAO.selectCubeMaster(dataSourceId);
        ret.put("DS_ID", dataSetMaster.getId());

        timer.stop();
            
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());

        out.print(ret);
        out.flush();
        out.close();  
	}
    
    @RequestMapping(value = {"/execToss.do"})
    private ModelAndView execToss(HttpServletRequest request, Model model) throws Exception {
        String redirector = "execToss";
        ModelAndView mv = new ModelAndView(redirector);
        
        return mv;
    }
    
    @RequestMapping(value = {"/execBatch.do"})
    private void execBatch(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	request.setCharacterEncoding("utf-8");
    	response.setCharacterEncoding("utf-8");
    	
    	PrintWriter out = response.getWriter();
    	
    	String uploadPath = request.getServletContext().getRealPath("/UploadFiles/tossBatch/CALL_TOS/");
    	String runshell_or_batch = SecureUtils.getParameter(request, "runType");
        String tableNm = SecureUtils.getParameter(request, "tableNm");
        String fileSpliter = "";
        if(runshell_or_batch.equals("bat")) {
        	fileSpliter = "\\";
        }else {
        	fileSpliter = "/";
        }
        
        JSONObject ret = new JSONObject();
        long startTime = System.currentTimeMillis();
        String execNm = "";
		
        SimpleDateFormat format1 = new SimpleDateFormat("yyyyMMddHHmmss");
        
        String codeKey = format1.format(startTime)+tableNm;

		execNm = uploadPath + fileSpliter + "CALL_TOS_run."+runshell_or_batch+" --context_param CODE="+codeKey+" --context_param TBL_NM="+tableNm;
		TossExecutor bebt = new TossExecutor(execNm);
		bebt.start();
		ret.put("CODE", codeKey);
		ret.put("TBL_NM", tableNm);
		
		logger.debug(ret.toString());
		out.print(ret);
		out.flush();
		out.close();
    }
    
    @RequestMapping(value = {"/getBatchStatus.do"})
    private void getBatchStatus(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	request.setCharacterEncoding("utf-8");
    	response.setCharacterEncoding("utf-8");
    	
    	PrintWriter out = response.getWriter();
    	String codeKey = SecureUtils.getParameter(request, "CODE");
    	String tableNm = SecureUtils.getParameter(request, "TBL_NM");
		
    	JSONObject ret = new JSONObject();
    	
    	Map param = new HashMap<>();
    	param.put("CODE", codeKey);
    	param.put("TBL_NM", tableNm);
    	
    	TossExeVO tossvo = this.dataSetServiceImpl.getTossBatch(param);
    	if(tossvo != null) {
    		if(tossvo.getSTATUS_CD().equals("60")) {
        		long startTime = Timestamp.valueOf(tossvo.getSTART_DT()).getTime();
        		long endTime = Timestamp.valueOf(tossvo.getEND_DT()).getTime();
        		long interval = endTime - startTime;
        		int seconds = (int) (interval / 1000) % 60 ;
            	int minutes = (int) ((interval / (1000*60)) % 60);
            	int hours   = (int) ((interval / (1000*60*60)) % 24);
            	
//            	System.out.println(String.format("%02d:%02d:%02d.%03d", hours, minutes, seconds,(interval%1000)));
            	String intervalLong = String.format("%02d:%02d:%02d.%03d", hours, minutes, seconds,(interval%1000));
            	ret.put("STATUS_CD", tossvo.getSTATUS_CD());
        		ret.put("STATUS_NM", tossvo.getSTATUS_NM());
        		ret.put("interval", intervalLong);
        	}
        	else {
//        		ret.put("STATUS", tossvo.getSTATUS_NM());
        		ret.put("STATUS_CD", tossvo.getSTATUS_CD());
        		ret.put("STATUS_NM", tossvo.getSTATUS_NM());
        	}
    	}else {
    		ret.put("STATUS_NM", "?????????");
    		ret.put("STATUS_CD", "50");
    	}
    	
    	logger.debug(ret.toString());
    	out.print(ret);
    	out.flush();
    	out.close();
    }
    
    @RequestMapping(value = {"/rollupSql.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject rollupSql(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        Timer timer = new Timer();
        JSONObject ret = new JSONObject();

    	String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        
        String selectDim = SecureUtils.getParameter(request, "selectDim");
        String selectMea = SecureUtils.getParameter(request, "selectMea");
        String sql = SecureUtils.getParameter(request, "sql");
        
        JSONObject params = new JSONObject();
        
        int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
        
        selectDim = selectDim.substring(0, selectDim.length()-1);
        selectMea = selectMea.substring(0, selectMea.length()-1);
        
        String query = "SELECT " + selectDim + ", SUM(" + selectMea + ") FROM (" + sql + ") GROUP BY ROLLUP(" + selectDim + ")";
        
        timer.start();
        
		// ????????? - ?????? ?????? ??????  20210913
        List<JSONObject> result = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, query, params, 0, null);
        //ORIGIN
//            JSONArray result = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, query, params, 0, false);

        String[] dimArray = selectDim.split(",");
        int dimLength = dimArray.length;
        
        for(int i = 0; i < result.size()-1; i++) {
        	for(int k = 0; k < dimLength; k++) {
        		// ????????? - ?????? ?????? ??????  20210913
        		if(result.get(i).getString(dimArray[k]) == "") {
        			JSONObject change =  result.get(i);
        			change.put(dimArray[k], "??????");
        		}
        	}
        }
        
        for(int k = 0; k < dimLength; k++) {
        	// ????????? - ?????? ?????? ??????  20210913
    		if(result.get(result.size()-1).getString(dimArray[k]) == "") {
    			JSONObject change =  result.get(result.size()-1);
    			change.put(dimArray[k], "??????");
    			break;
    		}
    	}
        
        ret.put("data", result);
        timer.stop();

        return ret;
    }
    @RequestMapping(value = {"/getReportType.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject getReportType(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        Timer timer = new Timer();
        JSONObject ret = new JSONObject();

       	String pid = SecureUtils.getParameter(request, "pid");
        	
    	ReportMasterVO reportInfo = this.reportService.selectReportType(pid);
    	/* DOGFOOT ktkang BMT ???????????? ???????????? ??????  20201201 */
    	String schedulePath = this.reportService.selectSchedulePath(Integer.parseInt(pid));

    	ret.put("reportType", reportInfo.getREPORT_TYPE());
    	ret.put("fldType", reportInfo.getFLD_TYPE());
    	ret.put("schedulePath", schedulePath);
        timer.stop();
        
        return ret;
    }
    
    @RequestMapping("/getParamNames.do")
   	public void getParamNames(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
   		response.setCharacterEncoding("utf-8");
   		PrintWriter out = response.getWriter();
   		
   		String reportId = SecureUtils.getParameter(request, "reportId");
   		
   		ReportMasterVO ret = this.reportService.selectReportParam(Integer.parseInt(reportId));
   		
   		JSONObject obj = new JSONObject();
   		obj.put("paramNames", ret.getParamJson());
   		out.print(obj);
   		out.flush();
   		out.close();
   	}
    
    @RequestMapping(value = {"/getGeoJSon.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject getGeoJson(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	JSONObject ret = new JSONObject();
    	String urlPath = SecureUtils.getParameter(request, "geojsonUrl");
    	String name = SecureUtils.getParameter(request, "name");
    		// ???????????? ?????? ??????
    	StringBuffer sb = new StringBuffer(); 

    	File folder = WebFileUtils.getWebFolder(request, true, "UploadFiles", "geojson", name);
    	File file = new File(folder, urlPath);
    	
    	try (BufferedReader br = new BufferedReader(new FileReader(file))) {
    		String line = null;
    		while ((line = br.readLine()) != null) {
    			sb.append(line);
    		}
    		ret.put("geoJsonMeta", sb.toString());
    	}

        return ret;
    }
    
    @RequestMapping("/uploadDsList.do")
	public void dsList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		ArrayList<JSONObject> dsList = new ArrayList<JSONObject>();
		boolean isUploadEnable = true;
		/* DOGFOOT ktkang ????????? ????????? ????????? ?????? ??????  20200716 */
		String userId = SecureUtils.getParameter(request, "userId");
		
		List<SubjectMasterVO> listSubject = this.dataSetServiceImpl.selectSubjectList(isUploadEnable, userId);
		ArrayList<JSONObject> subjects = new ArrayList<JSONObject>();
        JSONObject subjectInfos = new JSONObject();
		int i = 0;
		
		for (SubjectMasterVO subjectMasterVO : listSubject) {
			JSONObject subject = new JSONObject();
			JSONObject subjectInfo = new JSONObject();

			subjectInfo.put("????????? ?????? ???", subjectMasterVO.getDS_NM());
			subjectInfo.put("?????? ??????(???)", subjectMasterVO.getIP());
			subjectInfo.put("DB ???", subjectMasterVO.getDB_NM());
			subjectInfo.put("DB ??????", subjectMasterVO.getDBMS_TYPE());
			subjectInfo.put("Port", subjectMasterVO.getPORT());
			subjectInfo.put("?????????", subjectMasterVO.getOWNER_NM());
			subjectInfo.put("?????? ID", subjectMasterVO.getUSER_ID());
			subjectInfo.put("??????", subjectMasterVO.getDS_DESC());

			subject.put("DS_ID", subjectMasterVO.getDS_ID());
			subject.put("ID", i);
			subject.put("??????????????? ???", subjectMasterVO.getDS_NM());
			subject.put("DB ??????", subjectMasterVO.getDBMS_TYPE());
			subject.put("DB ???", subjectMasterVO.getDB_NM());
			subject.put("?????? ??????(???)", subjectMasterVO.getIP());
			subject.put("????????? ?????????", subjectMasterVO.getUSER_AREA_YN());
			subject.put("USER_ID", subjectMasterVO.getUSER_ID());
			subject.put("IP", subjectMasterVO.getIP());
			subject.put("DB_TYPE", subjectMasterVO.getDBMS_TYPE());
			subject.put("DB_NM", subjectMasterVO.getDB_NM());
//			subject.put("PASSWD", subjectMasterVO.getPASSWD());
			subject.put("PORT", subjectMasterVO.getPORT());
			subject.put("OWNER", subjectMasterVO.getOWNER_NM());

			subjects.add(subject);
			subjectInfos.put(i, subjectInfo);
			i++;
		}
		JSONObject obj = new JSONObject();
		obj.put("subjects", subjects);
		obj.put("subjectInfos", subjectInfos);
		
		out.print(obj);
		out.flush();
		out.close();
	}
    
    @RequestMapping("/Upload/data.do")
	public void uploadDataFile(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		
		try {
		String ckutf = request.getParameter("ckutf");
		String rename = request.getParameter("rename");
		
		String filename = "",file = "";
		ArrayList<JSONObject> colArr = new ArrayList<JSONObject>();
		
			out = response.getWriter();
			File uploadFolder = WebFileUtils.getWebFolder(request, true, "UploadFiles", "UserUpload");
			
			// ?????? ?????????. ????????? ????????? ???????????? ?????? ??????request ?????? ??????,
			// ????????? ??????, ?????? ?????? ??????, ????????????, ?????? ????????????
//			MultipartRequest multi = new MultipartRequest(request, uploadPath, size, "utf-8");
			
			MultipartHttpServletRequest multipartHttpServletRequest = (MultipartHttpServletRequest)request;
			Iterator<String> iterator = multipartHttpServletRequest.getFileNames(); 
			MultipartFile multipartFile = null; 
			while(iterator.hasNext()){
				multipartFile = multipartHttpServletRequest.getFile(iterator.next());
//				if(multipartFile.isEmpty() == false){ 
					
//					file = (String) multipartFile.getName();
//					filename = multipartFile.getOriginalFilename();
					if(multipartFile.isEmpty() == false){ 
						if(multipartFile.getSize() > 1024 * 1024 * 100) 
							throw new ServletException("??????");
						filename = multipartFile.getOriginalFilename();
						if(rename != null && rename.equals("true")) {
							filename = "wise" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date(System.currentTimeMillis())) + "." + filename.split("\\.")[1];
						}
						if ( filename != null ) { 
						    if( filename.toLowerCase().endsWith(".csv") || filename.toLowerCase().endsWith(".xlsx") || filename.toLowerCase().endsWith(".xls")) { 
					   /* file ????????? ?????? */ 
						    } else 
						    	throw new ServletException("?????? ????????? ??????"); 
					    } 
						
						logger.debug("------------- file start -------------"); 
						logger.debug("utf : "+ckutf); 
						logger.debug("name : "+multipartFile.getName()); 
						logger.debug("filename : "+filename);
						logger.debug("size : "+multipartFile.getSize());
						File uploadFile = new File(uploadFolder, filename);
						try (FileOutputStream fos = new FileOutputStream(uploadFile)) {
						    fos.write(multipartFile.getBytes());
						}
						logger.debug("-------------- file end --------------\n"); 
					}
//				}
			}
			// ???????????? ???????????? Enumeration ???????????? ??????
			// Enumeration?????? ???????????? ???????????? ????????? ??????????????? Enumeration????????? java.util ???????????? ?????? ??????????????????
			// java.util.Enumeration??? import ????????? ??????.
//			Enumeration files = multi.getFileNames();
			
			// ???????????? ???????????? ????????? ?????????
			String ext = "";
			int index = filename.lastIndexOf(".");
			if (index != -1) {
				ext = filename.substring(index + 1);
			}

			if (ext.equalsIgnoreCase("csv")) {
//				BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(uploadPath+"\\"+filename), "euc-kr"));
				String fileEncode = ckutf.equals("true")?"utf8":"euc-kr";
				File uploadFile = new File(uploadFolder, filename);
				
				try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(uploadFile), fileEncode))) {
    				if(br != null) {
    					String line = br.readLine();
    					String[] field = line.split(",");
    					
    					ArrayList<JSONObject> tempArr = new ArrayList<JSONObject>();
    					if(field != null) {
    						for(int i=0;i<field.length;i++) {
    							String str = field[i];
    					        str = (str.startsWith(UTF8_BOM)) ? str.substring(1):str;
    							JSONObject obj = new JSONObject();
    							obj.put("colNm", str);
    							obj.put("colPhysicalNm", (str.replaceAll(" ", "")));
    //							obj.put("colType", "String");
    							obj.put("colSize", 255);
    							obj.put("realpath", uploadFile.getPath());
    							obj.put("fileName", filename);
    							tempArr.add(obj);
    						}
    					}
    					line = br.readLine();
    					field = line.split(",", -1);
    					for(int i=0;i<field.length;i++) {
    						JSONObject obj = tempArr.get(i);
    						if(isStringDouble(field[i]))
    							obj.put("colType", "int");
    						else{
    							obj.put("colType", "String");
    						}
    						colArr.add(obj);
    					}
    				}
				}
			}
			else if(ext.equalsIgnoreCase("xls")) {
				ArrayList<JSONObject> tempArr = new ArrayList<JSONObject>();
				File uploadFile = new File(uploadFolder, filename);

				try (FileInputStream fis = new FileInputStream(uploadFile); HSSFWorkbook workbook = new HSSFWorkbook(fis)) {
    				int columnindex=0;
    				HSSFSheet sheet=workbook.getSheetAt(0);
    				HSSFRow row=sheet.getRow(0);
    				int cells=row.getPhysicalNumberOfCells();
    				for(columnindex=0;columnindex<cells;columnindex++){
    					HSSFCell cell=row.getCell(columnindex);
    					String value="";
    					switch (cell.getCellTypeEnum()){
    					case FORMULA:
    	                    value=cell.getCellFormula();
    	                    break;
    					case NUMERIC:
    	                    value=cell.getNumericCellValue()+"";
    	                    break;
    					case STRING:
    	                    value=cell.getStringCellValue()+"";
    	                    break;
    	                case BLANK:
    	                    value=cell.getBooleanCellValue()+"";
    	                    break;
    	                case ERROR:
    	                    value=cell.getErrorCellValue()+"";
    	                    break;
    	                }
    					
    					JSONObject obj = new JSONObject();
    					obj.put("colNm", value);
    					obj.put("colPhysicalNm", (value.replaceAll(" ", "")));
    					obj.put("colSize", 255);
    					obj.put("realpath", uploadFile.getPath());
    					obj.put("fileName", filename);
    					tempArr.add(obj);
    				}
    				row=sheet.getRow(1);
    //				cells=row.getPhysicalNumberOfCells();
    				for(columnindex=0;columnindex<cells;columnindex++){
    					HSSFCell cell=row.getCell(columnindex);
    					if(cell == null) {
    						String valueType = "String";
    						JSONObject obj = tempArr.get(columnindex);
    						obj.put("colType",valueType);
    						colArr.add(obj);
    					}else {
    						String valueType ="";
    						switch (cell.getCellTypeEnum()){
    		                case FORMULA:
    		                    valueType = "int";
    		                    break;
    		                case NUMERIC:
    		                    valueType = "int";
    		                    break;
    		                case STRING:
    		                    valueType = "String";
    		                    break;
    		                case BLANK:
    		                    valueType = "boolean";
    		                    break;
    		                case ERROR:
    		                    valueType = "String";
    		                    break;
    		                }
    						JSONObject obj = tempArr.get(columnindex);
    						obj.put("colType",valueType);
    						colArr.add(obj);
    					}
    				}
				}
			}
			else {
				ArrayList<JSONObject> tempArr = new ArrayList<JSONObject>();
//				Row row = null; //????????? ???????????? ???????????? Row ??????
//
//				Iterator<Row> iter = null; //???????????? Row ????????? ???????????? Iterator
//				File fileClass = new File(uploadPath+"/"+filename);
//				OPCPackage opc = OPCPackage.open(fileClass);
//
//				XSSFWorkbook workbook = new XSSFWorkbook(opc);
//
//				opc.close();
//
//				XSSFSheet sheet = workbook.getSheetAt(0);
//
//				iter = sheet.iterator();
//				String a, b, c, d;
//				while(iter.hasNext()){ //???????????? ???????????? ????????? ????????? ????????? ?????????.
//
//					row = iter.next();
//
//					a = row.getCell(0).getStringCellValue().trim(); //getCell(0) -> 1??? ??????
//
//					b = row.getCell(1).getStringCellValue().trim();
//
//					c = row.getCell(2).getStringCellValue().trim();
//
//					d = row.getCell(3).getStringCellValue().trim();
//
//					System.out.println(a+"\t"+b+"\t"+c+"\t"+d);
//
//					}
				
//				File fileClass = new File(uploadPath+"/"+filename);
//				OPCPackage pkg = OPCPackage.open(fileClass);
////				XSSFWorkbook workbook = new XSSFWorkbook(fileClass);
//				XSSFReader r = new XSSFReader(pkg);
//				SharedStringsTable sst = r.getSharedStringsTable();
//				
//				XMLReader parser = fetchSheetParser(sst);
//				
//				Iterator<InputStream> sheets = r.getSheetsData();
//				
//				while(sheets.hasNext()) {
//					InputStream sheet = sheets.next();
//		            InputSource sheetSource = new InputSource(sheet);
//		            parser.parse(sheetSource);
//		            sheet.close();
//		            System.out.println("");
//				}
				
//				while(sheets.hasNext()) {
//					Sheet wbsheet = workbook.getSheetAt(i);
//					sheetName = wbsheet.getSheetName();
//					
//					System.out.println("processing new Sheet : ["+sheetName+"] \n");
//					sheetStream = sheets.next();
//					sheetSource = new InputSource(sheetStream);
//					parser.parse(sheetSource);
//					sheetStream.close();
//					System.out.println("");
//					i++;
//					
////					int columnindex=0;
////					Sheet wbsheet = workbook.getSheetAt(i);
////					sheetName = wbsheet.getSheetName();
////					
////					sheetStream = sheets.next();
////					sheetSource = new InputSource(sheetStream);
////					parser.parse(sheetSource);
////					Row row = wbsheet.getRow(0);
////					int cells=row.getPhysicalNumberOfCells();
////					for(columnindex=0;columnindex<cells;columnindex++){
////						Cell cell = row.getCell(columnindex);
////						String value = "";
////						switch (cell.getCellTypeEnum()) {
////							case FORMULA:
////			                    value=cell.getCellFormula();
////			                    break;
////			                case NUMERIC:
////			                    value=cell.getNumericCellValue()+"";
////			                    break;
////			                case STRING:
////			                    value=cell.getStringCellValue()+"";
////			                    break;
////			                case BLANK:
////			                    value=cell.getBooleanCellValue()+"";
////			                    break;
////			                case ERROR:
////			                    value=cell.getErrorCellValue()+"";
////			                    break;
////						}
////						JSONObject obj = new JSONObject();
////						obj.put("colNm", value);
////						obj.put("colPhysicalNm", (value.replaceAll(" ", "")));
////						obj.put("colSize", 255);
////						obj.put("realpath", uploadPath+"/"+filename);
////						obj.put("fileName", filename);
////						tempArr.add(obj);
////					}
////					row=wbsheet.getRow(1);
////					for(columnindex=0;columnindex<cells;columnindex++){
////						Cell cell=row.getCell(columnindex);
////						String valueType ="";
////						if(cell == null) {
////							valueType = "String";
////							JSONObject obj = tempArr.get(columnindex);
////							obj.put("colType",valueType);
////							colArr.add(obj);
////						}else {
////							switch (cell.getCellType()){
////			                case FORMULA:
////			                    valueType = "int";
////			                    break;
////			                case NUMERIC:
////			                    valueType = "int";
////			                    break;
////			                case STRING:
////			                    valueType = "String";
////			                    break;
////			                case BLANK:
////			                    valueType = "boolean";
////			                    break;
////			                case ERROR:
////			                    valueType = "String";
////			                    break;
////			                }
////							JSONObject obj = tempArr.get(columnindex);
////							obj.put("colType",valueType);
////							colArr.add(obj);
////						}
////					}
//				}
				
				File uploadFile = new File(uploadFolder, filename);
				
				try (FileInputStream fis=new FileInputStream(uploadFile); XSSFWorkbook workbook = new XSSFWorkbook(fis)) {
    				int columnindex=0;
    				XSSFSheet sheet=workbook.getSheetAt(0);
    				XSSFRow row=sheet.getRow(0);
    				int cells=row.getPhysicalNumberOfCells();
    				for(columnindex=0;columnindex<cells;columnindex++){
    					XSSFCell cell=row.getCell(columnindex);
    					String value="";
    					switch (cell.getCellTypeEnum()){
    	                case FORMULA:
    	                    value=cell.getCellFormula();
    	                    break;
    	                case NUMERIC:
    	                    value=cell.getNumericCellValue()+"";
    	                    break;
    	                case STRING:
    	                    value=cell.getStringCellValue()+"";
    	                    break;
    	                case BLANK:
    	                    value=cell.getBooleanCellValue()+"";
    	                    break;
    	                case ERROR:
    	                    value=cell.getErrorCellValue()+"";
    	                    break;
    	                }
    					
    					JSONObject obj = new JSONObject();
    					obj.put("colNm", value);
    					obj.put("colPhysicalNm", (value.replaceAll(" ", "")));
    					obj.put("colSize", 255);
    					obj.put("realpath", uploadFile.getPath());
    					obj.put("fileName", filename);
    					tempArr.add(obj);
    				}
    				row=sheet.getRow(1);
    //				cells=row.getPhysicalNumberOfCells();
    				for(columnindex=0;columnindex<cells;columnindex++){
    					XSSFCell cell=row.getCell(columnindex);
    					String valueType ="";
    					if(cell == null) {
    						valueType = "String";
    						JSONObject obj = tempArr.get(columnindex);
    						obj.put("colType",valueType);
    						colArr.add(obj);
    					}else {
    						switch (cell.getCellType()){
    		                case FORMULA:
    		                    valueType = "int";
    		                    break;
    		                case NUMERIC:
    		                    valueType = "int";
    		                    break;
    		                case STRING:
    		                    valueType = "String";
    		                    break;
    		                case BLANK:
    		                    valueType = "boolean";
    		                    break;
    		                case ERROR:
    		                    valueType = "String";
    		                    break;
    		                }
    						JSONObject obj = tempArr.get(columnindex);
    						obj.put("colType",valueType);
    						colArr.add(obj);
    					}
    				}
				}
			}
			out.print(colArr);
			out.flush();
			out.close();	
		/* DOGFOOT ktkang ????????? ????????? ????????? ?????? ??????  20200910 */
		} catch(Exception e) {
			e.printStackTrace();
			ArrayList<JSONObject> colArr = new ArrayList<JSONObject>();
			JSONObject objCode = new JSONObject();
			objCode.put("code", 500);
			colArr.add(objCode);
			out.print(colArr);
			out.flush();
			out.close();	
		}
	}
    
    private XMLReader fetchSheetParser(SharedStringsTable sst) throws Exception {
//    	XMLReader parser = XMLReaderFactory.createXMLReader("org.apache.xerces.parsers.SAXParser");
    	XMLReader parser = SAXHelper.newXMLReader();
    	ContentHandler handler = new SheetHandler(sst);
    	parser.setContentHandler(handler);
		return parser;
	}

	public boolean isStringDouble(String s) {
		try {
			//Double.parseDouble(s);
			Integer.parseInt(s);
			return true;
		} catch (NumberFormatException e) {
			return false;
		}
	}
    @RequestMapping(value = "/uploadTableList.do" , method = RequestMethod.POST)
   	public void uploadTableList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		
		JSONArray tableList = new JSONArray();
		String ds_id = (SecureUtils.getParameter(request,"DS_ID"));
		String userId = (SecureUtils.getParameter(request,"userId"));
		
		List<UserUploadMstrVO> dsVO = this.dataSetDAO.selectUploadTableList(Integer.parseInt(ds_id));
		for(UserUploadMstrVO vo : dsVO) {
			JSONObject obj = new JSONObject();
			obj.put("DATA_NM",vo.getDATA_NM());
			obj.put("TBL_NM",vo.getTBL_NM());
//			obj.put("UPLOAD_XML", org.json.XML.toJSONObject(vo.getUPLOAD_XML()).toString());
			obj.put("DS_ID",vo.getDS_ID());
			tableList.add(obj);
		}
//		System.out.println(tableList);
		out.print(tableList);
		out.flush();
		out.close();
    }
    /*dogfoot shlim 20210308
     * ????????? ????????? ???????????? ???????????? ????????? ?????? ?????? ?????? 
     * ????????? ?????? ????????? ????????? ????????? ??????????????? ????????? ?????? ?????? ??????
     * */
    public boolean checkOnlyNumInString(String s) {
        char tmp;
            for (int i =0; i<s.length(); i++){
                tmp = s.charAt(i);
                if(Character.toString(s.charAt(i)) == ".") {
                	
                }else if(Character.isDigit(tmp)==false){
                    return false;
                }
                
            }
        return true;
    }
    
    @RequestMapping(value = "/Upload/save.do" , method = RequestMethod.POST)
	public void Uploadsave(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		
		/* DOGFOOT ktkang ????????? ????????? ????????? ????????? ??????  20200904 */
		try {
			JSONObject ds = new JSONObject();
			String ds_id = (SecureUtils.getParameter(request,"DS_ID"));
			String ip = (SecureUtils.getParameter(request,"IP"));
			String id = (SecureUtils.getParameter(request,"ID"));
			String port = (SecureUtils.getParameter(request,"PORT"));
			String dbNm = (SecureUtils.getParameter(request,"DB_NM"));
			String dbtype = (SecureUtils.getParameter(request,"DB_TYPE"));
			String tableCaption = (SecureUtils.getParameter(request,"TBL_CAPTION"));
			String Owner = (SecureUtils.getParameter(request,"OWNER"));
			String appendTable = SecureUtils.getParameter(request,"appendTable");
			String targetTable = SecureUtils.getParameter(request,"targetTable");
			String colList = SecureUtils.unsecure(SecureUtils.getParameter(request,"colList"));
			String tableDeleteYN = SecureUtils.getParameter(request,"tableDeleteYN");
			String userId = SecureUtils.getParameter(request,"userId");
			String ckutf = SecureUtils.getParameter(request,"ckutf");
			String realpath ="";
			String filename = "";
			if(ds_id != null && ip != null && id != null && port != null && dbNm != null && dbtype != null && tableCaption != null && Owner != null && appendTable != null && targetTable != null && tableDeleteYN != null && userId != null) {
				if(colList != null) {
					JSONArray jsonarr = JSONArray.fromObject(colList);
					//			System.out.println(colList);

					DataSetMasterVO dsVO = this.dataSetDAO.selectDataSetMaster(Integer.parseInt(ds_id));
					String passwd = dsVO.getDatabasePassword();

					String driverClass = "";
					Connection conn = null;
					ResultSet rs = null;
					PreparedStatement pstmt = null;
					String tmpTblNm = "";
					if(dbtype != null) {
						if(dbtype.equals("MS-SQL")) {
							driverClass = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
							Class.forName(driverClass);
							String url = "jdbc:sqlserver://" + ip + ":" + port + ";DatabaseName=" + dbNm;
							conn = DriverManager.getConnection(url, id, passwd);
						}
						else if(dbtype.equals("DB2BLU")) {
							driverClass = "com.ibm.db2.jcc.DB2Driver";
							Class.forName(driverClass);
							String url = "jdbc:db2://" + ip + ":" + port + "/" + dbNm;
							conn = DriverManager.getConnection(url, id, passwd);
						}
						else if(dbtype.equals("ORACLE")) {
							driverClass = "oracle.jdbc.driver.OracleDriver";
							Class.forName(driverClass);
							String url = "jdbc:oracle:thin:@" + ip + ":" + port + ":" + dbNm;
							conn = DriverManager.getConnection(url, id, passwd);
						}
						else if(dbtype.equals("TIBERO")) {
							driverClass = "com.tmax.tibero.jdbc.TbDriver";
							Class.forName(driverClass);
							String url = "jdbc:tibero:thin:@" + ip + ":" + port + ":" + dbNm;
							conn = DriverManager.getConnection(url, id, passwd);
						}
						else if(dbtype.equals("ALTIBASE")) {
							driverClass = "Altibase.jdbc.driver.AltibaseDriver";
							Class.forName(driverClass);
							String url = "jdbc:Altibase://" + ip + ":" + port + "/" + dbNm;
							conn = DriverManager.getConnection(url, id, passwd);
						}
						else if(dbtype.equals("CUBRID")) {
							driverClass = "cubrid.jdbc.driver.CUBRIDDriver";
							Class.forName(driverClass);
							String url = "jdbc:cubrid:" + ip + ":" + port + ":" + dbNm + ":dba::";
							conn = DriverManager.getConnection(url, id, passwd);
						}
						else if(dbtype.equals("IMPALA")) {
							driverClass = "com.cloudera.impala.jdbc41.Driver";
							Class.forName(driverClass);
							String url = "jdbc:impala://" + ip + ":" + port + "/" + dbNm;
							conn = DriverManager.getConnection(url, id, passwd);
						}
						/* DOGFOOT ktkang ????????? ????????? ????????? NETEZZA ??????  20200910 */
						else if(dbtype.equals("NETEZZA")) {
							driverClass = "org.netezza.Driver";
							Class.forName(driverClass);
							String url = "jdbc:netezza://" + ip + ":" + port + "/" + dbNm;
							conn = DriverManager.getConnection(url, id, passwd);
						}
						StringBuilder query = new StringBuilder();
						query.append(" ");
						StringBuilder tblQuery = new StringBuilder();
						int iCnt = 0;
						int iSeq = 0;


						//Table ?????? ????????? ??????
						boolean iFirst = true;
						if (dbtype.equals("MS-SQL")) {
							query.append(" SELECT  CAST(A.NAME AS NVARCHAR(200)) AS TABLE_NAME 			 ")
							.append(" FROM	SYSOBJECTS A 											 ")
							.append(" WHERE	A.xtype IN ('U', 'V') AND A.NAME LIKE 'T_WISE_%'	 ")
							.append(" ORDER BY 1  													 ");
						}
						else if(dbtype.equals("DB2BLU"))
						{
							query.append(" SELECT TABLE_NAME 											 ")
							.append(" FROM SYSIBM.TABLES 											 ")
							.append(" WHERE TABLE_NAME LIKE 'T_WISE_%'								 ")
							.append(" ORDER BY 1 WITH UR							 				 ");
						}
						else if(dbtype.equals("ORACLE") || dbtype.equals("TIBERO"))
						{
							query.append(" SELECT  A.TABLE_NAME 										 ")
							.append(" FROM	ALL_TABLES A, ALL_TAB_COMMENTS B 						 ")
							.append(" WHERE	A.OWNER = B.OWNER									 ")
							.append(" AND     A.TABLE_NAME = B.TABLE_NAME							 ")
							.append(" AND     A.TABLE_NAME LIKE 'T_WISE_%'							 ")
							.append(" ORDER BY 1													 ");
						}
						else if(dbtype.equals("ALTIBASE"))
						{
							query.append(" SELECT TABLE_NAME 											 ")
							.append(" FROM SYSTEM_.SYS_TABLES_ 									 ")
							.append(" WHERE TABLE_NAME LIKE 'T_WISE_%'								 ")
							.append(" ORDER BY 1							 						 ");
						}
						else if(dbtype.equals("CUBRID"))
						{
							query.append(" SELECT class_name AS TABLE_NAME								 ")
							.append(" FROM db_class												 ")
							.append(" WHERE class_name LIKE 't_wise_%'								 ")
							.append(" ORDER BY 1							 						 ");
						}
						else if(dbtype.equals("IMPALA"))
						{
							query.append(" SHOW TABLES LIKE 't_wise_*'									 ");
						}
						/* DOGFOOT ktkang ????????? ????????? ????????? NETEZZA ??????  20200910 */
						else if(dbtype.equals("NETEZZA"))
						{
//							query.append(" SELECT TABLENAME AS TABLE_NAME					")
//							.append(" FROM _V_TABLE											")
//							.append(" WHERE TABLE_NAME LIKE 'T_WISE_%'						")
//							.append(" ORDER BY 1							 				");
							/*dogfoot NETEZZA DB ?????? ??? ?????? ???????????? shlim 20210427*/
							query.append(" SELECT 1 AS TABLE_NAME					");
						}
						pstmt = conn.prepareStatement(query.toString());
						rs = pstmt.executeQuery();
						if(targetTable != null) {
							if(targetTable.equals("")) {
								if (!rs.equals(null))
								{
									while(rs.next())
									{
										iCnt++;
									}

									tmpTblNm = "T_WISE_" + ds_id + "_" + iCnt;
								}
							}else {
								//tmpTblNm = targetTable;
								tmpTblNm = new String(Base64.decode(targetTable.getBytes()));
							}
						}else {
							if (!rs.equals(null))
							{
								while(rs.next())
								{
									iCnt++;
								}

								tmpTblNm = "T_WISE_" + ds_id + "_" + iCnt;
							}
						}

						//					System.out.println(tmpTblNm);
						//????????? ?????? ????????? ???
						ArrayList<String> header = new ArrayList<String>();
						if(appendTable.equals("")) {
							//????????? ?????? ??????
							if(jsonarr != null) {
								tblQuery.append(" CREATE TABLE "+tmpTblNm + "(" );
								for (int i =0 ; i < jsonarr.size();i++)
								{
									net.sf.json.JSONObject obj = jsonarr.getJSONObject(i);
									String colType = obj.get("colType")+"";
									if(dbtype.equals("TIBERO") && colType.toUpperCase().equals("INT")) {
										colType = "NUMBER";
									/* DOGFOOT ktkang ????????? ????????? ????????? NETEZZA ??????  20200910 */
									} else if(dbtype.equals("NETEZZA") && colType.toUpperCase().equals("INT")) {
										colType = "NUMERIC";
									} else if(dbtype.equals("NETEZZA") && colType.toUpperCase().equals("STRING")) {
										colType = "NVARCHAR";
									} else {
										colType = obj.getString("colType");
									}

									String colLength = obj.get("colSize")+"";
									if (iFirst)
									{
										if(dbtype.equals("IMPALA")) {
											tblQuery.append(" " + obj.getString("colPhysicalNm") + " " + getMatchedLength(colType, colLength) + " ");
										} else {
											/*dogfoot ?????????????????? ????????? ???????????? ???????????? table ?????? ?????? ?????? shlim 20210308*/
											if(checkOnlyNumInString(obj.getString("colPhysicalNm"))) {
												tblQuery.append(" " + "\"" +obj.getString("colPhysicalNm") +"\"" + " " + getMatchedLength(colType, colLength) + " NULL ");
											}else {
												tblQuery.append(" " + obj.getString("colPhysicalNm") + " " + getMatchedLength(colType, colLength) + " NULL ");
											}
											
										}
										iFirst = false;
									}else {
										if(dbtype.equals("IMPALA")) {
											tblQuery.append(" , " + obj.getString("colPhysicalNm") + " " + getMatchedLength(colType, colLength) + " ");
										} else {
											/*dogfoot ?????????????????? ????????? ???????????? ???????????? table ?????? ?????? ?????? shlim 20210308*/
											if(checkOnlyNumInString(obj.getString("colPhysicalNm"))) {
												tblQuery.append(" , " + "\"" +obj.getString("colPhysicalNm")+ "\"" + " " +getMatchedLength(colType, colLength) + " NULL ");
											}else {
												tblQuery.append(" , " + obj.getString("colPhysicalNm") + " " +getMatchedLength(colType, colLength) + " NULL ");
											}
											
										}
									}
									/*dogfoot ?????????????????? ????????? ???????????? ???????????? table ?????? ?????? ?????? shlim 20210308*/
									if(checkOnlyNumInString(obj.getString("colPhysicalNm"))) {
										header.add("\""+obj.get("colPhysicalNm")+"\"");
									}else {
										header.add(obj.get("colPhysicalNm")+"");
									}
									
									realpath = obj.getString("realpath");
									filename = obj.get("fileName")+"";
								}

								tblQuery.append(" )" );
								if(tblQuery != null) {
									pstmt = conn.prepareStatement(tblQuery.toString());
									pstmt.execute();
								}
							}
							//????????? ?????? ???
						}else {
							if(tableDeleteYN != null) {
								if(tableDeleteYN.equals("Y")) {
									String truncateQuery = "TRUNCATE TABLE "+tmpTblNm;
									if(dbtype.equals("DB2BLU")) truncateQuery = "DELETE FROM "+tmpTblNm;
									pstmt = conn.prepareStatement(truncateQuery.toString());
									pstmt.execute();
								}
							}
							if(jsonarr != null) {
								for (int i =0 ; i < jsonarr.size();i++) {
									net.sf.json.JSONObject obj = jsonarr.getJSONObject(i);
									header.add(obj.get("colPhysicalNm")+"");
									realpath = obj.getString("realpath");
									filename = obj.get("fileName")+"";
								}
							}
						}


						//?????? ?????? ?????????
						ArrayList<HashMap<String, String>> colInfo = new ArrayList<HashMap<String, String>>();
						if(jsonarr != null) {
							for(int i=0;i<jsonarr.size();i++) {
								net.sf.json.JSONObject colobj = jsonarr.getJSONObject(i);
								Iterator colInfokey = colobj.keys();
								HashMap<String, String> map = new HashMap<String,String>();
								if(colInfokey != null) {
									while(colInfokey.hasNext()) {
										String colKey = (String) colInfokey.next();
										if(colKey != null) {
											if(!colKey.equals("fileName") || !colKey.equals("realpath"))
												map.put(colKey, colobj.get(colKey)+"");
										}

									}
								}
								colInfo.add(map);
							}
						}
						//?????? ?????? ???


						QuertExcuter exec = new QuertExcuter();
						org.json.JSONObject reuslt = exec.executeCsvImport(filename,tmpTblNm,header,',',colInfo,conn,realpath,ckutf);
						//					System.out.println(reuslt);

						//USER_UPLOAD_MSTR ?????? ??????
						Json2Xml xmlConverter = new Json2Xml();
						String tableXmlString = xmlConverter.UploadTableInfo(filename,  filename.substring(filename.lastIndexOf(".") + 1), tableCaption, Owner, jsonarr);
						//					System.out.println(tableXmlString);
						if(tableXmlString != null) {
							UserUploadMstrVO uploadVo = new UserUploadMstrVO();
							uploadVo.setDATA_NM(tableCaption);
							uploadVo.setTBL_NM(tmpTblNm);
							uploadVo.setREG_USER_ID(userId);
							uploadVo.setDATA_DESC("");
							/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
							uploadVo.setUPLOAD_XML(new String(java.util.Base64.getEncoder().encode(tableXmlString.getBytes())));
							uploadVo.setDS_ID(ds_id);
							if(appendTable.equals("")) {
								this.reportService.insertUserUpload(uploadVo);
							}
						}

						//USER_UPLOAD_MSTR ?????? ??????

						//USER_UPLOAD_HIS_MSTR ?????? ??????
						UploadHisVO getseq = new UploadHisVO();
						getseq.setTBL_NM(tmpTblNm);
						UploadHisVO hisVo = this.reportService.selectHisUpload(getseq);
						hisVo.setDATA_NM(tableCaption);
						hisVo.setTBL_NM(tmpTblNm);
						hisVo.setREC_CNT(reuslt.get("REC_CNT")+"");
						hisVo.setMOD_USER_ID(userId);
						if(appendTable != null) {
							if(appendTable.equals(""))
								this.reportService.insertUserUploadHis(hisVo);
						}
						//USER_UPLOAD_HIS_MSTR ?????? ?????? ???

						ds.put("code", 200);
						ds.put("dataName", tableCaption);
						ds.put("TableName", tmpTblNm);
						ds.put("REC_count", reuslt.get("REC_CNT")+"");
					}
				}
			}
			out.print(ds);
			out.flush();
			out.close();
		}catch (Exception e) {
			e.printStackTrace();
			JSONObject ds = new JSONObject();
			ds.put("code", 500);
			out.print(ds);
			out.flush();
			out.close();
		}
		
	}
    public String getMatchedLength(String columnType,String length) {
		String value = "";
		if(columnType.equalsIgnoreCase("String")) {
			value = "VARCHAR("+length+")";
		}else if(columnType.equalsIgnoreCase("int")) {
			value = "INT";
		}else if(columnType.equalsIgnoreCase("NUMBER")) {
			value = "NUMBER";
		/* DOGFOOT ktkang ????????? ????????? ????????? NETEZZA ??????  20200910 */
		}else if(columnType.equalsIgnoreCase("NUMERIC")) {
			value = "NUMERIC";
		}else if(columnType.equalsIgnoreCase("NVARCHAR")) {
			value = "NVARCHAR("+length+")";
		}else if(columnType.equalsIgnoreCase("decimal")) {
			String val[] = length.split("[.]");
			value = "DECIMAL("+val[0]+","+val[1].length()+")";
		}else if(columnType.equalsIgnoreCase("float")) {
			value = "float("+length+")";
		}else {
			/*dogfoot ??????????????????????????? ????????? ?????? ???????????? ?????? ?????? shlim 20210120*/
			value = columnType;
		}
		return value;
	}
    @RequestMapping(value = {"/subjectListForOpen.do"}, method = RequestMethod.POST)
    public void subjectListForOpen(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
        Timer timer = new Timer();
//        String userId = SecureUtils.getParameter(request, "userId");
        String dsid = SecureUtils.getParameter(request, "dsid");
        String ds_type = SecureUtils.getParameter(request, "dataType");
        ArrayList<JSONObject> subjects = new ArrayList<JSONObject>();
        JSONObject subjectInfos = new JSONObject();
		
        SubjectMasterVO subjectMasterVO = new SubjectMasterVO();
        
        JSONObject ret = new JSONObject();
        
        if(dsid.indexOf(",")>-1) {
        	String[] dsidArr = dsid.split(",");
        	dsid = dsidArr[0];
        }
        
        timer.start();
    	subjectMasterVO = this.dataSetServiceImpl.selectSubjectList(Integer.parseInt(dsid), ds_type);
        int i = 0;
//            for (SubjectMasterVO subjectMasterVO : listSubject) {
			JSONObject subject = new JSONObject();
			JSONObject subjectInfo = new JSONObject();
			
			subjectInfo.put("????????? ?????? ???", subjectMasterVO.getDS_NM());
			subjectInfo.put("?????? ??????(???)", subjectMasterVO.getIP());
			subjectInfo.put("DB ???", subjectMasterVO.getDB_NM());
			subjectInfo.put("DB ??????", subjectMasterVO.getDBMS_TYPE());
			subjectInfo.put("Port", subjectMasterVO.getPORT());
			subjectInfo.put("?????????", subjectMasterVO.getOWNER_NM());
			subjectInfo.put("?????? ID", subjectMasterVO.getUSER_ID());
			subjectInfo.put("??????", subjectMasterVO.getDS_DESC());
			
			subject.put("DS_ID", subjectMasterVO.getDS_ID());
			subject.put("ID", i);
			subject.put("??????????????? ???", subjectMasterVO.getDS_NM());
			subject.put("DB ??????", subjectMasterVO.getDBMS_TYPE());
			subject.put("?????? ??????(???)", subjectMasterVO.getIP());
			subject.put("????????? ?????????", subjectMasterVO.getUSER_AREA_YN());
			
			subjects.add(subject);
			subjectInfos.put(i , subjectInfo);
//    			i++;
//    		}
        
        ret.put("subjects", subjects);
        ret.put("subjectInfos", subjectInfos);
        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("query elapse time: " + timer.getInterval());
        
        out.print(ret);
		out.flush();
		out.close();   
		return;
    }
    
    @RequestMapping(value = {"/getDataList.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject getDataList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        String dataSourceIdStr = SecureUtils.getParameter(request, "DS_ID");
        int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
        
        List result = null;
        JSONObject ret = new JSONObject();
        
        Timer timer = new Timer();
        
        timer.start();
        String dataSourceType = SecureUtils.getParameter(request, "DATASRC_TYPE");
        String columnName = SecureUtils.getParameter(request, "COLUMN_NM");
        String tableName = SecureUtils.getParameter(request, "TABLE_NM");
        
        String conditionType = SecureUtils.getParameter(request, "PARAM_TYPE");
        result = this.reportConditionService.selectDataList(dataSourceId, dataSourceType, columnName, tableName);
        
        ret.put("data", result);
        
        model.addAttribute("OUT_DATA", ret);

        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        int resultSize = result == null ? 0 : result.size();
        logger.debug("data size : " + resultSize);
        logger.debug("condition query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("condition query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("condition query elapse time: " + timer.getInterval());
        
        return ret;
    }
    
    // ymbin : load image
 	@RequestMapping(value = "/loadImage.do", method = RequestMethod.POST)
 	public void loadImage(HttpServletRequest request, HttpServletResponse response) throws Exception {
 		response.setCharacterEncoding("utf-8");
 		PrintWriter out = response.getWriter();
 		MultipartHttpServletRequest multipartHttpServletRequest = (MultipartHttpServletRequest)request;
 		Iterator<String> iterator = multipartHttpServletRequest.getFileNames(); 
 		MultipartFile uploadFile = null; 
       
 		uploadFile = multipartHttpServletRequest.getFile(iterator.next()); 
        
 		String filename = uploadFile.getOriginalFilename();
		if ( filename != null ) { 
		    if( filename.toLowerCase().endsWith(".jpeg") || filename.toLowerCase().endsWith(".jpg") || filename.toLowerCase().endsWith(".png") 
		    		|| filename.toLowerCase().endsWith(".gif") || filename.toLowerCase().endsWith(".rle") || filename.toLowerCase().endsWith(".dib") 
		    		|| filename.toLowerCase().endsWith(".bmp") || filename.toLowerCase().endsWith(".tiff") || filename.toLowerCase().endsWith(".tif")) { 
	   /* file ????????? ?????? */ 
		    } else 
		    	throw new ServletException("?????? ????????? ??????"); 
	    }
		
		//20210715 AJKIM ????????? ?????? ????????? ???????????? ????????? ???????????? ?????? ?????? dogfoot
		String fileFormat = filename.substring(filename.lastIndexOf('.'));
		SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmssSSS");
		
		filename = format.format(new Date()) + fileFormat;
		
		if(uploadFile.getSize() > 1024 * 1024 * 20) throw new ServletException("??????"); 
 		
 		File folder = WebFileUtils.getWebFolder(multipartHttpServletRequest, true, "UploadFiles", "ReportFile");
 		File file = new File(folder, filename);
        logger.debug("uploadPath : {}", file);
 		uploadFile.transferTo(file);
 		/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
 		out.print(new String(java.util.Base64.getEncoder().encode(file.getPath().getBytes())));
 		out.flush();
 		out.close();
 		logger.debug("-------------- file end --------------\n"); 
       
 	}
 	@RequestMapping(value = "/testData.do", method = RequestMethod.POST)
 	public void testData(HttpServletRequest request, HttpServletResponse response) throws Exception {
 		response.setCharacterEncoding("utf-8");
 		PrintWriter out = response.getWriter();
 		
 		String InfoString = SecureUtils.unsecure(SecureUtils.getParameter(request, "Infos"));
 		
 		String execType = SecureUtils.getParameter(request,"execType");
 		
 		String statics = SecureUtils.getParameter(request,"statics");
 		
 		logger.debug(InfoString);
 		if(InfoString != null) {
 			JSONObject InfoJson = JSONObject.fromObject(InfoString);
 	 		if(InfoJson != null) {
// 	 	 		JSONArray selArray = InfoJson.getJSONArray("selArray");
// 	 	 		JSONArray whereArray = InfoJson.getJSONArray("whereArray");
// 	 	 		JSONArray relArray = InfoJson.getJSONArray("relArray");
// 	 	 		JSONArray etcArray = InfoJson.getJSONArray("etcArray");
 	 			JSONArray selArray = new JSONArray();
 	 	 		JSONArray whereArray = new JSONArray();
 	 	 		JSONArray relArray = new JSONArray();
 	 	 		JSONArray etcArray = new JSONArray();
 	 	 		selArray = InfoJson.getJSONArray("selArray");
 	 	 		whereArray = InfoJson.getJSONArray("whereArray");
 	 	 		relArray = InfoJson.getJSONArray("relArray");
 	 	 		etcArray = InfoJson.getJSONArray("etcArray");
 	 	 		
 	 	 		ConfigMasterVO configVo = authenticationService.getConfigMstr();
 	 	 		String allowNonTBLYN = configVo.getALLOW_NON_TBL_REL();
 	 	 		
 	 	 		if(execType.equals("DS")) {
 	 	 			QuerySettingEx sqlQenQuery = new QuerySettingEx();
 	 	 	        ArrayList<SelectCube> aDtSel = new ArrayList<SelectCube>();
 	 	 	        ArrayList<Hierarchy> aDtSelHIe = new ArrayList<Hierarchy>();
 	 	 	        ArrayList<SelectCubeMeasure> aDtSelMea = new ArrayList<SelectCubeMeasure>();
 	 	 	        ArrayList<Relation> aDtCubeRel = new ArrayList<Relation>();
 	 	 	        ArrayList<Relation> aDtDsViewRel = new ArrayList<Relation>();
 	 	 	        ArrayList<SelectCubeWhere> aDtWhere = new ArrayList<SelectCubeWhere>();
 	 	 	        ArrayList<SelectCubeEtc> aDtEtc =new ArrayList<SelectCubeEtc>();
 	 	 	        
 	 	 	        for(int idx= 0;idx<selArray.size();idx++) {
 	 	 	        	JSONObject selJson = selArray.getJSONObject(idx); 
 	 	 	        	if(selJson != null) {
 	 	 	        		if(selJson.getString("TYPE").equals("DIM")) {
 	 	 	 	        		SelectCube selCube = new SelectCube();
 	 	 	 	 	 			selCube.setUNI_NM(selJson.get("TBL_NM")+"."+selJson.get("COL_NM")); //TBL_NM+COL_NM
 	 	 	 	 	 			selCube.setCAPTION(selJson.get("COL_CAPTION")+""); //COL_CAPTION
 	 	 	 	 	 			selCube.setDATA_TYPE(selJson.get("DATA_TYPE")+""); // DATA_TYPE
 	 	 	 	 	 			selCube.setORDER(Integer.toString(idx)); // for????????? ??????
 	 	 	 	 	 			selCube.setTYPE("DIM"); //TYPE
 	 	 	 	 	 			aDtSel.add(selCube);
 	 	 	 	 	 			
 	 	 	 	 	 			Hierarchy selHie = new Hierarchy();
 	 	 	 	 	 			
 	 	 	 	 	 			selHie.setDIM_UNI_NM(selJson.getString("TBL_NM")); // TBL_NM
 	 	 	 	 	 			selHie.setHIE_UNI_NM(selJson.get("TBL_NM")+"."+selJson.get("COL_NM")); // TBL_NM+COL_NM
 	 	 	 	 	 			selHie.setHIE_CAPTION(selJson.get("COL_CAPTION")+""); // COL_CAPTION
 	 	 	 	 	 			selHie.setTBL_NM(selJson.get("TBL_NM")+""); // TBL_NM
 	 	 	 	 	 			selHie.setCOL_NM(selJson.getString("COL_NM")); // COL_NM
 	 	 	 	 	 			selHie.setCOL_EXPRESS("");
 	 	 	 	 	 			aDtSelHIe.add(selHie);
 	 	 	 	        	}else {
 	 	 	 	        		SelectCube selCubemea = new SelectCube();
 	 	 	 	        		if(selJson != null) {
 	 	 	 	        			selCubemea.setUNI_NM(selJson.get("TBL_NM")+"."+selJson.get("COL_NM")); //TBL_NM+COL_NM
 	 	 	 	 	    			selCubemea.setCAPTION(selJson.get("COL_CAPTION")+""); //COL_CAPTION
 	 	 	 	 	    			selCubemea.setDATA_TYPE(selJson.get("DATA_TYPE")+"");// DATA_TYPE
 	 	 	 	 	    			selCubemea.setORDER(Integer.toString(idx));// for????????? ??????
 	 	 	 	 	    			selCubemea.setTYPE("MEA");//TYPE
 	 	 	 	 	    			aDtSel.add(selCubemea);
 	 	 	 	 	    			
 	 	 	 	 	    			SelectCubeMeasure selMea = new SelectCubeMeasure();
 	 	 	 	 	    			
 	 	 	 	 	    			selMea.setMEA_GRP_UNI_NM(selJson.get("TBL_NM")+""); //TBL_NM
 	 	 	 	 	    			selMea.setMEA_UNI_NM(selJson.getString("TBL_NM")+"."+selJson.getString("COL_NM")); //TBL_NM+COL_NM
 	 	 	 	 	    			selMea.setMEA_CAPTION(selJson.get("COL_CAPTION")+""); //COL_CAPTION
 	 	 	 	 	    			selMea.setMEA_TBL_NM(selJson.getString("TBL_NM")); //TBL_NM
 	 	 	 	 	    			selMea.setMEA_COL_NM(selJson.get("COL_NM")+"");// COL_NM
 	 	 	 	 	    			selMea.setMEA_AGG(selJson.getString("AGG")); // AGG
 	 	 	 	 	    			selMea.setCOL_EXPRESS("");
 	 	 	 	 	    			aDtSelMea.add(selMea);
 	 	 	 	        		}
 	 	 	 	        	}
 	 	 	        	}
 	 	 	        }
 	 	 	        if(whereArray != null) {
 	 	 	        	for(int idx=0;idx<whereArray.size();idx++) {
 	 	 	 	        	JSONObject whereJson = whereArray.getJSONObject(idx);
 	 	 	 	        	if(whereJson != null) {
 	 	 	 	        		SelectCubeWhere whereCube = new SelectCubeWhere();
 	 	 	 	 	        	whereCube.setPARENT_UNI_NM("["+whereJson.get("DATASRC")+"]");
 	 	 	 	        		whereCube.setUNI_NM(whereJson.get("UNI_NM")+"");
 	 	 	 	        		whereCube.setCAPTION(whereJson.getString("PARAM_CAPTION"));
 	 	 	 	        		whereCube.setOPER(whereJson.get("OPER")+"");
 	 	 	 	        		whereCube.setVALUES(whereJson.getString("DEFAULT_VALUE"));
 	 	 	 	        		whereCube.setVALUES_CAPTION(whereJson.getString("DEFAULT_VALUE").equals("[All]") ? "??????":whereJson.getString("DEFAULT_VALUE"));
 	 	 	 	        		whereCube.setAGG(whereJson.getString("AGG"));
 	 	 	 	        		whereCube.setDATA_TYPE(whereJson.get("DATA_TYPE")+"");
 	 	 	 	        		whereCube.setPARAM_YN(whereJson.get("PARAM_YN")+"");
 	 	 	 	        		whereCube.setPARAM_NM(whereJson.get("PARAM_NM")+"");
 	 	 	 	        		whereCube.setTYPE("DIM");
 	 	 	 	        		whereCube.setORDER(whereJson.get("ORDER")+"");
 	 	 	 	        		whereCube.setTBL_NM(whereJson.getString("DATASRC"));
 	 	 	 	        		whereCube.setCOL_NM(whereJson.get("KEY_VALUE_ITEM")+"");
 	 	 	 	        		whereCube.setLOGIC("");
 	 	 	 	        		whereCube.setCOL_EXPRESS("");
 	 	 	 	        		whereCube.setWHERE_CLAUSE(whereJson.getString("WHERE_CLAUSE"));
 	 	 	 	        		whereCube.setCOND_ID(whereJson.get("COND_ID")+"");
 	 	 	 	        		aDtWhere.add(whereCube);
 	 	 	 	        	}
 	 	 	 	        }
 	 	 	        }
 	 	 	       
 	 	 	        for(int idx=0;idx<relArray.size();idx++) {
 	 	 	        	JSONObject relJson = relArray.getJSONObject(idx);
 	 	 	        	
 	 	 	        	Relation cuberel = new Relation();
 	 	 	        	if(relJson != null) {
 	 	 	        		cuberel.setCONST_NM(relJson.getString("CONST_NM")); //CONST_NM
 	 	 	 	 			cuberel.setFK_TBL_NM(relJson.get("FK_TBL_NM")+""); // FK_TBL_NM
 	 	 	 	 			cuberel.setFK_COL_NM(relJson.getString("FK_COL_NM")); // FK_COL_NM
 	 	 	 	 			cuberel.setPK_TBL_NM(relJson.get("PK_TBL_NM")+""); // PK_TBL_NM
 	 	 	 	 			cuberel.setPK_COL_NM(relJson.getString("PK_COL_NM")); // PK_COL_NM
 	 	 	 	 			cuberel.setJOIN_TYPE(relJson.get("JOIN_TYPE")+""); // JOIN_TYPE
 	 	 	 	 			cuberel.setJOIN_SET_OWNER(relJson.getString("JOIN_SET_OWNER")); // JOIN_SET_OWNER
 	 	 	 	 			cuberel.setREL_CONST_NM(relJson.get("CONST_NM")+""); // CONST_NM
 	 	 	 	 			cuberel.setDIM_UNI_NM(relJson.getString("PK_TBL_NM")); // PK_TBL_NM
 	 	 	 	 			cuberel.setMEA_GRP_UNI_NM(relJson.getString("FK_TBL_NM")); // FK_TBL_NM
 	 	 	 	 			cuberel.setMODIFY_TAG("");
 	 	 	 	 			
 	 	 	 	 			aDtCubeRel.add(cuberel);
 	 	 	        	}
 	 	 	        }
 	 	 	       for(int idx=0;idx<etcArray.size();idx++) {
 	 		        	JSONObject etcJson = etcArray.getJSONObject(idx);
 	 		        	
 	 		        	SelectCubeEtc etc = new SelectCubeEtc();
// 	 	 		        	etc.setSTRATIFIED("");
 	 		        	etc.setDISTINCT("N");
 	 		        	etc.setCHANGE_COND(etcJson.get("CHANGE_COND")+"");
 	 		        	etc.setSEL_COND("");//empty
 	 		        	etc.setSEL_NUMBERIC("0");//0
 	 		 			
 	 		 			aDtEtc.add(etc);
 	 		        }
 	 	 	        //2020.12.07 MKSONG MARIADB ??????  DOGFOOT
// 	 	 	       	String sql2 = sqlQenQuery.CubeQuerySetting(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, new ArrayList<SelectCubeOrder> (), "MARIA", aDtCubeRel, aDtDsViewRel, aDtEtc ,allowNonTBLYN);
 	 	 			String sql2 = sqlQenQuery.CubeQuerySetting(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, new ArrayList<SelectCubeOrder> (), "DB2", aDtCubeRel, aDtDsViewRel, aDtEtc ,allowNonTBLYN);
 	 	 			if(statics.equals("true")) {
 	 	 				sql2 = sql2.replaceFirst("DISTINCT", "");
 	 	 			}
 	 	 			logger.debug(sql2);
 	 	 			out.print(sql2);
 	 	 	 		out.flush();
 	 	 	 		out.close();
 	 	 		}else if(execType.equals("singleDS")) {
 	 	 			String tableName = "";
 	 	 			QuerySettingEx sqlQenQuery = new QuerySettingEx();
 	 	 	        ArrayList<SelectCube> aDtSel = new ArrayList<SelectCube>();
 	 	 	        ArrayList<Hierarchy> aDtSelHIe = new ArrayList<Hierarchy>();
 	 	 	        ArrayList<SelectCubeMeasure> aDtSelMea = new ArrayList<SelectCubeMeasure>();

 	 	 	     /* DOGFOOT ktkang ??????????????? MSSQL ??? ??? ????????? ?????? ???????????? ??????  20201118 */
 	 	 	        DataSetMasterVO dataSetMaster = null;
 	 	 	        if (DataSetConst.DataSetType.DS.equals("DS") || DataSetConst.DataSetType.DS_SQL.equals("DS_SQL")) {
 	 	 	        	dataSetMaster = this.dataSetDAO.selectDataSetMaster(Integer.parseInt(InfoJson.getString("dsId")));
 	 	 	        }
 	 	 	        
 	 	 	        boolean hasSummary = false;
 	 	 	        if(selArray != null) {
 	 	 	        	for(int idx= 0;idx<selArray.size();idx++) {
 	 	 	 	        	JSONObject selJson = selArray.getJSONObject(idx);
 	 	 	 	        	String selJsonAgg = "";
 	 	 	 	        	selJsonAgg = selJson.get("AGG") + "";
 	 	 	 	        	if(!selJsonAgg.equals("")) {
 	 	 	 	        		hasSummary = true;
 	 	 	 	        		break;
 	 	 	 	        	}
 	 	 	 	        }
 	 	 	        	if(hasSummary == true) {
 	 	 	 	        	for(int idx= 0;idx<selArray.size();idx++) {
 	 	 	 	 	        	JSONObject selJson = selArray.getJSONObject(idx); 
 	 	 	 	 	        	if(selJson != null) {
 	 	 	 	 	        		if((selJson.get("AGG")+"").equals("")) {
 	 	 	 	 	 	        		SelectCube selCube = new SelectCube();
 	 	 	 	 	 	 	 			selCube.setUNI_NM(selJson.get("TBL_NM")+"."+selJson.get("COL_NM")); //TBL_NM+COL_NM
 	 	 	 	 	 	 	 			selCube.setCAPTION(selJson.get("COL_CAPTION")+""); //COL_CAPTION
 	 	 	 	 	 	 	 			selCube.setDATA_TYPE(selJson.get("DATA_TYPE")+""); // DATA_TYPE
 	 	 	 	 	 	 	 			selCube.setORDER(Integer.toString(idx)); // for????????? ??????
 	 	 	 	 	 	 	 			selCube.setTYPE("DIM"); //TYPE
 	 	 	 	 	 	 	 			aDtSel.add(selCube);
 	 	 	 	 	 	 	 			
 	 	 	 	 	 	 	 			Hierarchy selHie = new Hierarchy();
 	 	 	 	 	 	 	 			
 	 	 	 	 	 	 	 			selHie.setDIM_UNI_NM(selJson.get("TBL_NM")+""); // TBL_NM
 	 	 	 	 	 	 	 			selHie.setHIE_UNI_NM(selJson.get("TBL_NM")+"."+selJson.get("COL_NM")); // TBL_NM+COL_NM
 	 	 	 	 	 	 	 			selHie.setHIE_CAPTION(selJson.get("COL_CAPTION")+""); // COL_CAPTION
 	 	 	 	 	 	 	 			selHie.setTBL_NM(selJson.get("TBL_NM")+""); // TBL_NM
 	 	 	 	 	 	 	 			selHie.setCOL_NM(selJson.getString("COL_NM")); // COL_NM
 	 	 	 	 	 	 	 			selHie.setCOL_EXPRESS("");
 	 	 	 	 	 	 	 			aDtSelHIe.add(selHie);
 	 	 	 	 	 	 	 			
 	 	 	 	 	 	 	 			tableName = selJson.get("TBL_NM")+"";
 	 	 	 	 	 	        	}else {
 	 	 	 	 	 	        		SelectCube selCubemea = new SelectCube();
 	 	 	 	 	 	    			selCubemea.setUNI_NM(selJson.get("TBL_NM")+"."+selJson.get("COL_NM")); //TBL_NM+COL_NM
 	 	 	 	 	 	    			selCubemea.setCAPTION(selJson.get("COL_CAPTION")+""); //COL_CAPTION
 	 	 	 	 	 	    			selCubemea.setDATA_TYPE(selJson.get("DATA_TYPE")+"");// DATA_TYPE
 	 	 	 	 	 	    			selCubemea.setORDER(Integer.toString(idx));// for????????? ??????
 	 	 	 	 	 	    			selCubemea.setTYPE("MEA");//TYPE
 	 	 	 	 	 	    			aDtSel.add(selCubemea);
 	 	 	 	 	 	    			
 	 	 	 	 	 	    			SelectCubeMeasure selMea = new SelectCubeMeasure();
 	 	 	 	 	 	    			
 	 	 	 	 	 	    			selMea.setMEA_GRP_UNI_NM(selJson.get("TBL_NM")+""); //TBL_NM
 	 	 	 	 	 	    			selMea.setMEA_UNI_NM(selJson.getString("TBL_NM")+"."+selJson.getString("COL_NM")); //TBL_NM+COL_NM
 	 	 	 	 	 	    			selMea.setMEA_CAPTION(selJson.get("COL_CAPTION")+""); //COL_CAPTION
 	 	 	 	 	 	    			selMea.setMEA_TBL_NM(selJson.getString("TBL_NM")); //TBL_NM
 	 	 	 	 	 	    			selMea.setMEA_COL_NM(selJson.get("COL_NM")+"");// COL_NM
 	 	 	 	 	 	    			selMea.setMEA_AGG(selJson.getString("AGG")); // AGG
 	 	 	 	 	 	    			selMea.setCOL_EXPRESS("");
 	 	 	 	 	 	    			aDtSelMea.add(selMea);
 	 	 	 	 	 	        	}
 	 	 	 	 	        	}
 	 	 	 	 	        }
 	 	 	 	        }else {
 	 	 	 	        	if(selArray != null) {
 	 	 	 	        		for(int idx= 0;idx<selArray.size();idx++) {
 	 	 	 	 	 	        	JSONObject selJson = selArray.getJSONObject(idx); 
 	 	 	 	 	        		SelectCube selCubemea = new SelectCube();
 	 	 	 	 	        		if(selJson != null) {
 	 	 	 	 	        			selCubemea.setUNI_NM(selJson.get("TBL_NM")+"."+selJson.get("COL_NM")); //TBL_NM+COL_NM
 	 	 	 	 	 	    			selCubemea.setCAPTION(selJson.get("COL_CAPTION")+""); //COL_CAPTION
 	 	 	 	 	 	    			selCubemea.setDATA_TYPE(selJson.get("DATA_TYPE")+"");// DATA_TYPE
 	 	 	 	 	 	    			selCubemea.setORDER(Integer.toString(idx));// for????????? ??????
 	 	 	 	 	 	    			selCubemea.setTYPE("MEA");//TYPE
 	 	 	 	 	 	    			aDtSel.add(selCubemea);
 	 	 	 	 	 	    			
 	 	 	 	 	 	    			SelectCubeMeasure selMea = new SelectCubeMeasure();
 	 	 	 	 	 	    			
 	 	 	 	 	 	    			selMea.setMEA_GRP_UNI_NM(selJson.get("TBL_NM")+""); //TBL_NM
 	 	 	 	 	 	    			selMea.setMEA_UNI_NM(selJson.getString("TBL_NM")+"."+selJson.getString("COL_NM")); //TBL_NM+COL_NM
 	 	 	 	 	 	    			selMea.setMEA_CAPTION(selJson.get("COL_CAPTION")+""); //COL_CAPTION
 	 	 	 	 	 	    			selMea.setMEA_TBL_NM(selJson.getString("TBL_NM")); //TBL_NM
 	 	 	 	 	 	    			selMea.setMEA_COL_NM(selJson.get("COL_NM")+"");// COL_NM
 	 	 	 	 	 	    			selMea.setMEA_AGG(selJson.getString("AGG")); // AGG
 	 	 	 	 	 	    			selMea.setCOL_EXPRESS("");
 	 	 	 	 	 	    			aDtSelMea.add(selMea);
 	 	 	 	 	 	    			
 	 	 	 	 	 	    			tableName = selJson.get("TBL_NM")+"";
 	 	 	 	 	        		}
 	 	 	 	 	        	}
 	 	 	 	        	}
 	 	 	 	        }
 	 	 	        }
 	 	 	        
 	 	 	        //2020.12.07 MKSONG MARIADB ??????  DOGFOOT
// 	 	 	        String sql = sqlQenQuery.CubeQuerySettingSingleDS(aDtSel, aDtSelHIe, aDtSelMea, new ArrayList<SelectCubeWhere> (), new ArrayList<SelectCubeOrder> (), "MARIA", new ArrayList<Relation>(),  new ArrayList<Relation>(), new ArrayList<SelectCubeEtc>());
 	 	 	        String sql = sqlQenQuery.CubeQuerySettingSingleDS(aDtSel, aDtSelHIe, aDtSelMea, new ArrayList<SelectCubeWhere> (), new ArrayList<SelectCubeOrder> (), "DB2", new ArrayList<Relation>(),  new ArrayList<Relation>(), new ArrayList<SelectCubeEtc>());
 	 	 	        if(statics.equals("true")) {
 	 	 	        	sql = sql.replaceFirst("DISTINCT", "");
	 	 			}
 	 	 	        /* DOGFOOT ktkang ??????????????? MSSQL ??? ??? ????????? ?????? ???????????? ??????  20201118 */
 	 	 	        if(dataSetMaster.getDatabaseType().equals("MS-SQL")) {
 	 	 	        	sql = sql.replaceAll(tableName, dataSetMaster.getDatabaseOwner() + "." + tableName);
 	 	 	        }
 	 	 	        	
 	 	 	        logger.debug(sql);
 	 	 	        out.print(sql);
 	 	 	 		out.flush();
 	 	 	 		out.close();
 	 			} else if (execType.equals("CUBE")) {
 	 				QuerySettingEx sqlQenQuery = new QuerySettingEx();
 	 				ArrayList<SelectCube> aDtSel = new ArrayList<SelectCube>();
 	 				ArrayList<Hierarchy> aDtSelHIe = new ArrayList<Hierarchy>();
 	 				ArrayList<SelectCubeMeasure> aDtSelMea = new ArrayList<SelectCubeMeasure>();
 	 				ArrayList<SelectCubeWhere> aDtWhere = new ArrayList<SelectCubeWhere>();
 	 				ArrayList<SelectCubeOrder> aDtOrder = new ArrayList<SelectCubeOrder>();
 	 				
 	 				JSONArray OrderArray = InfoJson.getJSONArray("orderArray");
 	 				Map<String,List<CubeTableVO>> cubeTableInfo = this.dataSetServiceImpl.selectCubeReportTableInfoList(Integer.parseInt(InfoJson.getString("dsId")),InfoJson.getString("userId"));
 	 				
 	 				List<CubeTableVO> dimCubeTable = cubeTableInfo.get("dimensions");
 	 				List<CubeTableVO> meaCubeTable = cubeTableInfo.get("measures");

 					for (int idx = 0; idx < selArray.size(); idx++) {
 	 					JSONObject selJson = selArray.getJSONObject(idx);
 	 					if(selJson.getString("TYPE").equals("DIM")) {
 	 						for(CubeTableVO dimVo : dimCubeTable) {
 	 							List<CubeTableColumnVO> dimColumns = dimVo.getColumns();
 	 							for(CubeTableColumnVO dimColVo : dimColumns) {
 	 								if(dimColVo.getUniqueName().equals(selJson.getString("UNI_NM"))) {
 	 									SelectCube selCube = new SelectCube();
 	 	 								selCube.setUNI_NM(selJson.getString("UNI_NM"));
 	 	 								selCube.setCAPTION(selJson.getString("CAPTION"));
 	 	 								selCube.setDATA_TYPE(selJson.get("DATA_TYPE")+"");
 	 	 								selCube.setORDER(Integer.toString(idx));
 	 	 								selCube.setTYPE("DIM"); // TYPE
 	 	 	 	 						aDtSel.add(selCube);
		 	 	 	 					
 	 	 	 	 						Hierarchy selHie = new Hierarchy();
 	 	 	 	 						selHie.setDIM_UNI_NM(dimColVo.getTableName());
 	 	 	 	 						selHie.setHIE_UNI_NM(dimColVo.getUniqueName());
	 	 	 	 	 					selHie.setHIE_CAPTION(dimColVo.getCaptionName()); // COL_CAPTION
	 	 	 	 						selHie.setTBL_NM(dimColVo.getPhysicalTableName()); // TBL_NM
	 	 	 	 						selHie.setCOL_NM(dimColVo.getPhysicalColumnName()); // COL_NM
	 	 	 	 						selHie.setCOL_EXPRESS(dimColVo.getExpression());
	 	 	 	 						aDtSelHIe.add(selHie);
 	 	 	 	 						break;
 	 								}
 	 							}
 	 						}
 	 					}else {
 	 						for(CubeTableVO meaVo : meaCubeTable) {
 	 							List<CubeTableColumnVO> meaColumns = meaVo.getColumns();
 	 							for(CubeTableColumnVO meaColVo : meaColumns) {
 	 								if(meaColVo.getUniqueName().equals(selJson.getString("UNI_NM"))) {
 	 									SelectCube selCubemea = new SelectCube();
 	 		 	 						selCubemea.setUNI_NM(selJson.getString("UNI_NM"));
 	 		 	 						selCubemea.setCAPTION(selJson.getString("CAPTION")); // COL_CAPTION
 	 		 	 						selCubemea.setDATA_TYPE(selJson.getString("DATA_TYPE"));// DATA_TYPE
 	 		 	 						selCubemea.setORDER(Integer.toString(idx));// for????????? ??????
 	 		 	 						selCubemea.setTYPE("MEA");// TYPE
 	 		 	 						aDtSel.add(selCubemea);
 	 		 	 						
	 	 		 	 					SelectCubeMeasure selMea = new SelectCubeMeasure();
	 	 	 	 						selMea.setMEA_GRP_UNI_NM(meaColVo.getTableName());
	 	 	 	 						selMea.setMEA_UNI_NM(meaColVo.getUniqueName()); // TBL_NM+COL_NM
	 	 	 	 						selMea.setMEA_CAPTION(meaColVo.getCaptionName()); // COL_CAPTION
	 	 	 	 						selMea.setMEA_TBL_NM(meaColVo.getLogicalTableName()); // TBL_NM
	 	 	 	 						selMea.setMEA_COL_NM(meaColVo.getLogicalColumnName());// COL_NM
	 	 	 	 						selMea.setMEA_AGG(meaColVo.getSummaryType()); // AGG
	 	 	 	 						selMea.setCOL_EXPRESS(meaColVo.getExpression());
	 	 	 	 						if (!meaColVo.getExpression().equals("") && meaColVo.getSummaryType().equals("")) {
	 	 	 	 							Hierarchy selHie = new Hierarchy();
	 	 	 	 							selHie.setDIM_UNI_NM(meaColVo.getTableName()); // TBL_NM
	 	 	 	 							selHie.setHIE_UNI_NM(meaColVo.getUniqueName()); // TBL_NM+COL_NM
	 	 	 	 							selHie.setHIE_CAPTION(meaColVo.getCaptionName()); // COL_CAPTION
	 	 	 	 							selHie.setTBL_NM(meaColVo.getLogicalTableName()); // TBL_NM
	 	 	 	 							selHie.setCOL_NM(meaColVo.getLogicalColumnName()); // COL_NM
	 	 	 	 							selHie.setCOL_EXPRESS(meaColVo.getExpression());
	 	 	 	 							aDtSelHIe.add(selHie);
	 	 	 	 						}
	 	 	 	 						aDtSelMea.add(selMea);
	 	 	 	 						break;
 	 								}
 	 							}
 	 							
 	 						}
 	 						
 	 					}
 	 					
// 	 	 					if (selJson.getString("TYPE").equals("DIM")) {
// 	 	 						SelectCube selCube = new SelectCube();
//// 	 	 	 	 	 			selCube.setUNI_NM(selJson.getString("TBL_NM")+"."+selJson.getString("COL_NM")); //TBL_NM+COL_NM
// 	 	 						selCube.setUNI_NM(selJson.getString("UNI_NM"));
// 	 	 						selCube.setCAPTION(selJson.getString("CAPTION")); // COL_CAPTION
// 	 	 						selCube.setDATA_TYPE(selJson.get("DATA_TYPE")+""); // DATA_TYPE
// 	 	 						selCube.setORDER(Integer.toString(idx)); // for????????? ??????
// 	 	 						selCube.setTYPE("DIM"); // TYPE
// 	 	 						aDtSel.add(selCube);
// 	 	 						logger.debug(selCube.toString());
// 	 	 						Hierarchy selHie = new Hierarchy();
//// 	 	 						String tableName = "";
//// 	 	 						if(!selJson.has("tableName")) {
//// 	 	 							tableName = "["+selJson.get("TBL_NM")+"]";
//// 	 	 						}else {
//// 	 	 							tableName = selJson.getString("tableName");
//// 	 	 						}
//// 	 	 	 	 	 			selHie.setDIM_UNI_NM(selJson.getString("TBL_NM")); // TBL_NM
//// 	 	 	 	 	 			selHie.setDIM_UNI_NM("["+selJson.getString("TBL_NM")+"]"); //TBL_NM
// 	 	 						selHie.setDIM_UNI_NM(selJson.getString("tableName"));
//// 	 	 	 	 	 			selHie.setHIE_UNI_NM(selJson.getString("TBL_NM")+"."+selJson.getString("COL_NM")); // TBL_NM+COL_NM
// 	 	 						selHie.setHIE_UNI_NM(selJson.getString("UNI_NM")); // TBL_NM+COL_NM
// 	 	 						selHie.setHIE_CAPTION(selJson.get("CAPTION")+""); // COL_CAPTION
// 	 	 						selHie.setTBL_NM(selJson.get("physicalTableName")+""); // TBL_NM
// 	 	 						selHie.setCOL_NM(selJson.getString("COL_NM")); // COL_NM
// 	 	 						selHie.setCOL_EXPRESS(selJson.getString("COL_EXPRESS"));
// 	 	 						aDtSelHIe.add(selHie);
// 	 	 						logger.debug(selHie.toString());
// 	 	 					} else {
// 	 	 						SelectCube selCubemea = new SelectCube();
//// 	 	 	 	    			selCubemea.setUNI_NM(selJson.getString("TBL_NM")+"."+selJson.getString("COL_NM")); //TBL_NM+COL_NM
// 	 	 						selCubemea.setUNI_NM(selJson.getString("UNI_NM"));
// 	 	 						selCubemea.setCAPTION(selJson.getString("CAPTION")); // COL_CAPTION
// 	 	 						selCubemea.setDATA_TYPE(selJson.getString("DATA_TYPE"));// DATA_TYPE
// 	 	 						selCubemea.setORDER(Integer.toString(idx));// for????????? ??????
// 	 	 						selCubemea.setTYPE("MEA");// TYPE
// 	 	 						aDtSel.add(selCubemea);
// 	 	 						logger.debug(selCubemea.toString());
// 	 	 						SelectCubeMeasure selMea = new SelectCubeMeasure();
// 	 	 						String tableName = "";
// 	 	 						if(!selJson.has("tableName")) {
// 	 	 							tableName = "["+selJson.get("TBL_NM")+"]";
// 	 	 						}else {
// 	 	 							tableName = selJson.getString("tableName");
// 	 	 						}
//// 	 	 	 	    			selMea.setMEA_GRP_UNI_NM(selJson.getString("TBL_NM")); //TBL_NM
//// 	 	 	 	    			selMea.setMEA_GRP_UNI_NM("["+selJson.getString("TBL_NM")+"]"); //TBL_NM
// 	 	 						selMea.setMEA_GRP_UNI_NM(tableName);
//// 	 	 	 	    			selMea.setMEA_UNI_NM(selJson.getString("TBL_NM")+"."+selJson.getString("COL_NM")); //TBL_NM+COL_NM
// 	 	 						selMea.setMEA_UNI_NM(selJson.getString("UNI_NM")); // TBL_NM+COL_NM
// 	 	 						selMea.setMEA_CAPTION(selJson.getString("CAPTION")); // COL_CAPTION
// 	 	 						selMea.setMEA_TBL_NM(selJson.getString("TBL_NM")); // TBL_NM
// 	 	 						selMea.setMEA_COL_NM(selJson.get("COL_NM")+"");// COL_NM
// 	 	 						selMea.setMEA_AGG(selJson.getString("AGG")); // AGG
// 	 	 						selMea.setCOL_EXPRESS(selJson.getString("COL_EXPRESS"));
// 	 	 						if (!selMea.getCOL_EXPRESS().equals("") && selMea.getMEA_AGG().equals("")) {
// 	 	 							Hierarchy selHie = new Hierarchy();
//// 	 	 	 	 	 	 			selHie.setDIM_UNI_NM(selJson.getString("TBL_NM")); // TBL_NM
// 	 	 							selHie.setDIM_UNI_NM("[" + selJson.getString("TBL_NM") + "]"); // TBL_NM
//// 	 	 	 	 	 	 			selHie.setHIE_UNI_NM(selJson.getString("TBL_NM")+"."+selJson.getString("COL_NM")); // TBL_NM+COL_NM
// 	 	 							selHie.setHIE_UNI_NM(selJson.getString("UNI_NM")); // TBL_NM+COL_NM
// 	 	 							selHie.setHIE_CAPTION(selJson.get("COL_CAPTION")+""); // COL_CAPTION
// 	 	 							selHie.setTBL_NM(selJson.get("TBL_NM")+""); // TBL_NM
// 	 	 							selHie.setCOL_NM(selJson.getString("COL_NM")); // COL_NM
// 	 	 							selHie.setCOL_EXPRESS(selJson.getString("COL_EXPRESS"));
// 	 	 							aDtSelHIe.add(selHie);
// 	 	 						}
// 	 	 						logger.debug(selMea.toString());
// 	 	 						aDtSelMea.add(selMea);
// 	 	 					}
 	 				}

 					for (int idx = 0; idx < whereArray.size(); idx++) {
 						JSONObject whereJson = whereArray.getJSONObject(idx);

 						SelectCubeWhere whereCube = new SelectCubeWhere();
 						whereCube.setPARENT_UNI_NM("[" + whereJson.getString("DATASRC") + "]");
 						whereCube.setUNI_NM(whereJson.get("PARAM_NM")+"");
 						whereCube.setCAPTION(whereJson.getString("PARAM_CAPTION"));
 						whereCube.setOPER(whereJson.get("OPER")+"");
 						whereCube.setVALUES(whereJson.getString("DEFAULT_VALUE"));
 						whereCube.setVALUES_CAPTION(whereJson.getString("DEFAULT_VALUE").equals("[All]") ? "??????": whereJson.getString("DEFAULT_VALUE"));
 						whereCube.setAGG("");
 						whereCube.setDATA_TYPE(whereJson.get("DATA_TYPE")+"");
 						whereCube.setPARAM_YN(whereJson.get("PARAM_YN") + "");
 						whereCube.setPARAM_NM(whereJson.get("PARAM_NM")+"");
 						whereCube.setTYPE("DIM");
 						whereCube.setORDER(whereJson.get("ORDER")+"");
 						whereCube.setTBL_NM(whereJson.getString("DATASRC"));
 						whereCube.setCOL_NM(whereJson.get("KEY_VALUE_ITEM")+"");
 						whereCube.setLOGIC("");
 						whereCube.setCOL_EXPRESS("");
 						whereCube.setWHERE_CLAUSE(whereJson.getString("WHERE_CLAUSE"));
 						whereCube.setCOND_ID("A"+(idx+1));
 						aDtWhere.add(whereCube);
 					}

 					for(int idx=0;idx<OrderArray.size();idx++) {
 						JSONObject orderJson = OrderArray.getJSONObject(idx);
 						if(orderJson.getString("TYPE").equals("DIM")) {
 	 						for(CubeTableVO dimVo : dimCubeTable) {
 	 							List<CubeTableColumnVO> dimColumns = dimVo.getColumns();
 	 							for(CubeTableColumnVO dimColVo : dimColumns) {
 	 								if(dimColVo.getUniqueName().equals(orderJson.getString("UNI_NM"))) {
 	 									SelectCubeOrder orderCube = new SelectCubeOrder();
 	 									orderCube.setUNI_NM(orderJson.getString("UNI_NM"));
 	 		 	 						orderCube.setCAPTION(orderJson.getString("COL_CAPTION"));
 	 		 	 						orderCube.setSORT_TYPE(orderJson.getString("SORT_TYPE"));
 	 		 	 						orderCube.setTYPE(orderJson.getString("TYPE"));
 	 		 	 						orderCube.setORDER(idx+"");
 	 		 	 						orderCube.setTBL_NM(orderJson.getString("TBL_NM"));
 	 		 	 						String tableName = "";
 	 		 	 						if(!orderJson.has("tableName")) {
 	 		 	 							tableName = "["+orderJson.get("TBL_NM")+"]";
 	 		 	 						}else {
 	 		 	 							tableName = orderJson.getString("tableName");
 	 		 	 						}
 	 		 	 						orderCube.setPARENT_UNI_NM(tableName);
// 	 	 		 	 						orderCube.setPARENT_UNI_NM(orderJson.getString("tableName"));
 	 		 	 						aDtOrder.add(orderCube);
 	 	 	 	 						break;
 	 								}
 	 							}
 	 						}
 	 					}
 	 						
// 	 						orderCube.setUNI_NM(orderJson.getString("UNI_NM"));
// 	 						orderCube.setCAPTION(orderJson.getString("COL_CAPTION"));
// 	 						orderCube.setSORT_TYPE(orderJson.getString("SORT_TYPE"));
// 	 						orderCube.setTYPE(orderJson.getString("TYPE"));
// 	 						orderCube.setORDER(idx+"");
// 	 						orderCube.setTBL_NM(orderJson.getString("TBL_NM"));
// 	 						String tableName = "";
// 	 						if(!orderJson.has("tableName")) {
// 	 							tableName = "["+orderJson.get("TBL_NM")+"]";
// 	 						}else {
// 	 							tableName = orderJson.getString("tableName");
// 	 						}
// 	 						orderCube.setPARENT_UNI_NM(tableName);
//// 	 						orderCube.setPARENT_UNI_NM(orderJson.getString("tableName"));
// 	 						aDtOrder.add(orderCube);
 					}
 	 				

 	 				String sql = "";
 	 				//2020.12.07 MKSONG MARIADB ??????  DOGFOOT
// 	 				sql = this.dataSetServiceImpl.getSql(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, aDtOrder, "MARIA", InfoJson.getString("dsId"));
 					sql = this.dataSetServiceImpl.getSql(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, aDtOrder, "DB2", InfoJson.getString("dsId"));
 					if(statics.equals("true")) {
 						sql = sql.replaceFirst("DISTINCT", "");
	 	 			}
// 	 	 	        String sql = sqlQenQuery.CubeQuerySetting(aDtSel, aDtSelHIe, aDtSelMea, new ArrayList<SelectCubeWhere> (), new ArrayList<SelectCubeOrder> (), "DB2", new ArrayList<Relation>(),  new ArrayList<Relation>(), new ArrayList<SelectCubeEtc>());
 	 				logger.debug(sql);
 	 				out.print(sql);
 	 				out.flush();
 	 				out.close();
 	 			}
 	 	 		/*DOGFOOT cshan 20200113 - ???????????? ??????*/
 	 		}
 		}
 	}
 	
 	@RequestMapping(value = {"/drillthru/queries.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject queryDrillThruCubeSql(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        
        User sessionUser = this.authenticationService.getSessionUser(request);

       /* if (!Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication")) { 
            sessionUser = null;
            logger.error(this.messageSource.getMessage("request.report.cube.non-authn-mode"));
        }
        
        if (sessionUser == null) {
            response.setStatus(401);
            return new AjaxMessageConverter(401, "Not Authenticated User").toJson();
        }
        */
        Timer timer = new Timer();
        
        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        String actIdStr = SecureUtils.getParameter(request, "actid");
        
        JSONObject ret = new JSONObject();
        
        try {
            int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();
            int actId = Integer.valueOf(actIdStr).intValue();
            JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
            
            timer.start();
            
            ret = this.dataSetServiceImpl.queryDrillThruSql(sessionUser, dataSourceId, dataSourceType, actId, params);
        }
        catch (UndefinedDataTypeForNullValueException e) {
            logger.error("ReportController#query - ", e);
            response.setStatus(500);
            ret = new AjaxMessageConverter(921, "Undefined data type null value - " + e.toString()).toJson();
        } catch (NotFoundDatabaseConnectorException e) {
        	 logger.error("ReportController#query - ", e);
             response.setStatus(500);
             ret = new AjaxMessageConverter(920, "Not Found Database Connector. See Server Log. - " + e.toString()).toJson();
		} catch (EmptyDataSetInformationException e) {
			logger.error("ReportController#query - ", e);
            response.setStatus(500);
            ret = new AjaxMessageConverter(920, "Empty DataSet Information. See Server Log. - " + e.toString()).toJson();
		} catch (NotFoundDataSetTypeException e) {
			logger.error("ReportController#query - ", e);
            response.setStatus(500);
            ret = new AjaxMessageConverter(920, "Not Found DataSet Type. See Server Log. - " + e.toString()).toJson();
		} catch (SQLException e) {
			logger.error("ReportController#query - ", e);
            response.setStatus(500);
            ret = new AjaxMessageConverter(920, "Invalid Query. See Server Log. - " + e.toString()).toJson();
		}
        finally {
            timer.stop();
            
            Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
            Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
            
            logger.debug("query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
            logger.debug("query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
            logger.debug("query elapse time: " + timer.getInterval());
        }
        
        return ret;
    }
 	
 	@RequestMapping(value = {"/cancelqueries.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject cancelQuery(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception{
		JSONObject ret = new JSONObject();
		this.dataSetServiceImpl.cancelQuery();	
		ret = new AjaxMessageConverter(200, "Query Cancel success").toJson();
		return ret;
	}
 	
 	@RequestMapping(value = {"/cubeListInfo.do"}, method = RequestMethod.POST)
    public void cubeListInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
        
		long startMili = System.currentTimeMillis();
		long checkMili = 0;
		double checkMin = 0;
		
        String dsViewId = SecureUtils.getParameter(request, "dsviewid");
        String datasrc_type = SecureUtils.getParameter(request, "dstype");
        String user_id = SecureUtils.getParameter(request, "userId");
        String id_type = SecureUtils.getParameter(request, "idType");
        
        Map<String,List<CubeTableVO>> cubeTableInfo;
        
        JSONArray sqldata = null;
        
        JSONObject ret = new JSONObject();
        ret.put("DATASRC_TYPE", datasrc_type);
        
        List<CubeVO> cubeIdList;
        if(id_type.equals("CUBE")) {
        /* DOGFOOT ktkang KERIS cube????????? ??????????????? ????????? ???????????? ?????? ????????? ?????? ??????  20200114 */
        	cubeIdList = this.dataSetDAO.selectCubeMasterInformation(Integer.parseInt(dsViewId));
        } else {
        	cubeIdList = this.dataSetDAO.selectCubeId(Integer.parseInt(dsViewId));
        }
        
        /* DOGFOOT ktkang KERIS cube????????? ??????????????? ????????? ???????????? ?????? ????????? ?????? ??????  20200114 */
        String focusCube = null;

    	Map<String, Map<String,List<CubeTableVO>>> cubeTableInfoList = new HashMap<String, Map<String,List<CubeTableVO>>>();
    	for(int i = 0; i < cubeIdList.size(); i++) {
    		if(id_type.equals("CUBE") && cubeIdList.get(i).getCUBE_ID() == Integer.parseInt(dsViewId)) {
    			focusCube = cubeIdList.get(i).getCUBE_NM();
    		}
    		
    		checkMili = System.currentTimeMillis();
            checkMin = (checkMili - (double) startMili) / 1000;
            System.out.println("cubeListinfo.do ???????????? ?????? ?????? : " + checkMin + "???");
            startMili = System.currentTimeMillis();
            
    		cubeTableInfo = this.dataSetServiceImpl.selectCubeReportTableInfoList(cubeIdList.get(i).getCUBE_ID(), user_id);
    		
    		checkMili = System.currentTimeMillis();
            checkMin = (checkMili - (double) startMili) / 1000;
            System.out.println("cubeListinfo.do ???????????? ????????? ?????? ?????? : " + checkMin + "???");
            startMili = System.currentTimeMillis();
            
    		cubeTableInfoList.put(cubeIdList.get(i).getCUBE_NM(), cubeTableInfo);
    		ret.put("error", false);
    	}
    	
    	
        
    	/*dogfoot ??????????????? ?????? ?????? shlim 20200715*/
    	if(!(id_type.equals("Spread") || id_type.equals("Excel")) && id_type.equals("CUBE")) {
    		int cubeId = Integer.parseInt(dsViewId);
        	List<DrillThruColumnVO> drillThruCategoryList = this.reportService.selectDrillThruCategoryList(cubeId);
            
        	ret.put("drillThru", drillThruCategoryList);
    	}
    	
    	checkMili = System.currentTimeMillis();
        checkMin = (checkMili - (double) startMili) / 1000;
        System.out.println("cubeListinfo.do ???????????? ?????? ????????? ?????? ?????? : " + checkMin + "???");
        startMili = System.currentTimeMillis();
    	
    	ret.put("cubeTableInfoList", cubeTableInfoList);
    	ret.put("focusCube", focusCube);
        ret.put("data", sqldata);
        
        out.print(ret);
        out.flush();
        out.close();   
        return;
	}
 	/*DOGFOOT cshan 20200113 - ?????? ????????? ?????? - ???????????? ??? ??????*/
 	@RequestMapping(value = {"/cubeDatasetInfo.do"}, method = RequestMethod.POST)
    public void cubeDatasetInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
        
        String cubeId = SecureUtils.getParameter(request, "CUBE_ID");
        String cubeNm = SecureUtils.getParameter(request, "CUBE_NM");
        String user_id = SecureUtils.getParameter(request, "userId");
        String ds_type = SecureUtils.getParameter(request, "dstype");
        
        Map<String,List<CubeTableVO>> cubeTableInfo;
        
        JSONArray sqldata = null;
        
        JSONObject ret = new JSONObject();
        ret.put("DATASRC_TYPE", ds_type);
        
        List<CubeVO> cubeIdList;
        
    	Map<String, Map<String,List<CubeTableVO>>> cubeTableInfoList = new HashMap<String, Map<String,List<CubeTableVO>>>();
		cubeTableInfo = this.dataSetServiceImpl.selectCubeReportTableInfoList(Integer.parseInt(cubeId), user_id);
//    		cubeTableInfoList.put(cubeNm, cubeTableInfo);
		ret.put("error", false);
    	ret.put("cubeTableInfoList", cubeTableInfo);
        ret.put("data", sqldata);
        
        out.print(ret);
        out.flush();
        out.close();
        return;
	}
 	
 	/* DOGFOOT ktkang KERIS ????????? ??? ?????? ?????? ????????????  20200123 */
 	@RequestMapping(value = {"/getReportFieldList.do"}, method = RequestMethod.POST)
 	public @ResponseBody JSONObject getReportFieldList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception{
 		JSONObject ret = new JSONObject();
 		List<ReportFieldMasterVO> reportFieldList = new ArrayList<ReportFieldMasterVO>();
 		
 		String reportId = SecureUtils.getParameter(request, "reportId");
 		
 		//reportFieldList = this.reportService.selectReportFieldList(Integer.parseInt(reportId));	
 		reportFieldList = null;
 		
 		ret.put("data", reportFieldList);
 		return ret;
 	}
 	
 	//2020.01.30 mksong SQL LIKE ????????? ?????? dogfoot
 	//2020.01.31 MKSONG ?????? ?????? ?????? DOGFOOT
 	@RequestMapping(value = {"/sqlLike.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject sqllike(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
 		
 		/*dogfoot ?????? ????????? ??????????????? shlim 20201209*/
 		long beforeTime = System.currentTimeMillis(); //?????? ?????? ???
 		System.out.println("-------------------------------");
		System.out.println("???????????? : "+beforeTime);
		System.out.println("-------------------------------");
    	request.setCharacterEncoding("utf-8");
        User sessionUser = this.authenticationService.getSessionUser(request);

//        JSONArray fields = SecureUtils.getJSONArrayParameter(request, "fields");
//        String reportId = SecureUtils.getParameter(request, "reportId");
        JSONObject sqlConfig = SecureUtils.getJSONObjectParameter(request, "sqlConfig");
        /* DOGFOOT ktkang ?????? ????????? ??????  20200721 */
        String sql_query = new String(Base64.decode(SecureUtils.getParameter(request, "sql_query")));
        String dataSourceNm = SecureUtils.getParameter(request, "ds_nm");
        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        boolean multiDbQuery = (dataSourceIdStr.indexOf(",")>-1);
        if(multiDbQuery) {
        	String[] multiDsId = dataSourceIdStr.split(",");
        	dataSourceIdStr = multiDsId[0];
        }
        int dataSourceId = Integer.parseInt(dataSourceIdStr);
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        String schedulePath = SecureUtils.getParameter(request, "schedulePath");
        String inMemory = SecureUtils.getParameter(request, "inMemory");
        
        Timer timer = new Timer();
        
        int sqlTimeout = Integer.parseInt(SecureUtils.getParameter(request, "sqlTimeout"));
        JSONObject ret = new JSONObject();
        String status = "50";
        JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
        String join2 = SecureUtils.getParameter(request, "join");
        String fullQuery = SecureUtils.getParameter(request, "fullQuery");
        /* DOGFOOT ktkang SQL ?????? ??????  20200721 */
        String userId = SecureUtils.getParameter(request, "userId");
        String reportType = SecureUtils.getParameter(request, "reportType");
		/* DOGFOOT ajkim ??????????????? null ?????? ?????? ?????? 20201207 */
        String itemType = SecureUtils.getParameter(request, "itemType");
        /* DOGFOOT ktkang Null ????????? ?????? ??????  20200904 */
        JSONObject nullDimension = SecureUtils.getJSONObjectParameter(request, "nullDimension");
        /* DOGFOOT ktkang BMT ???????????? ???????????? ??????  20201201 */
        String oldSchedule = SecureUtils.getParameter(request, "oldSchedule");
        /*dogfoot ????????? ?????? ?????? ???????????? ?????? ?????? shlim 20210728*/
        String forCountQuery = SecureUtils.getParameter(request, "forCountQuery");
        String useWithQuery = SecureUtils.getParameter(request, "useWithQuery");
        
        boolean join = false;
        
        /* DOGFOOT ktkang ???????????? ??????????????? ???????????? ????????? ?????? ??????  20200922 */
        String sql = sql_query;
        String pidString = SecureUtils.getParameter(request, "pid");
		String reportTypeForWeb = "";
		ReportLogMasterVO LogVo = new ReportLogMasterVO();
		String ip = "";
		
		User user = this.authenticationService.getSessionUser(request);
		boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
		if (logUse) {
			ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
			if(ip==null) ip = "127.0.0.1";
			logger.debug("remoteADDR : " + ip);
			if (pidString.equals("")) {
				LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), 0, "", reportTypeForWeb,
						user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "",
						/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
						new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceId, timer.getInterval(), "WB");
			} else {
				int pid = Integer.parseInt(SecureUtils.getParameter(request, "pid"));
				LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), pid, "", reportTypeForWeb,
						user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "",
						/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
						new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceId, timer.getInterval(), "WB");
			}

			logger.debug("query log ----" + LogVo.toString());
			this.reportService.enrollReportQueryLog(logUse, LogVo);
		}
		
        timer.start();
        /* DOGFOOT ktkang KERIS ???????????? ?????? ??? ?????? ??? ?????????  20200123 */
        String queryParam = null;
        if(fullQuery.equals("true") && dataSourceNm.contains("????????????")) {
        } else if(dataSourceNm.contains("????????????")) {
        	queryParam = "dataCut";
        }
        
        status = "60";
        //2020.09.11 mksong ????????? ?????? ?????? ?????? dogfoot
        
    	Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("sqlLike query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("sqlLike query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("sqlLike query elapse time: " + timer.getInterval());
        // ????????? - ?????? ?????? ??????  20210913
        CloseableList<JSONObject> result = new FileBackedJSONObjectList();
        JSONArray data = new JSONArray();
        
        //mssql????????? with????????? order by??? ?????? ????????? ???????????? ???
//        if(sql_query.toUpperCase().indexOf("ORDER BY") > 0) {
//        	sql_query = sql_query.substring(0, sql_query.toUpperCase().indexOf("ORDER BY"));
//        }        
        boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");
        if(!schedulePath.equals("1001") && !schedulePath.equals("")) {
        	File folder = WebFileUtils.getWebFolder(request, true, "DataFiles");
    		/* DOGFOOT ktkang BMT ???????????? ???????????? ??????  20201201 */
    		File file = null;
    		if(oldSchedule.equals("Y")) {
    			file = new File(schedulePath);
    		} else {
    			file = new File(folder, schedulePath);
    		}

    		try (InputStream is = new FileInputStream(file)) {
        		String jsonText = IOUtils.toString(is, "UTF-8");
        		JSONObject dataJson = (JSONObject) JSONSerializer.toJSON(jsonText);
                JSONArray jArr = (JSONArray) dataJson.get(dataSourceNm);
                result = (FileBackedJSONObjectList) this.dataSetServiceImpl.sparkJson(jArr, sql_query, params, queryParam, sqlConfig);
    		}
        } else {
        	/*dogfoot spark ???????????? ?????? shlim 20210205*/
            if(multiDbQuery || inMemory.equals("true")) {
            	JSONArray tbllist = SecureUtils.getJSONArrayParameter(request, "tbllist");
            	
            	if(tbllist.size() > 0 || inMemory.equals("true")) {
            		ArrayList<Integer> dsid = new ArrayList<Integer>();
        	        ArrayList<String> tblnm = new ArrayList<String>();
        	        for(int i=0;i<tbllist.size();i++) {
        	        	JSONObject jobj = (JSONObject) tbllist.get(i);
        	        	dsid.add((int)jobj.get("dsid"));
        	        	tblnm.add((String)jobj.get("tblnm"));
        	        }                    	
                	
        	        result = (FileBackedJSONObjectList) this.dataSetServiceImpl.sparkSqlLike(dsid, tblnm, dataSourceType, sql_query, params, sqlTimeout, queryParam, sqlConfig);
            	}else {
            		result = (FileBackedJSONObjectList) this.dataSetServiceImpl.querySqlLike(dataSourceId, dataSourceType, sql_query, params, sqlTimeout, queryParam, sqlConfig, nullDimension, itemType);
            	}
    	        
            } else { 
           		/* DOGFOOT ktkang Null ????????? ?????? ??????  20200904 */
            	/* DOGFOOT ajkim ??????????????? null ?????? ?????? ?????? 20201207 */
            	if("N".contains(useWithQuery)) {
            		result = (FileBackedJSONObjectList) this.dataSetServiceImpl.querySqlLike(dataSourceId, dataSourceType, sql_query, params, sqlTimeout, queryParam, sqlConfig, nullDimension, itemType, false);
            	}else {
            		result = (FileBackedJSONObjectList) this.dataSetServiceImpl.querySqlLike(dataSourceId, dataSourceType, sql_query, params, sqlTimeout, queryParam, sqlConfig, nullDimension, itemType);
            	}
            	
            }
        }
        //2020.09.11 mksong ????????? ?????? ?????? ?????? dogfoot
        timer.stop();
       	// ????????? - ?????? ?????? ??????  20210913
        // sql ???????????? ????????? ????????? ????????? result??? sql??? ?????? ?????? ?????? ??????
//        JSONArray resultsql = new JSONArray();
//        resultsql.add(result.getAttribute("sql"));
        ret.put("sql", new String(Base64.encode(result.getAttribute("sql").toString().getBytes())));

       	/*dogfoot ????????? ?????? ?????? ???????????? ?????? ?????? shlim 20210728*/
       	if (reportType.equals("AdHoc")) {
			if(forCountQuery.equalsIgnoreCase("true")) {
				if(result.size()>=100000) {
					ret.put("dataSizeOver", true);
	        		ret.put("forCountQuery",true);
				}else {
					ret.put("dataSizeOver", false);
	        		ret.put("forCountQuery",false);
	        		ret.put("data", result);
				}
			}else {
				ret.put("data", result);
			}
       		
		} else {
			ret.put("data", result);
		}
		
		
        /* DOGFOOT ktkang ???????????? ??????????????? ???????????? ????????? ?????? ??????  20200922 */
		if (logUse) {
			//20210908 AJKIM ?????? ????????? ?????? ?????? dogfoot
			if (reportType.equals("AdHoc")) {
				reportTypeForWeb = "AdHoc";
			} else if(reportType.equals("Spread") || reportType.equals("Excel")){
				reportTypeForWeb = "Spread";
			} else if(reportType.equals("DSViewer")){
				reportTypeForWeb = "DSViewer";
			} else if(reportType.equals("StaticAnalysis") || reportType.equals("StaticAnal")) {
				reportTypeForWeb = "StaticAnalysis";
			} else {
				reportTypeForWeb = "DashAny";
			}

			String keyTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS").format(new Date(timer.getStartTime()));
			Timestamp queryEndTimestamp = Timer.formatTime(timer.getFinishTime());
			
			ReportLogMasterVO vo = new ReportLogMasterVO();
			vo.setLOG_SEQ(keyTime);
			vo.setED_DT(queryEndTimestamp);
			vo.setSTATUS_CD(status);
			
			if (logUse) {
				this.reportService.updateReportLogDetail(logUse, vo);
			}
		}
		
		/*dogfoot ?????? ????????? ??????????????? shlim 20201209*/        
		long afterTime = System.currentTimeMillis(); // ?????? ?????? ???
		long secDiffTime = (afterTime - beforeTime); 
		System.out.println("-------------------------------");
		System.out.println("???????????? : "+afterTime);
		System.out.println("????????????(ms) : "+secDiffTime);
		System.out.println("-------------------------------");
		ret.put("Queries_Time", secDiffTime);
		
		return ret;
    }
 	
 	/* DOGFOOT ktkang ????????? ????????? ?????? ????????? ???????????? ???????????? ?????? ??????  20200903 */
 	@RequestMapping(value = {"/sqlLikePaging.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject sqlLikePaging(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	request.setCharacterEncoding("utf-8");
        User sessionUser = this.authenticationService.getSessionUser(request);

//        JSONArray fields = SecureUtils.getJSONArrayParameter(request, "fields");
//        String reportId = SecureUtils.getParameter(request, "reportId");
        JSONObject sqlConfig = SecureUtils.getJSONObjectParameter(request, "sqlConfig");
        /* DOGFOOT ktkang ?????? ????????? ??????  20200721 */
        String sql_query = new String(Base64.decode(SecureUtils.getParameter(request, "sql_query")));
        String dataSourceNm = SecureUtils.getParameter(request, "ds_nm");
        String dataSourceIdStr = SecureUtils.getParameter(request, "dsid");
        boolean multiDbQuery = (dataSourceIdStr.indexOf(",")>-1);
        if(multiDbQuery) {
        	String[] multiDsId = dataSourceIdStr.split(",");
        	dataSourceIdStr = multiDsId[0];
        }
        int dataSourceId = Integer.parseInt(dataSourceIdStr);
        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        
        Timer timer = new Timer();
        
        int sqlTimeout = Integer.parseInt(SecureUtils.getParameter(request, "sqlTimeout"));
        JSONObject ret = new JSONObject();
        String status = "50";
        JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
        String join2 = SecureUtils.getParameter(request, "join");
        String fullQuery = SecureUtils.getParameter(request, "fullQuery");
        /* DOGFOOT ktkang SQL ?????? ??????  20200721 */
        String userId = SecureUtils.getParameter(request, "userId");
        String reportType = SecureUtils.getParameter(request, "reportType");
        
        int pagingSize = Integer.parseInt(SecureUtils.getParameter(request, "pagingSize"));
        int pagingStart = Integer.parseInt(SecureUtils.getParameter(request, "pagingStart"));
        
        boolean join = false;
        
        timer.start();
        status = "60";
        //2020.09.11 mksong ????????? ?????? ?????? ?????? dogfoot
        
        // ????????? - ?????? ?????? ??????  20210913
        List<JSONObject> result = new JSONArray();
        JSONArray data = new JSONArray();
        
        result = this.dataSetServiceImpl.querySqlLikePaging(dataSourceId, dataSourceType, sql_query, params, sqlTimeout, sqlConfig, pagingSize, pagingStart);
        
        //2020.09.11 mksong ????????? ?????? ?????? ?????? dogfoot
        timer.stop();
        
        Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("sqlLike query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("sqlLike query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("sqlLike query elapse time: " + timer.getInterval());
        
       	/* DOGFOOT ktkang ???????????? ?????? ??????  20200804 */
       	ret.put("sql", result.get(result.size()-2));
       	ret.put("totalCount", result.get(result.size()-1));
       	result.remove(result.size()-1);
       	result.remove(result.size()-1);
		ret.put("data", result);
		
        /* DOGFOOT ktkang SQL ?????? ??????  20200721 */
		boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
		if (logUse) {
			int dataSourceID = this.dataSetServiceImpl.getDSIDforLog(dataSourceId,
					dataSourceType);
			String pidString = SecureUtils.getParameter(request, "pid");
			String reportTypeForWeb = "";
			ReportLogMasterVO LogVo = new ReportLogMasterVO();
			User user = this.authenticationService.getRepositoryUser(userId);

			//20210908 AJKIM ?????? ????????? ?????? ?????? dogfoot
			if (reportType.equals("AdHoc")) {
				reportTypeForWeb = "AdHoc";
			} else if(reportType.equals("Spread") || reportType.equals("Excel")){
				reportTypeForWeb = "Spread";
			} else if(reportType.equals("DSViewer")){
				reportTypeForWeb = "DSViewer";
			} else if(reportType.equals("StaticAnalysis") || reportType.equals("StaticAnal")) {
				reportTypeForWeb = "StaticAnalysis";
			} else {
				reportTypeForWeb = "DashAny";
			}

			String sql = sql_query;

			String ip = "";
				ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
				if(ip==null) ip = "127.0.0.1";
				logger.debug("remoteADDR : " + ip);
				if (pidString.equals("")) {
					LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), 0, "", reportTypeForWeb,
							user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "",
							/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
							new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceID, timer.getInterval(), "WB");
				} else {
					int pid = Integer.parseInt(SecureUtils.getParameter(request, "pid"));
					LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), pid, "", reportTypeForWeb,
							user.getUSER_ID(), user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "", ip, "",
							/* DOGFOOT mksong BASE64 ?????? ??????  20200116 */
							new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceID, timer.getInterval(), "WB");
				}

			logger.debug("query log ----" + LogVo.toString());
			this.reportService.enrollReportQueryLog(logUse, LogVo);
			
			String keyTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS").format(new Date(timer.getStartTime()));
			Timestamp queryEndTimestamp = Timer.formatTime(timer.getFinishTime());
			
			ReportLogMasterVO vo = new ReportLogMasterVO();
			vo.setLOG_SEQ(keyTime);
			vo.setED_DT(queryEndTimestamp);
			vo.setSTATUS_CD(status);
			
			if (logUse) {
				this.reportService.updateReportLogDetail(logUse, vo);
			}
		}
        
        return ret;
    }

 	
 	/* DOGFOOT ktkang ???????????? ?????????????????? ?????? ????????? ????????? ??????   20200212 */
 	@RequestMapping(value = {"/condition/cubeUniName.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject cubeUniName(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
 		int cube_id = Integer.parseInt(SecureUtils.getParameter(request, "cube_id"));
		String uni_nm = SecureUtils.getParameter(request, "uni_nm");
		Object defaultValue = null;
		JSONObject ret = new JSONObject();
		
		CubeTableVO cubeTable = new CubeTableVO();
		cubeTable.setCubeId(cube_id);
		cubeTable.setUniqueName(uni_nm);
		/* DOGFOOT ktkang ???????????? ?????? ?????? ??? ????????? ?????? ??????  20200309 */
		DataSetMasterVO dataSetMaster;
	    dataSetMaster = this.dataSetDAO.selectCubeMaster(cube_id);
	            
		List<CubeTableColumn> cubeTableColList = this.reportService.selectCubeColumnInfomationList(cubeTable);
		CubeHieMasterVO cubeHie = this.dataSetDAO.selectHieHieUniNm(cube_id, uni_nm);
		
		/* DOGFOOT ktkang ???????????? ?????????????????? ?????? ????????? ????????? ??????   20200212 */
		if(cubeHie != null) {
			ret.put("uni_nm", cubeHie.getHIE_HIE_UNI_NM());
		}
		ret.put("cubeTableColList", cubeTableColList);
		/* DOGFOOT ktkang ???????????? ?????? ?????? ??? ????????? ?????? ??????  20200309 */
		ret.put("ds_id", dataSetMaster.getId());
		return ret;
	}
 	
 	/* DOGFOOT ktkang ???????????? ?????????????????? ????????? ??? ????????? ????????? ??????   20200212 */
 	@RequestMapping(value = {"/cubeRelationList.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject cubeRelationList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
 		int cube_id = Integer.parseInt(SecureUtils.getParameter(request, "cube_id"));
		String uni_nm = SecureUtils.getParameter(request, "uni_nm");
		Object defaultValue = null;
		JSONObject ret = new JSONObject();
		
		Relation cubeRel = new Relation();
		cubeRel.setCUBE_ID(cube_id);
		cubeRel.setFK_TBL_NM(uni_nm);
		
		List<Relation> cubeRelationList = this.dataSetDAO.selectCubeRelationList(cubeRel);
		List<String> relationTableList = new ArrayList<String>(); 
		for (Relation rel : cubeRelationList) {
			/*dogfoot shlim  ???????????? ?????? ??? relation ????????? ????????? 20210701*/
//			List<Relation> DSVIEWRelationList = this.dataSetDAO.selectDsViewCubeRelationList(rel);
			relationTableList.add(rel.getDIM_UNI_NM());
//			for (Relation dsrel : DSVIEWRelationList) {
//				relationTableList.add(dsrel.getDIM_UNI_NM());
//			}
		}
		relationTableList.add("[" + uni_nm + "]");
		ret.put("relationTableList", relationTableList);
		return ret;
	}
 	
 	// ????????? - ?????? ?????? ??????  20210913
 	@RequestMapping(value = {"/getDatasetTableColumns.do"}, method = RequestMethod.POST)
	public @ResponseBody List<JSONObject> getDatasetTableColumns(HttpServletRequest request, HttpServletResponse response, Model model) {
		List<JSONObject> data = null;
		
		try {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			int dataSourceId = Integer.parseInt(SecureUtils.getParameter(request, "id"));
			String dataSourceType = SecureUtils.getParameter(request, "type");
			String tableName = SecureUtils.getParameter(request, "table");
			String requestType = SecureUtils.getParameter(request, "request");
			
			String nameKey = "COLUMN".equals(requestType) ? "COL_NM" : "TBL_NM";
			String captionKey = "COLUMN".equals(requestType) ? "COL_CAPTION" : "TBL_CAPTION";

			DataSetMasterVO dataSetInfo = this.dataSetServiceImpl.getDataSourceInfo(dataSourceId,dataSourceType);			
			SqlForEachMartDbType sqlFor = new SqlForEachMartDbType();
			String sql = sqlFor.SqlForEachDbType(
				dataSetInfo.getDatabaseType(), 
				requestType, 
				dataSetInfo.getDatabaseOwner(), 
				dataSetInfo.getDatabaseName(), 
				tableName,
				null
			);
			
			JSONObject params = new JSONObject();
			data = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql, params, 0, null);
			
			for (int i = 0; i < data.size(); i++) {
				if (data.get(i) instanceof JSONObject) {
				// ????????? - ?????? ?????? ??????  20210913
					JSONObject dataItem = data.get(i);
					
					String caption = dataItem.getString(captionKey);
					if (caption == null || caption.length() == 0) {
						caption = dataItem.getString(nameKey);
					}
					
					dataItem.put("text", caption);
					dataItem.put("parent", tableName);
					
					if ("TABLE".equals(requestType)) {
						dataItem.put("id", caption);
						dataItem.put("isDirectory", true);
						dataItem.put("hasItems", true);
						dataItem.put("TYPE", "TABLE");
					} else {
						dataItem.put("id", tableName + "-" + caption);
						dataItem.put("isDirectory", false);
						dataItem.put("hasItems", false);
						dataItem.put("TYPE", "COLUMN");
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			data = new JSONArray();
		}
		
		return data;
	}
 	
 	// ????????? - ?????? ?????? ??????  20210913
	@RequestMapping(value = {"/getDatasetTableColumns2.do"}, method = RequestMethod.POST)
	public @ResponseBody List<JSONObject> getDatasetTableColumns2(HttpServletRequest request, HttpServletResponse response, Model model) {
		try {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			String dataSourceIdStr = SecureUtils.getParameter(request, "id");
			if(dataSourceIdStr.indexOf(",")>-1) {
				String[] dataSourceIdArr = dataSourceIdStr.split(",");
				dataSourceIdStr = dataSourceIdArr[0];
			}
			int dataSourceId = Integer.parseInt(dataSourceIdStr);
			String dataSourceType = SecureUtils.getParameter(request, "type");
			String tableName = SecureUtils.getParameter(request, "table");
			String requestType = SecureUtils.getParameter(request, "request");
			String searchWord = SecureUtils.getParameter(request, "search");
			
			switch (requestType) {
				case "SEARCH":
					// ????????? - ?????? ?????? ??????  20210913
					List<JSONObject> tables = this.dataSetServiceImpl.getTableList(dataSourceId, dataSourceType, "TABLE", searchWord);
					List<JSONObject> result = tables;
					if (tables.size() > 0) {
						String tableListStr = "(";
						for (int i = 0; i < tables.size(); i++) {
							tableListStr += "'" + tables.get(i).getString("TBL_NM") + "'";
							if (i < tables.size() - 1) {
								tableListStr += ",";
							}
						}
						tableListStr += ")";
						List<JSONObject> columns = this.dataSetServiceImpl.getColumnList(dataSourceId, dataSourceType, "COLUMN", tableListStr);
						if (columns.size() > 0) {
							String jsonConcatFirst = result.toString();
							jsonConcatFirst = jsonConcatFirst.substring(0, jsonConcatFirst.length() - 1);
							String jsonConcatSecond = columns.toString();
							jsonConcatSecond = "," + jsonConcatSecond.substring(1, jsonConcatSecond.length());
							result = JSONArray.fromObject(jsonConcatFirst + jsonConcatSecond);
						}
					}
					return result;
				case "COLUMN":
					return this.dataSetServiceImpl.getColumnList(dataSourceId, dataSourceType, "COLUMN", tableName);
				case "TABLE":
				default:
					return this.dataSetServiceImpl.getTableList(dataSourceId, dataSourceType, "TABLE", searchWord);
			}			
		} catch (Exception e) {
			e.printStackTrace();
			return new JSONArray();
		}
	} 	
	
	@RequestMapping(value = {"/getMultiDatasetTableColumns.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONArray getDatasetTableColumnsMulti(HttpServletRequest request, HttpServletResponse response, Model model) {
		try {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			String dataSourceIdArr[] = SecureUtils.getParameter(request, "dsid").split(",");
			String dataSourceType = SecureUtils.getParameter(request, "type");
			/*dogfoot ERD ?????? ????????? ???????????? -> ????????? ???????????? ??????????????? ?????? shlim 20210402*/
			String selectedTableList = SecureUtils.getParameter(request, "selectedTableList");
			JSONArray ret = new JSONArray();
			
			for(String dataSourceIdStr:dataSourceIdArr) {
				int dataSourceId = Integer.parseInt(dataSourceIdStr);
				/*dogfoot ERD ?????? ????????? ???????????? -> ????????? ???????????? ??????????????? ?????? shlim 20210402*/
//				JSONArray tables = this.dataSetServiceImpl.getTableList(dataSourceId, dataSourceType, "TABLE", "");
				// ????????? - ?????? ?????? ??????  20210913
				List<JSONObject> tables = this.dataSetServiceImpl.getTableList(dataSourceId, dataSourceType, "TABLE", selectedTableList);
				List<JSONObject> result = tables;
				if (tables.size() > 0) {
					String tableListStr = "(";
					for (int i = 0; i < tables.size(); i++) {
						tableListStr += "'" + tables.get(i).getString("TBL_NM") + "'";
						if (i < tables.size() - 1) {
							tableListStr += ",";
						}
					}
					tableListStr += ")";
					List<JSONObject> columns = this.dataSetServiceImpl.getColumnList(dataSourceId, dataSourceType, "COLUMN", tableListStr);
					if (columns.size() > 0) {
						String jsonConcatFirst = result.toString();
						jsonConcatFirst = jsonConcatFirst.substring(0, jsonConcatFirst.length() - 1);
						String jsonConcatSecond = columns.toString();
						jsonConcatSecond = "," + jsonConcatSecond.substring(1, jsonConcatSecond.length());
						result = JSONArray.fromObject(jsonConcatFirst + jsonConcatSecond);
					}
				}
				for(int i=0;i<result.size();i++) {
					JSONObject jObj = (JSONObject)result.get(i);
					jObj.put("DATASET_SRC", dataSourceId);
					ret.add(jObj);
				}
			}
			return ret;
		} catch (Exception e) {
			e.printStackTrace();
			return new JSONArray();
		}
	} 		
 	
 	@RequestMapping(value = { "/getDatasourceInfoById2.do" }, method = RequestMethod.GET)
	public @ResponseBody JSONObject getDatasourceInfoById2(HttpServletRequest request, HttpServletResponse response, Model model) {
		JSONObject result = new JSONObject();

		try {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			int id = Integer.parseInt(SecureUtils.getParameter(request, "id"));
			SubjectMasterVO dsInfo = this.dataSetServiceImpl.getDatasourceInfoById(id);
			if(dsInfo != null) {	
				JSONObject data = new JSONObject();
				data.put("DS_ID", dsInfo.getDS_ID());
				data.put("????????? ?????? ???", dsInfo.getDS_NM());
				data.put("DB ???", dsInfo.getDB_NM());
				data.put("DB ??????", dsInfo.getDBMS_TYPE());
				data.put("?????? ??????(???)", dsInfo.getIP());
				data.put("????????? ?????????", dsInfo.getUSER_AREA_YN());
				data.put("Port", dsInfo.getPORT());
				data.put("?????????", dsInfo.getOWNER_NM());
				data.put("?????? ID", dsInfo.getUSER_ID());
				data.put("??????", dsInfo.getDS_DESC());
				result.put("data", data);
				result.put("status", 200);
			} else {
				throw new NotFoundDatabaseConnectorException();
			}
		} catch (Exception e) {
			e.printStackTrace();
			result = new JSONObject();
			result.put("status", 500);
		}
		
		return result;
	}
	
	@RequestMapping(value = { "/getDatasourceInfoById.do" }, method = RequestMethod.GET)
	public @ResponseBody JSONObject getDatasourceInfoById(HttpServletRequest request, HttpServletResponse response, Model model) {
		JSONObject result = new JSONObject();

		try {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			JSONObject resultData = new JSONObject();
			JSONArray ids = JSONArray.fromObject(request.getParameter("ids"));
			for (int i = 0; i < ids.size(); i++) {
				JSONObject idObj = ids.getJSONObject(i);
				String dsid = "";
				switch (idObj.getString("dstype")) {
					case "CUBE":
					case "DS_CUBE":
						SubjectCubeMasterVO cubeDsInfo = this.dataSetServiceImpl.getCubeDatasourceInfoById(idObj.getInt("dsid"));
						if(cubeDsInfo != null) {	
							JSONObject data = new JSONObject();
							data.put("DS_ID", cubeDsInfo.getCUBE_ID());
							data.put("DS_NM", cubeDsInfo.getDS_NM());
							data.put("DB_NM", cubeDsInfo.getDB_NM());
							data.put("DBMS_TYPE", cubeDsInfo.getDBMS_TYPE());
							data.put("IP", cubeDsInfo.getIP());
							data.put("USER_AREA_YN", cubeDsInfo.getUSER_AREA_YN());
							data.put("PORT", cubeDsInfo.getPORT());
							data.put("OWNER_NM", cubeDsInfo.getOWNER_NM());
							data.put("USER_ID", cubeDsInfo.getUSER_ID());
							data.put("DS_DESC", cubeDsInfo.getDS_DESC());
							data.put("WF_YN", cubeDsInfo.getWF_YN());
							data.put("DS_VIEW_ID", cubeDsInfo.getDS_VIEW_ID());
							data.put("DS_VIEW_NM", cubeDsInfo.getDS_VIEW_NM());
							data.put("CUBE_ID", cubeDsInfo.getCUBE_ID());
							data.put("CUBE_NM", cubeDsInfo.getCUBE_NM());
							data.put("ORG_DS_ID", cubeDsInfo.getDS_ID());
							resultData.put(idObj.getString("mapid"), data);
						}
						break;
					case "DS_VIEW":
						dsid = idObj.get("dsid").toString();
						if(dsid.indexOf(",")>-1) {
							String[] dsidArr = dsid.split(",");
							dsid = dsidArr[0];
						}
						DataSetMasterVO dataSetMaster = this.dataSetDAO.selectDataSetViewMaster(Integer.parseInt(dsid));
						SubjectMasterVO dsInfo = this.dataSetDAO.getDatasourceInfoById(dataSetMaster.getId());
						if(dsInfo != null) {	
							JSONObject data = new JSONObject();
							data.put("DS_ID", dsInfo.getDS_ID());
							data.put("DS_NM", dsInfo.getDS_NM());
							data.put("DB_NM", dsInfo.getDB_NM());
							data.put("DBMS_TYPE", dsInfo.getDBMS_TYPE());
							data.put("IP", dsInfo.getIP());
							data.put("USER_AREA_YN", dsInfo.getUSER_AREA_YN());
							data.put("PORT", dsInfo.getPORT());
							data.put("OWNER_NM", dsInfo.getOWNER_NM());
							data.put("USER_ID", dsInfo.getUSER_ID());
							data.put("DS_DESC", dsInfo.getDS_DESC());
							resultData.put(idObj.getString("mapid"), data);
						}
						break;
					default:
						dsid = idObj.get("dsid").toString();
						if(dsid.indexOf(",")>-1) {
							String[] dsidArr = dsid.split(",");
							dsid = dsidArr[0];
						}
						SubjectMasterVO dsInfo2 = this.dataSetServiceImpl.getDatasourceInfoById(Integer.parseInt(dsid));
						if(dsInfo2 != null) {	
							JSONObject data = new JSONObject();
							data.put("DS_ID", dsInfo2.getDS_ID());
							data.put("DS_NM", dsInfo2.getDS_NM());
							data.put("DB_NM", dsInfo2.getDB_NM());
							data.put("DBMS_TYPE", dsInfo2.getDBMS_TYPE());
							data.put("IP", dsInfo2.getIP());
							data.put("USER_AREA_YN", dsInfo2.getUSER_AREA_YN());
							data.put("PORT", dsInfo2.getPORT());
							data.put("OWNER_NM", dsInfo2.getOWNER_NM());
							data.put("USER_ID", dsInfo2.getUSER_ID());
							data.put("DS_DESC", dsInfo2.getDS_DESC());
							resultData.put(idObj.getString("mapid"), data);
						}
						break;
				}
			}
			result.put("data", resultData);
			result.put("status", 200);
		} catch (Exception e) {
			e.printStackTrace();
			result = new JSONObject();
			result.put("status", 500);
		}
		
		return result;
	}	
	
	@RequestMapping(value = {"/getConditionValues.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getConditionValues(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		int dataSourceId = Integer.parseInt(SecureUtils.getParameter(request, "dsid"));
		String dataSourceType = SecureUtils.getParameter(request, "dstype");
		String tblNm = SecureUtils.getParameter(request, "tblNm");
		String colNm = SecureUtils.getParameter(request, "colNm");
		
		DataSetMasterVO dataSetInfo = this.dataSetServiceImpl.getDataSourceInfo(dataSourceId,dataSourceType);
		
		SqlForEachMartDbType sqlFor = new SqlForEachMartDbType();
		String sql = String.format("SELECT %s FROM %s GROUP BY %s ORDER BY 1 ASC", colNm, tblNm, colNm);
		
		JSONObject params = new JSONObject();
		
		// ????????? - ?????? ?????? ??????  20210913
		List<JSONObject> ret = this.dataSetServiceImpl.querySql(dataSourceId, dataSourceType, sql, params, 0, null);

		returnObj.put("data", ret);
		return returnObj;
	}
	
 	
	@RequestMapping(value = {"/getMenuConfig.do"})
	public @ResponseBody JSONObject getLeftMenuConfig(HttpServletRequest request, HttpServletResponse response, Model model) {
		JSONObject result = new JSONObject();
		try {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			WebConfigMasterVO webConfig = this.authenticationService.getWebConfigMstr();
			result.put("data", webConfig.getMENU_CONFIG());
			result.put("status", 200);
		} catch (Exception e) {
			e.printStackTrace();
			result = new JSONObject();
			result.put("status", 500);
		}
		return result;
	}
	
	
	@RequestMapping(value = {"/getFontConfig.do"}, method = RequestMethod.GET)
	public @ResponseBody JSONObject getFontConfig(HttpServletRequest request, HttpServletResponse response, Model model) {
		JSONObject result = new JSONObject();
		try {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			WebConfigMasterVO webConfig = this.authenticationService.getWebConfigMstr();
			result.put("data", webConfig.getFONT_CONFIG());
			result.put("status", 200);
		} catch (Exception e) {
			e.printStackTrace();
			result = new JSONObject();
			result.put("status", 500);
		}
		return result;
	} 			
	/* DOGFOOT ktkang ????????? ???????????? ?????? ??????  20200903 */
	@RequestMapping(value = {"/getReportHisList.do"}, method = RequestMethod.POST)
    public void getReportHisList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
        
        int reportId = Integer.parseInt(SecureUtils.getParameter(request, "reportId"));
        
        ArrayList<JSONObject> reportHisLists = new ArrayList<JSONObject>();
        List<ReportMasterHisVO> reportHisList = new ArrayList<ReportMasterHisVO>();
        
        JSONObject ret = new JSONObject();
        
        reportHisList = this.reportService.selectReportHisList(reportId);
        for (ReportMasterHisVO reportHis : reportHisList) {
        	JSONObject datasetfld = new JSONObject();

        	datasetfld.put("REPORT_SEQ", reportHis.getREPORT_SEQ());
        	datasetfld.put("MOD_DT", reportHis.getMOD_DT());
        	
        	reportHisLists.add(datasetfld);
		}
        
        ret.put("reportHisLists", reportHisLists);

        out.print(ret);
		out.flush();
		out.close();   
		return;
    }
	
	/**
	 * ????????? ?????? ??????
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping("/timeSeriesForecast.do")
	public Map<String, Object> timeSeriesForecast(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String globalDataArr = String.valueOf(params.get("globalDataArray"));
		String filteredDataArr = String.valueOf(params.get("filteredDataArray"));
		/* DOGFOOT yhkim ??????????????? ?????? ??? ???????????? 20201123 */
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDataArr, new TypeToken<List<LinkedHashMap<String, String>>>() {}.getType());
		List<LinkedHashMap<String, Object>> filteredDataList = gson.fromJson(filteredDataArr, new TypeToken<List<LinkedHashMap<String, String>>>() {}.getType());
		List<LinkedHashMap<String, Object>> measureInfoList = gson.fromJson(String.valueOf(params.get("measureInfoArray")), new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> seriesDimensionInfoList = gson.fromJson(String.valueOf(params.get("seriesDimensionInfoArray")), new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		/* DOGFOOT syjin ????????? ?????? ?????? ??????(JAVA,R) ?????? ?????? 20210219 */
		int analUseType = Integer.parseInt(String.valueOf(params.get("analUseType")));
		
		ExecutorService executor = Executors.newSingleThreadExecutor();
		Callable task = new Callable() {
			public List<LinkedHashMap<String, Object>> call() throws Exception {
				/* DOGFOOT syjin ????????? ?????? R??? ?????? 20210205 */
				/* DOGFOOT syjin ????????? ?????? ?????? ??????(JAVA,R) ?????? ?????? 20210219 */
				if(analUseType == 0) {//R
					return reportService.getTimeSeriesRForecast(globalDataList, measureInfoList, seriesDimensionInfoList, params, 0);
				}else {
					return reportService.getTimeSeriesForecast(globalDataList, measureInfoList, seriesDimensionInfoList, params, 0);
				}
			}
		};
		Future future = executor.submit(task);
		
		Map<String, Object> result = new HashMap<>();
		
		//result.put("globalData", future.get(15000, TimeUnit.MILLISECONDS));
		
		/* DOGFOOT syjin ????????? ?????? R??? ?????? 20210205 */
		/* DOGFOOT syjin ????????? ?????? ?????? ??????(JAVA,R) ?????? ?????? 20210219 */
		if(analUseType == 0) {//R
			result.put("filteredData", reportService.getTimeSeriesRForecast(filteredDataList, measureInfoList, seriesDimensionInfoList, params,  1));
		}else {
			result.put("filteredData", reportService.getTimeSeriesForecast(filteredDataList, measureInfoList, seriesDimensionInfoList, params,  1));
		}
		
		/* DOGFOOT yhkim ???????????? ?????? ?????? 20201123 */
		result.put("p", params.get("pOrder"));
		result.put("d", params.get("dOrder"));
		result.put("q", params.get("qOrder"));
		
		return result;
	}
	
	@RequestMapping(value = {"/sparkTest.do"}, method = RequestMethod.GET)
	public @ResponseBody JSONObject sparkTest(HttpServletRequest request, HttpServletResponse response, Model model) {
		JSONObject result = new JSONObject();

		try {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
				
			SparkSession spark = this.sparkLoad.sparkSession();
			
			Dataset<org.apache.spark.sql.Row> df1 = spark.read()
			  .format("jdbc")
			  .option("url", "jdbc:sqlserver://169.56.81.21:1433;DatabaseName=VISUAL_DATA")
			  .option("driver", "com.microsoft.sqlserver.jdbc.SQLServerDriver")
			  .option("dbtable", "F_?????????_????????????")
			  .option("user", "wise")
			  .option("password", "dnltpdemo1012!@#$")
			  .load();
			df1.createOrReplaceTempView("`f_?????????_????????????`");

			Dataset<org.apache.spark.sql.Row> df2 = spark.read()
			  .format("jdbc")
			  .option("url", "jdbc:mysql://169.56.72.6:3306/WISEMART")
			  .option("driver", "org.mariadb.jdbc.Driver")
			  .option("dbtable", "D_???????????????")
			  .option("user", "wisemart")
			  .option("password", "wisemart")
			  .load();
			df2.createOrReplaceTempView("`D_???????????????`");
			
			String sql = "SELECT `D_???????????????`.`????????????`,sum(`F_?????????_????????????`.`??????`) "
					+ "FROM `F_?????????_????????????` JOIN `D_???????????????` ON `F_?????????_????????????`.`?????????` = `D_???????????????`.`???????????????` "
					+ "GROUP BY `D_???????????????`.`????????????` "
					+ "HAVING sum(`F_?????????_????????????`.`??????`) > 1000";
			SQLContext sqlContext = new SQLContext(spark);
			Dataset<org.apache.spark.sql.Row> df3 = sqlContext.sql(sql);

			List list = new ArrayList<>(); 
			for(String str:df3.toJSON().collectAsList()) {
				list.add(JSONObject.fromObject(JSONSerializer.toJSON(str)));
			}
			result.put("data", JSONArray.fromObject(list));
			result.put("status", 200);
		} catch (Exception e) {
			e.printStackTrace();
			result = new JSONObject();
			result.put("status", 500);
		}

		return result;
	} 		
	
	@RequestMapping(value = {"/restoreReport.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject restoreReport(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		try {
			String reportId = SecureUtils.getParameter(request, "reportId");
			String reportSeq = SecureUtils.getParameter(request, "reportSeq");
		
			this.reportService.updateReportMstrHis(reportId, reportSeq);
			
			returnObj.put("status", 200);
		} catch (Exception e) {
			e.printStackTrace();
			returnObj = new JSONObject();
			returnObj.put("status", 500);
		}
		
		return returnObj;
	}
	
	@RequestMapping(value = {"/restoreReportAs.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject restoreReportAs(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		try {
			String reportMeta = SecureUtils.unsecure(SecureUtils.getParameter(request, "JSON_REPORT"));
			if(reportMeta != null) {
				org.json.JSONObject obj = new org.json.JSONObject(reportMeta);
				
				/* DOGFOOT ktkang ????????? ???????????? ?????? ??????  20201126 */
				int reportId = 0;
				if(obj.getString("report_id").isEmpty() == false) {
					reportId = Integer.parseInt(obj.getString("report_id"));
				}
				
				ReportMasterHisVO reportMstrHis = this.reportService.selectReportHis(Integer.parseInt(obj.getString("old_report_id")), Integer.parseInt(obj.getString("reportSeq")));
				
				this.reportService.callUpReportMstrACT2(obj, reportMstrHis);
			}
			returnObj.put("status", 200);
		} catch (Exception e) {
			e.printStackTrace();
			returnObj = new JSONObject();
			returnObj.put("status", 500);
		}
		
		return returnObj;
	}
	
	@RequestMapping(value = {"/updateReportLog.do"}, method = RequestMethod.POST)
	public void updateReportLog(HttpServletRequest request, HttpServletResponse response, Model model) {
		boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
		String logSeq = SecureUtils.getParameter(request, "logSeq");
		String status = SecureUtils.getParameter(request, "status");
        if(logUse) {
        	Timer timer = new Timer();
        	timer.start();
        	Timestamp queryEndTimestamp = Timer.formatTime(timer.getStartTime());
			
			ReportLogMasterVO vo = new ReportLogMasterVO();
			vo.setLOG_SEQ(logSeq);
			vo.setED_DT(queryEndTimestamp);
			vo.setSTATUS_CD(status);
			
			if (logUse) {
				this.reportService.updateReportUseLog(logUse, vo);
			}
        }
	}
	
	/* goyong ktkang ???????????? ?????? ??????????????? ??????  20210603 */
	@RequestMapping(value = {"/insertReportLog.do"}, method = RequestMethod.POST)
	public void insertReportLog(HttpServletRequest request, HttpServletResponse response, Model model) {
		boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
		String reportTime = "";
		String logReportType = "";
        if(logUse) {
        	Timer timer = new Timer();
        	timer.start();
        	Timestamp queryEndTimestamp = Timer.formatTime(timer.getStartTime());
        	
        	boolean sessionCheck = Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication.viewer.session.check", false);
        	User user = new User();
        	if(sessionCheck) {
	        	user = this.authenticationService.getSessionUser(request);
        	} else {
        		String userId = SecureUtils.getParameter(request, "userId");
        		user = this.authenticationService.getRepositoryUser(userId);
        	}
        	
            int reportId = Integer.parseInt(SecureUtils.getParameter(request, "reportId"));
            String reportType = SecureUtils.getParameter(request, "reportType");
            String reportName = SecureUtils.getParameter(request, "reportName");
			
        	ReportLogMasterVO logVO = new ReportLogMasterVO();
        	
        	if(reportType.equals("DashAny")) {
        		logReportType = "DashAny";
        	} else if(reportType.equals("AdHoc")){
        		logReportType = "AdHoc";
        	} else if(reportType.equals("StaticAnal")){ /*dogfoot ?????? ?????? ?????? shlim 20201102*/
        		logReportType = "StaticAnal";
        	} else if(reportType.equals("DSViewer")){ /*dogfoot ???????????? ?????? ?????? ajkim 20210511*/
        		logReportType = "DSViewer";
        	} else {
        		logReportType = "Excel";
        	}

        	String ip = (String) request.getSession(false).getAttribute("IP_ADDRESS");
        	logVO.setReportUseLog(String.valueOf(Timer.formatTime(timer.getStartTime())),reportId,reportName,logReportType,user.getUSER_ID(),user.getUSER_NM(),user.getUSER_NO(),user.getGRP_ID(),""/*user.getGrpnm()*/,ip,Timer.formatTime(timer.getStartTime()),Timer.formatTime(0),"50","WB");
        	reportTime = String.valueOf(Timer.formatTime(timer.getStartTime()));
        	this.reportService.enrollReportUseLog(logUse,logVO);
        }
	}
	
	/* DOGFOOT ktkang ?????? ?????? ?????? ?????? ??????  20200922 */
	@RequestMapping(value = {"/selectReportWorks.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject selectReportWorks(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		try {
			int reportWorks = this.reportService.selectReportWorks();
			returnObj.put("works", reportWorks);
		} catch (Exception e) {
			e.printStackTrace();
			returnObj = new JSONObject();
			returnObj.put("works", 0);
		}
		
		return returnObj;
	}
	
	/* DOGFOOT ktkang BMT ????????? ?????? ??????  20201203 */
	@RequestMapping(value = {"/selectCubeGroupingData.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject selectCubeGroupingData(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		try {
			String cubeId = SecureUtils.getParameter(request, "cubeId");
			
			List<DSViewColVO> cubeGroupingDataList = this.reportService.selectCubeGroupingData(Integer.parseInt(cubeId));
			List<CubeHieMasterVO> cubeGroupingTblList = this.reportService.selectCubeGroupingTblList(Integer.parseInt(cubeId));
			List<String> cubeGroupingTblList2 = new ArrayList<String>();
			List<String> cubeGroupingColList = new ArrayList<String>();
			for(CubeHieMasterVO groupingTbl : cubeGroupingTblList) {
				String replaceTblName = groupingTbl.getDIM_UNI_NM().replace("[", "").replace("]", "");
				if(!cubeGroupingTblList2.contains(replaceTblName)) {
					cubeGroupingTblList2.add(replaceTblName);
				}
				cubeGroupingColList.add(groupingTbl.getHIE_CAPTION());
			}
			
			returnObj.put("groupingDataList", cubeGroupingDataList);
			returnObj.put("groupingTblList", cubeGroupingTblList2);
			returnObj.put("groupingColList", cubeGroupingColList);
		} catch (Exception e) {
			e.printStackTrace();
			returnObj = new JSONObject();
			returnObj.put("groupingDataList", 0);
			returnObj.put("groupingTblList", 0);
			returnObj.put("groupingColList", 0);
		}
		
		return returnObj;
	}
	
	@RequestMapping(value = {"/saveCubeGroupingData.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject saveCubeGroupingData(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		try {
			JSONArray groupingDataList = JSONArray.fromObject(request.getParameter("groupingDataList"));
			String cubeId = SecureUtils.getParameter(request, "cubeId");
			String dsViewId = SecureUtils.getParameter(request, "dsViewId");
			if(dsViewId.equals("0")) {
				CubeMember cubeInfo = this.reportService.selectCubeMasterInformation(Integer.parseInt(cubeId));
				dsViewId = String.valueOf(cubeInfo.getDsViewId());
			}
			
			this.reportService.deleteDsViewColMstr(Integer.parseInt(dsViewId));
			this.reportService.deleteDsViewHieMstr(Integer.parseInt(dsViewId));
			this.reportService.deleteCubeHieMstr(Integer.parseInt(cubeId));
			
			int maxColId = this.reportService.selectMaxColId();
			for(int i = 0; i < groupingDataList.size(); i++) {
				org.json.JSONObject obj = new org.json.JSONObject(groupingDataList.get(i).toString());
				this.reportService.insertDsViewColMstr(obj, i, maxColId + i, Integer.parseInt(dsViewId));
				this.reportService.insertDsViewHieMstr(obj, i, Integer.parseInt(dsViewId));
				this.reportService.insertCubeHieMstr(obj, i, Integer.parseInt(cubeId));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return returnObj;
	}
	
	@RequestMapping(value = {"/selectCubeGroupingDimList.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject selectCubeGroupingDimList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		try {
			String cubeId = SecureUtils.getParameter(request, "cubeId");
			String selectTableName = SecureUtils.getParameter(request, "selectTableName");
			selectTableName = "[" + selectTableName + "]";
			
			List<CubeHieMasterVO> cubeGroupingTblList = this.reportService.selectCubeGroupingDimList(cubeId, selectTableName);
			for(CubeHieMasterVO cubeHie : cubeGroupingTblList) {
				String a = cubeHie.getHIE_UNI_NM();
				String[] uniName = a.split("\\.");
				String hieUniName = uniName[1].replace("[", "").replace("]", "");
				cubeHie.setHIE_HIE_UNI_NM(hieUniName);
			}
			
			returnObj.put("groupingTblList", cubeGroupingTblList);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return returnObj;
	}
	
//	@RequestMapping(value = {"/importFileDataToSpark.do"}, method = RequestMethod.GET)
//	public void importFileDataToSpark(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
//		JSONObject returnObj = new JSONObject();
//		JSONArray ret = new JSONArray();
//		try {
//			SparkSession spark = sparkLoad.sparkSession();
//			
//			Dataset<org.apache.spark.sql.Row> data = spark.read().option("header", true).csv("../Develop/wise.rnd.ds.1/WebContent/UploadFiles/newReport_????????? 1.csv");
//			
//			data.createOrReplaceTempView("`newReport_????????? 1`");
//			data.persist(StorageLevel.MEMORY_AND_DISK_2());
//			
//			SQLContext sqlContext = new SQLContext(spark); 
//			Dataset<org.apache.spark.sql.Row> dfRes = sqlContext.sql("select * from `newReport_????????? 1`");
//			
//			
//			List<JSONObject> list = new ArrayList<JSONObject>(); 
//			for(String str:dfRes.toJSON().collectAsList()) {
//				list.add(JSONObject.fromObject(JSONSerializer.toJSON(str)));
//			}
//			ret = JSONArray.fromObject(list);
//		} catch (Exception e) {
//			e.printStackTrace();
//		}		
//	}
	
	/* DOGFOOT shlim reportmstr dsid ??????  20200309 */
 	@RequestMapping(value = {"/replacedsid.do"})
    public void replacedsid(HttpServletRequest request) throws Exception {
 		String before_dsid = request.getParameter("before_dsid");
 		String after_dsid = request.getParameter("after_dsid");
// 		String report_id = SecureUtils.getParameter(request, "report_id");
// 		String before_dsid = SecureUtils.getParameter(request, "before_dsid");
// 		String after_dsid = SecureUtils.getParameter(request, "after_dsid");
 		
 		File file = new File("C:\\Users\\user\\Desktop\\reportId.txt");
 		try (FileReader filereader = new FileReader(file); BufferedReader bufReader = new BufferedReader(filereader)) {
            String reportId = "";
            while((reportId = bufReader.readLine()) != null){
            	System.out.println(reportId);
            	if (reportId != null && reportId.length() > 0) {
            		ReportMasterVO reportXmlVal = this.reportService.selectReportParamXmlList(Integer.parseInt(reportId));
            		String encoding = Configurator.getInstance().getConfig("encoding");
            		if(reportXmlVal != null) {
            			String DATASET_XML = new String(Base64.decode(reportXmlVal.getDECODE_DATASET().getBytes()), encoding);
            			String PARAM_XML = new String(Base64.decode(reportXmlVal.getDECODE_PARAM().getBytes()), encoding);
    
            			int countreP = 0;
            			if(before_dsid != null && after_dsid != null) {
            				if(before_dsid.length() > 0 && after_dsid.length() > 0) {
            					if(DATASET_XML.contains("<DS_ID>"+before_dsid)) {
            						DATASET_XML = DATASET_XML.replaceAll("<DS_ID>"+before_dsid, "<DS_ID>"+after_dsid);
            						countreP++;
            					}
            					if(DATASET_XML.contains("DS_ID&gt;"+before_dsid)){
            						DATASET_XML = DATASET_XML.replaceAll("DS_ID&gt;"+before_dsid,"DS_ID&gt;"+after_dsid);
            						countreP++;
            					}
            					if(PARAM_XML.contains("<DS_ID>"+before_dsid)){
            						PARAM_XML = PARAM_XML.replaceAll("<DS_ID>"+before_dsid,"<DS_ID>"+after_dsid);
            						countreP++;
            					}
            				}
            			}
            			if(countreP>0) {
            				//         		 		String parmmm = new String(java.util.Base64.getEncoder().encode(DATASET_XML.getBytes()));
    
            				ReportMasterVO updateReportXmlVal = new ReportMasterVO();
            				updateReportXmlVal.setDECODE_DATASET(new String(java.util.Base64.getEncoder().encode(DATASET_XML.getBytes())));
            				updateReportXmlVal.setDECODE_PARAM(new String(java.util.Base64.getEncoder().encode(PARAM_XML.getBytes())));
            				updateReportXmlVal.setDECODE_REPORT_ID(Integer.parseInt(reportId));
    
            				this.reportService.updateReportDatasetParam(updateReportXmlVal);
            			}
            		}
            	}
            }
		}
	}
 	
 	
// 	@RequestMapping(value = {"/selectdeltatype.do"})
//    public void selectdeltatype(HttpServletRequest request) throws Exception {
// 		
// 		try {
//            String reportId = "";
//            List<ReportMasterVO> reportIdList = this.reportService.selectReportIdGoyongList();
//            System.out.println("search start. ");
//            for(ReportMasterVO rep : reportIdList) {
//            	
//            		String encoding = Configurator.getInstance().getConfig("encoding");
//            		if(rep != null) {
////            			String DATASET_XML = new String(Base64.decode(reportXmlVal.getDECODE_DATASET().getBytes()), encoding);
////            			String PARAM_XML = new String(Base64.decode(reportXmlVal.getDECODE_PARAM().getBytes()), encoding);
//            			String REPORT_XML = new String(Base64.decode(rep.getDECODE_REPORT().getBytes()), encoding);
//            			int countreP = 0;
//            			String deltaValueName = "";
//            			String deltaValue = "";
//            			if(REPORT_XML != null){
////            				if(REPORT_XML.indexOf("<DELTA_VALUE_TYPE>") > -1) {
////            					while(REPORT_XML.indexOf("<DELTA_VALUE_TYPE>") > -1) {
////            						deltaValue = REPORT_XML.substring(REPORT_XML.indexOf("<DELTA_VALUE_TYPE>"), REPORT_XML.indexOf("</DELTA_VALUE_TYPE>")+19);	
////            						System.out.println("reportId / deltaValue : "+rep.getREPORT_ID()+ " / " + rep.getREPORT_NM() + " / " + deltaValue);
////            						REPORT_XML = REPORT_XML.substring(REPORT_XML.indexOf("</DELTA_VALUE_TYPE>")+19 , REPORT_XML.length());
////            					}
////            				}
//            				if(REPORT_XML.indexOf("<SUMMARY_TYPE>") > -1) {
//            					while(REPORT_XML.indexOf("<SUMMARY_TYPE>") > -1) {
//            						deltaValueName = REPORT_XML.substring(REPORT_XML.indexOf("<FLD_NM>"), REPORT_XML.indexOf("</FLD_NM>")+9);
//            						deltaValue = REPORT_XML.substring(REPORT_XML.indexOf("<SUMMARY_TYPE>"), REPORT_XML.indexOf("</SUMMARY_TYPE>")+15);
//            						
//            						if(deltaValue.indexOf("1") == -1) {
//            							System.out.println("reportId / deltaValue : "+rep.getREPORT_ID()+ " / " + rep.getREPORT_NM() + " / " + deltaValueName + " / " + deltaValue);
//            						}
//            						
//            						
//            						REPORT_XML = REPORT_XML.substring(REPORT_XML.indexOf("</SUMMARY_TYPE>")+15 , REPORT_XML.length());
//            					}
//            				}
//	            		}
//	            	}
//            }
//		} finally {
//			System.out.println("search end. ");
//		}
// 	}
 	
 	/*
	 2021-08-17 yyb ??????????????? RemoteOperation ?????? 
	*/
	@RequestMapping(value = {"/remoteRenderPivotGrid.do"})
	public void remoteRenderPivotGrid(HttpServletResponse response, HttpServletRequest request,
			@RequestParam Map<String, Object> allParameters) {
		
		response.setContentType("application/json");
		response.setCharacterEncoding("utf-8");

       FilterParam rootFilter = null;
       List<UdfGroupParam> udfGroupParams = null;
       List<GroupParam> groupParams = null;
       List<SummaryParam> groupSummaryParams = null;
       List<SummaryParam> totalSummaryParams = null;
       PagingParam pagingParam = null;
       List<SortInfoParam> sortInfoParams = null;
       TopBottomParam topBottomParam = null;

       ServletOutputStream sos = null;
       BufferedOutputStream bos = null;
       JsonGenerator gen = null;

       try {
           // ???????????? ??????
           int take = allParameters.get("take") == null ? -1
                   : NumberUtils.toInt(allParameters.get("take").toString());
           int skip = allParameters.get("skip") == null ? -1
                   : NumberUtils.toInt(allParameters.get("skip").toString());

           String filter = allParameters.get("filter").toString();
           String udfGroups = allParameters.get("udfGroups").toString();
           String group = allParameters.get("group").toString();
           String groupSummary = allParameters.get("groupSummary").toString();
           String totalSummary = allParameters.get("totalSummary").toString();
           String paging = allParameters.get("paging").toString();
           String useWithQueryParam = allParameters.containsKey("useWithQuery")? allParameters.get("useWithQuery").toString() : "Y";

           String sortInfo = allParameters.get("sortInfo").toString();
           String topBottom = allParameters.get("topBottom").toString();
           String sqlLikeOption = allParameters.get("sqlLikeOption").toString();

           // String[] arrColNames = (String[])allParameters.get("columnNames[]");
           
           final boolean useWithQuery = useWithQueryParam.equals("Y")? true : false;

           final ArrayNode filterParamsNode = StringUtils.isNotBlank(filter)
                   ? (ArrayNode) objectMapper.readTree(filter) : null;
           rootFilter = ParamUtils.toFilterParam(filterParamsNode);

           final ArrayNode udfGroupParamsNode = StringUtils.isNotBlank(udfGroups)
                   ? (ArrayNode) objectMapper.readTree(udfGroups) : null;
           udfGroupParams = ParamUtils.toUdfGroupParams(objectMapper, udfGroupParamsNode);

           final ArrayNode groupParamsNode = StringUtils.isNotBlank(group)
                   ? (ArrayNode) objectMapper.readTree(group) : null;
           groupParams = ParamUtils.toGroupParams(objectMapper, groupParamsNode);

           final ArrayNode groupSummaryParamsNode = StringUtils.isNotBlank(groupSummary)
                   ? (ArrayNode) objectMapper.readTree(groupSummary) : null;
           groupSummaryParams = ParamUtils.toSummaryParams(objectMapper, groupSummaryParamsNode);

           final ArrayNode totalSummaryParamsNode = StringUtils.isNotBlank(totalSummary)
                   ? (ArrayNode) objectMapper.readTree(totalSummary) : null;
           totalSummaryParams = ParamUtils.toSummaryParams(objectMapper, totalSummaryParamsNode);

           final ObjectNode pagingParamNode = StringUtils.isNotBlank(paging)
                   ? (ObjectNode) objectMapper.readTree(paging) : null;
           pagingParam = ParamUtils.toPagingParam(objectMapper, pagingParamNode);

           final ArrayNode sortInfoParamsNode = StringUtils.isNotBlank(sortInfo)
                   ? (ArrayNode) objectMapper.readTree(sortInfo) : null;
           sortInfoParams = ParamUtils.toSortInfoParams(objectMapper, sortInfoParamsNode);

           final ObjectNode topBottomParamNode = StringUtils.isNotBlank(topBottom)
                   ? (ObjectNode) objectMapper.readTree(topBottom) : null;
           topBottomParam = ParamUtils.toTopBottomParam(objectMapper, topBottomParamNode);

			// ????????? - ?????? ?????? ??????  20210913
           final CloseableList<JSONObject> dataArray = this.dataSetServiceImpl.executeSqlLike(sqlLikeOption, useWithQuery, request);
           final List<String> colNames = dataArray != null && dataArray.size() > 0
                   ? new ArrayList<>(dataArray.get(0).keySet())
                   : Collections.emptyList();
                   
           sos = response.getOutputStream();
           bos = new BufferedOutputStream(sos);
           gen = objectMapper.createGenerator(bos);
            
           // ???????????? ???????????? DataFrame ??????
           final DataFrame dataFrame = new JSONArrayDataFrame(dataArray, colNames.toArray(new String[colNames.size()]));
           
           // ?????????????????? ???????????? ????????? Summary ??????
           if (!groupParams.isEmpty()) {
               logger.debug("Group aggregation data request invoked. filter: " + filter
                       + ", udfGroups: " + udfGroups + ", group: " + group + ", groupSummary: "
                       + groupSummary + ", totalSummary: " + totalSummary + ", paging: " + paging
                       + ", sortInfo: " + sortInfo + ", topBottom: " + topBottom
                       + ", sqlLikeOption: " + sqlLikeOption);

               final WeakReference<DataAggregation> aggregation = dataAggregator.createDataAggregation(dataFrame,
                       rootFilter, udfGroupParams, groupParams, groupSummaryParams,
                       totalSummaryParams, pagingParam, sortInfoParams, topBottomParam);

               PivotGridJsonUtils.writeSummaryContainerToJson(gen, aggregation.get(), null, "data",
                       aggregation.get().getPaging(), aggregation.get().isPagingApplied(), new String(Base64.encode(dataArray.getAttribute("sql").toString().getBytes())));
           }
           
           
           // ???????????? ?????????????????????(dev?????? ????????? ??????????????? ??????) ?????? ????????? ????????? ??????(default: 20) 
           else {
           	logger.debug("Simple data request invoked. skip: {}, take: {}", skip, take);
               PivotGridJsonUtils.writeTabularDataToJson(gen, dataFrame, skip, take);
           }
	    	
   	}
   	catch (Exception e) {
   		logger.error("Failed to process data aggregation.", e);
   		response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
       }
		finally {
           IOUtils.closeQuietly(gen, bos, sos);
       }
	}
	
	@RequestMapping(value = { "/pivotSummaryMatrix.do" })
    public void pivotSummaryMatrix(HttpServletResponse response, HttpServletRequest request,
            @RequestParam Map<String, Object> allParameters) {
		try(WdcTask task = WDC.getCurrentTask().startSubtask("pivotSummaryMatrix")){
			internalPivotSummaryMatrix(response, request, allParameters);
		}
	}
	

    private void internalPivotSummaryMatrix(HttpServletResponse response, HttpServletRequest request,
            Map<String, Object> allParameters) {

        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");

        ServletOutputStream sos = null;
        BufferedOutputStream bos = null;
        JsonGenerator gen = null;

        try {
            final String pagingParamValue = allParameters.get("paging").toString();
            final ObjectNode pagingParamNode = StringUtils.isNotBlank(pagingParamValue)
                    ? (ObjectNode) objectMapper.readTree(pagingParamValue) : null;
            final PagingParam pagingParam = ParamUtils.toPagingParam(objectMapper, pagingParamNode);

            SummaryMatrix matrix = summaryMatrixProvider.getPivotSummaryMatrix(request, allParameters, pagingParam, new QueryExecutor() {
         	   @Override
         	   public CloseableList<JSONObject> execute(String sqlLikeOption, boolean useWithQuery) throws Exception {
         		   return dataSetServiceImpl.executeSqlLike(sqlLikeOption, useWithQuery, request);
         	   }
            }).get();

            sos = response.getOutputStream();
            bos = new BufferedOutputStream(sos);
            gen = objectMapper.createGenerator(bos);

            if (matrix == null) {
                gen.writeStartObject();
                gen.writeEndObject();
                return;
            }

            final Paging paging = new Paging();
            paging.setOffset(pagingParam.getOffset());
            paging.setLimit(pagingParam.getLimit());

            final SummaryMatrix pagedMatrix = SummaryMatrixFactory.slicePageSummaryMatrix(matrix,
                    paging).get();
            pagedMatrix.setAttributes(matrix.getAttributes());

            SummaryMatrixUtils.writeSummaryMatrixToJson(gen, paging, pagedMatrix);
        }
        catch (Exception e) {
            logger.error("Failed to process summary matrix.", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
        finally {
            IOUtils.closeQuietly(gen, bos, sos);
        }
    }
    
    
    @RequestMapping(value = {"/getdwwd.do"})
    private String requestPageView() throws Exception {
        
    	return "edit.do?assign_name=bWVpcw==&USER=%2BzN9U1F9PSvngTd7oONJcQ%3D%3D";
    }
    
    @RequestMapping(value = {"/getencodedUrl.do"})
	public @ResponseBody JSONObject getencodedUrl(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONObject returnObj = new JSONObject();
		try {
			
			String encodedUrl = URLEncoder.encode("+zN9U1F9PSvngTd7oONJcQ==", "UTF-8");
			
			returnObj.put("encodedUrl", "edit.do?assign_name=bWVpcw==&USER="+encodedUrl);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return returnObj;
	}
}
