package com.wise.ds.repository.controller;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.management.ManagementFactory;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.JSONException;
import org.json.XML;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import com.wise.authn.ConfigMasterVO;
import com.wise.authn.DataSourceGRPVO;
import com.wise.authn.DataSourceUserVO;
import com.wise.authn.DataSourceVO;
import com.wise.authn.User;
import com.wise.authn.UserGroupVO;
import com.wise.authn.UserSessionVO;
import com.wise.authn.WebConfigMasterVO;
import com.wise.authn.WiseSessionListener;
import com.wise.authn.service.AuthenticationService;
import com.wise.common.message.AjaxMessageConverter;
import com.wise.common.secure.SecureUtils;
import com.wise.common.util.Timer;
import com.wise.context.config.Configurator;
import com.wise.ds.repository.AnalysisLogVO;
import com.wise.ds.repository.AuthReportVO;
import com.wise.ds.repository.CubeTableVO;
import com.wise.ds.repository.CubeVO;
import com.wise.ds.repository.CurrentSqlVO;
import com.wise.ds.repository.DSViewDimVO;
import com.wise.ds.repository.DSViewHieVO;
import com.wise.ds.repository.DSViewVO;
import com.wise.ds.repository.DashLoginOutMasterVO;
import com.wise.ds.repository.DashReportMasterVO;
import com.wise.ds.repository.DataSetInfoMasterVO;
import com.wise.ds.repository.DataSetInfoVO;
import com.wise.ds.repository.ExportLogVO;
import com.wise.ds.repository.FolderMasterVO;
import com.wise.ds.repository.GrpAuthDataSetVO;
import com.wise.ds.repository.GrpListVO;
import com.wise.ds.repository.InsertGroupAuthDataSetVO;
import com.wise.ds.repository.InsertUserAuthDataSetVO;
import com.wise.ds.repository.JobListVO;
import com.wise.ds.repository.LogParamVO;
import com.wise.ds.repository.PublicFolderListVO;
import com.wise.ds.repository.QueryLogVO;
import com.wise.ds.repository.ReportListMasterVO;
import com.wise.ds.repository.ReportMasterVO;
import com.wise.ds.repository.SameTimeConVO;
import com.wise.ds.repository.SessionParamVO;
import com.wise.ds.repository.SubjectCubeMasterVO;
import com.wise.ds.repository.SubjectMasterVO;
import com.wise.ds.repository.UserAuthDataSetVO;
import com.wise.ds.repository.UserConfigVO;
import com.wise.ds.repository.UserGrpAuthReportListVO;
import com.wise.ds.repository.service.ConfigService;
import com.wise.ds.repository.service.DataSetService;
import com.wise.ds.repository.service.ReportService;
import com.wise.ds.util.Json2Xml;
import com.wise.ds.util.WiseResource;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

@Controller
@RequestMapping(value = "/report")
public class ConfigController {

	@Resource(name = "configService")
    private ConfigService configService;

	@Resource(name = "authenticationService")
	private AuthenticationService authenticationService;

	@Resource(name = "reportService")
	private ReportService reportService;

	@Resource(name = "dataSetService")
	private DataSetService dataSetService;

    /*
     * CONFIG VIEWS
     */
	//2020.12.21 syjin 환경 설정 원본 추가 layout 추가
	@RequestMapping(value = {"/datasource.do"})
    public String loadDataSourceLayout(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	return "config/dataSource";
    }

    @RequestMapping(value = {"/usergroup.do"})
    public String loadUserGroupLayout(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	return "config/userGroup";
    }

    @RequestMapping(value = {"/monitoring.do"})
    public String loadMonitoringLayout(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	return "config/monitoring";
    }

	@RequestMapping(value = {"/auth.do"})
	public String loadAuthenticationLayout(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		return "config/auth";
	}

	@RequestMapping(value = {"/preferences.do"})
    public String loadPreferencesLayout(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	return "config/generalConfig";
    }

	@RequestMapping(value = {"/log.do"})
	public String loadLogLayout(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		return "config/log";
	}

	@RequestMapping(value = {"/reportfolder.do"})
	public String loadReportFolderLayout(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		return "config/reportFolder";
	}

	@RequestMapping(value = {"/configSession.do"})
	public String loadconfigSessionLayout(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		return "config/session";
	}

	@RequestMapping(value = {"/addDataSetlist.do"})
	public String loadconfigaddDataSetlistLayout(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		return "config/addDataSet";
	}

	/**
	 * Returns current user session.
	 * @param request Current http request containing user session
	 * @return User object stored in session
	 */
	private User getSessionUser(HttpServletRequest request) {
        String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
        String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
        String sessionUserKey = SESSINO_USER_PREFIX + authnKey;

        HttpSession session = request.getSession(false);
        if (session == null) {
        	return null;
        }
        return (User) session.getAttribute(sessionUserKey);
    }

	/**
	 * Updates user info stored on a user's HttpSession.
	 * @param request Current http request containing user session
	 */
	private void updateSessionUser(HttpServletRequest request) {
        String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
        String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
        String sessionUserKey = SESSINO_USER_PREFIX + authnKey;

        HttpSession session = request.getSession(false);
        if (session != null) {
        	User sessionUser = (User) session.getAttribute(sessionUserKey);
	        User updatedSessionUser = authenticationService.selectUserByNo(sessionUser.getUSER_NO());
	        session.setAttribute(sessionUserKey, updatedSessionUser);
        }

    }

	/*
	 * CONFIG MONITORING SERVICES
	 */
	@RequestMapping("/getSystemProperty.do")
	public @ResponseBody void getSystemProperty(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		WiseResource wiseResource = new WiseResource();
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject obj = wiseResource.showOS();
		out.print(obj);
		return;
	}

	@RequestMapping("/getJobList.do")
	public void getJobList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		ArrayList<JSONObject> jobs = new ArrayList<JSONObject>();
		List<JobListVO> jobList = configService.selectJobListMaster();

		SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String str = f.format(new Date());
		Date d1 = f.parse(str);


		for (JobListVO JobListVO : jobList) {
			Date d2 = f.parse(JobListVO.getST_DT());
			long diff = d1.getTime() - d2.getTime();
			long sec = diff / 1000;
			int second = Integer.parseInt(String.valueOf(sec));

			int hour = (second) / (60 * 60);
			int minute = (second - hour * 3600) / 60;
			int second2 = second % 60;

			String secon;
			if(second2 < 0) {
				secon = "0";
			} else if(String.valueOf(second2).length() == 1) {
				secon = "0" + String.valueOf(second2);
			} else {
				secon = String.valueOf(second2);
			}

			String minu;
			if(String.valueOf(minute).length() == 1) {
				minu = "0" + String.valueOf(minute);
			} else {
				minu = String.valueOf(minute);
			}

			JSONObject job = new JSONObject();
			/* DOGFOOT ktkang 모니터링 부분 기능 추가  20201014 */
			job.put("seq", JobListVO.getLOG_SEQ());
			job.put("보고서 아이디", JobListVO.getREPORT_ID());
			job.put("보고서 이름", JobListVO.getREPORT_NM());
			job.put("사용자 ID", JobListVO.getUSER_ID());
			job.put("사용자 명", JobListVO.getUSER_NM());
			job.put("사용자 IP", JobListVO.getACCESS_IP());
			job.put("보고서 유형", JobListVO.getREPORT_TYPE());
			/* DOGFOOT ktkang 모니터링 프로세스 오류 수정  20200922 */
			job.put("작업 유형", JobListVO.getPROG_TYPE());
			job.put("경과 시간", hour + ":" + minu + ":" + secon);
			//job.put("상태 명", JobListVO.getSTATUS_CD());
			jobs.add(job);
		}
		JSONObject obj = new JSONObject();

		obj.put("jobResult", jobs);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getSameTimeConnection.do")
	public void getSameTimeConnection(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		ArrayList<JSONObject> sames = new ArrayList<JSONObject>();

		List<SameTimeConVO> sameTimeList = configService.selectSameTimeConMaster();

		for (SameTimeConVO SameTimeConVO : sameTimeList) {
			JSONObject same = new JSONObject();
			same.put("사용자 ID", SameTimeConVO.getUSER_ID());
			same.put("사용자 IP", SameTimeConVO.getACCESS_IP());
			same.put("로그 타입", SameTimeConVO.getLOG_TYPE());
			same.put("마지막 접속 시간", SameTimeConVO.getLAST_MSG_DT().substring(0, SameTimeConVO.getLAST_MSG_DT().indexOf(".")));
			sames.add(same);
		}

		JSONObject obj = new JSONObject();

		obj.put("sameResult", sames);
		out.print(obj);
		out.flush();
		out.close();
	}

	/*
	 * CONFIG USER & GROUP SERVICES
	 */
	@RequestMapping("/getGroupList.do")
	public void getGroupNames(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		ArrayList<JSONObject> groups = new ArrayList<JSONObject>();
		JSONObject obj = new JSONObject();
		try {
			out = response.getWriter();
			List<UserGroupVO> query = configService.selectGroupList();
			for (UserGroupVO userGroupVO : query) {
				JSONObject group = new JSONObject();
				group.put("id", userGroupVO.getGRP_ID());
				group.put("name", userGroupVO.getGRP_NM());
				group.put("runMode", userGroupVO.getGRP_RUN_MODE());
				group.put("desc", userGroupVO.getGRP_DESC());
				group.put("relCd", userGroupVO.getGRP_REL_CD());
				groups.add(group);
			}
			obj.put("groups", groups);
		} catch (IOException e) {
			e.printStackTrace();
			throw new Error(e);
		}finally {
			out.print(obj);
			out.flush();
			out.close();
		}

	}
	@RequestMapping("/getDataSourceList.do")
	public void getListOfDataSources(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		ArrayList<JSONObject> dataSources = new ArrayList<JSONObject>();

		// 관리자 페이지인데 권한이 있는것만 가져오면 안됨
//		User user = getSessionUser(request);
//
//		List<DataSourceUserVO> duv = configService.selectDataSourceUserList(user.getUSER_NO());;
//		List<DataSourceGRPVO> dgv = configService.selectDataSourceGRPList(user.getGRP_ID());

//		Set<Integer> dsIDSet = new HashSet<Integer>();
//
//		for(DataSourceUserVO da : duv) {
//			dsIDSet.add(da.getDS_ID());
//		}
//
//		for(DataSourceGRPVO da : dgv) {
//			dsIDSet.add(da.getDS_ID());
//		}

		List<Integer> ids = null; //new ArrayList<Integer>();
		//ids.addAll(dsIDSet);

		List<DataSourceVO> query = configService.selectDataSourceList(ids);

		for(DataSourceVO datasourceVO : query) {
			JSONObject datasource = new JSONObject();
			datasource.put("데이터 ID", datasourceVO.getDS_ID());
			datasource.put("데이터원본 명", datasourceVO.getDS_NM());
			datasource.put("서버주소 명", datasourceVO.getIP());
			datasource.put("DB 명", datasourceVO.getDB_NM());
			datasource.put("DB 유형", datasourceVO.getDBMS_TYPE());
			datasource.put("소유자", datasourceVO.getOWNER_NM());
			datasource.put("Port", datasourceVO.getPORT());
			datasource.put("접속 id", datasourceVO.getUSER_ID());
			datasource.put("접속 암호", datasourceVO.getPASSWD());
			datasource.put("접속 유형", datasourceVO.getCONN_TYPE());
			datasource.put("DATA", datasourceVO.getUSER_AREA_YN());
			datasource.put("USER NO", datasourceVO.getREG_USER_NO());

			dataSources.add(datasource);
		}

		JSONObject obj = new JSONObject();

		obj.put("datasources", dataSources);
		out.print(obj);
		out.flush();
		out.close();
	}
	@RequestMapping("/getUserList.do")
	public void getListOfUsers(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		ArrayList<JSONObject> users = new ArrayList<JSONObject>();

//		try {
			List<UserGroupVO> query = configService.selectUserListAndGroupName();
			
			for (UserGroupVO userGroupVO : query) {
				JSONObject user = new JSONObject();
				user.put("사용자 NO", userGroupVO.getUSER_NO());
				user.put("사용자 ID", userGroupVO.getUSER_ID());
				user.put("사용자 명", userGroupVO.getUSER_NM());
				user.put("그룹 ID", userGroupVO.getGRP_ID());
				user.put("그룹 명", userGroupVO.getGRP_NM());
				user.put("사용자 실행모드", userGroupVO.getUSER_RUN_MODE());
				user.put("그룹 실행모드", userGroupVO.getGRP_RUN_MODE());
				user.put("참조코드", userGroupVO.getUSER_REL_CD());
				user.put("설명", userGroupVO.getUSER_DESC());
				users.add(user);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();

		obj.put("users", users);
		out.print(obj);
		out.flush();
		out.close();
	}

	//2020.12.21 syjin 환경 설정 원본 추가 insert 설정
	@RequestMapping(value= {"/insertDatasourceInfo.do"}, method = RequestMethod.POST)
	public void insertDatasourceInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject obj = new JSONObject();

		String dsNm = SecureUtils.getParameter(request, "newDsNm");
		String dbNm = SecureUtils.getParameter(request, "newDbNm");
		String ip = SecureUtils.getParameter(request, "newIp");
		String userId = SecureUtils.getParameter(request, "newUserId");
		String passwd = SecureUtils.getParameter(request, "newPasswd");
		String port = SecureUtils.getParameter(request, "newPort");
		String dbmsType = SecureUtils.getParameter(request, "newDbmsType");
		String ownerNm = SecureUtils.getParameter(request, "newOwnerNm");
		String dsDesc = SecureUtils.getParameter(request, "newDsDesc");
		String dsConnstr = SecureUtils.getParameter(request, "newDsConnstr");
		String regDt = SecureUtils.getParameter(request, "newRegDt");
		//String regUserNo = SecureUtils.getParameter(request, "newRegUserNo");
		String updDt = SecureUtils.getParameter(request, "newUpdDt");
		//String updUserNo = SecureUtils.getParameter(request, "newUpdUserNo");
		String racip = SecureUtils.getParameter(request, "newRacip");
		String racport = SecureUtils.getParameter(request, "newRacport");
		String wfyn = SecureUtils.getParameter(request, "newWfyn");
		String userAreaYn = SecureUtils.getParameter(request, "newUserAreaYn");
		String connType = SecureUtils.getParameter(request, "newConnType");
		String hashYn = SecureUtils.getParameter(request, "newHashYn");

		connType = connType.equals("1001")? "" : connType;

		User user = getSessionUser(request);

		Timestamp currentTime = Timer.formatTime(System.currentTimeMillis());

		DataSourceVO datasource = new DataSourceVO();
		DataSourceUserVO datasourceUser = new DataSourceUserVO();

		datasource.setDS_NM(dsNm);
		datasource.setDB_NM(dbNm);
		datasource.setIP(ip);
		datasource.setUSER_ID(userId);
		datasource.setPASSWD(passwd);
		datasource.setPORT(port);
		datasource.setDBMS_TYPE(dbmsType);
		datasource.setOWNER_NM(ownerNm);
		datasource.setDS_DESC(dsDesc);
		switch(dbmsType) {
		case "ORACLE":
			if ("SID".equals(connType)) {
				dsConnstr = "jdbc:oracle:thin:@" + ip + ":" + port + ":" + dbNm;
			}
			else {
				dsConnstr = "jdbc:oracle:thin:@" + ip + ":" + port + "/" + dbNm;
			}
			break;
		case "MS-SQL":
			dsConnstr = "jdbc:sqlserver://" + ip + ":" + port + ";DatabaseName=" + dbNm;
			break;
		case "TIBERO":
			dsConnstr = "jdbc:tibero:thin:@" + ip + ":" + port + ":" + dbNm;
			break;
		case "TBIN":
			dsConnstr = "jdbc:tibero:thin:@" + ip + ":" + port + ":" + dbNm;
			break;
		case "VERTICA":
			dsConnstr = "jdbc:vertica://" + ip + ":" + port + "/" + dbNm;
			break;
		case "MSPDW":
			dsConnstr = "jdbc:sqlserver://" + ip + ":" + port + ";DatabaseName=" + dbNm;
			break;
		case "MYSQL":
			dsConnstr = "jdbc:mysql://" + ip + ":" + port + "/" + dbNm;
			break;
		case "MARIA":
			dsConnstr = "jdbc:mariadb://" + ip + ":" + port + "/" + dbNm;
			break;
		case "MYIDM":
			dsConnstr = "jdbc:mysql://" + ip + ":" + port + "/" + dbNm;
			break;
		case "DB2BLU":
			dsConnstr = "jdbc:db2://" + ip + ":" + port + "/" + dbNm;
			break;
		case "PETASQL":
			dsConnstr = "jdbc:db2://" + ip + ":" + port + "/" + dbNm;
			break;
		case "POSTGRES":
			dsConnstr = "jdbc:postgresql://" + ip + ":" + port + "/" + dbNm;
			break;
		case "NETEZZA":
			dsConnstr = "jdbc:netezza://" + ip + ":" + port + "/" + dbNm;
			break;
		case "SAPIO":
			dsConnstr = "jdbc:sybase:Tds:" + ip + ":" + port + "/" + dbNm;
			break;
		case "SAPASE":
			dsConnstr = "jdbc:sybase:Tds:" + ip + ":" + port + "/" + dbNm;
			break;
		case "CUBRID":
			dsConnstr = "jdbc:cubrid:" + ip + ":" + port + ":" + dbNm + ":dba::";
			break;
		case "ALTIBASE":
			dsConnstr = "jdbc:Altibase://" + ip + ":" + port + "/" + dbNm;
			break;
		case "GOLDILOCKS":
			dsConnstr = "jdbc:goldilocks://" + ip + ":" + port + "/" + dbNm;
			break;
		case "TERADATA":
			dsConnstr = "jdbc:teradata://" + ip + "/DATABASE=" + dbNm + ",DBS_PORT=" + port + ",CHARSET=UTF8,TMODE=ANSI,ENCRYPTDATA=ON";
			break;
		case "IMPALA":
			dsConnstr = "jdbc:impala://" + ip + ":" + port + "/" + dbNm;
			break;
		}
		datasource.setDS_CONNSTR(dsConnstr);
		datasource.setREG_DT(currentTime);
		datasource.setREG_USER_NO(user.getUSER_NO());
		datasource.setUPD_DT(currentTime);
		datasource.setUPD_USER_NO(user.getUSER_NO());
		datasource.setRACIP(racip);
		datasource.setRACPORT(racport);
		datasource.setWF_YN(wfyn);
		datasource.setUSER_AREA_YN(userAreaYn);
		datasource.setCONN_TYPE(connType);
		datasource.setHASH_YN(hashYn);

		ArrayList<JSONObject> datasources = new ArrayList<JSONObject>();

		configService.insertNewDatasource(datasource);

		int dsID = datasource.getDS_ID();

		if(dsID>0) {
//			datasourceUser.setDS_ID(dsID);
//			datasourceUser.setUSER_NO(user.getUSER_NO());

			// int result = configService.insertNewDatasourceUser(datasourceUser);

			//if(result>0) {
				ArrayList<JSONObject> dataSources = new ArrayList<JSONObject>();

//				List<DataSourceUserVO> duv = configService.selectDataSourceUserList(user.getUSER_NO());;
//				List<DataSourceGRPVO> dgv = configService.selectDataSourceGRPList(user.getGRP_ID());
//
//				Set<Integer> dsIDSet = new HashSet<Integer>();
//
//				for(DataSourceUserVO da : duv) {
//					dsIDSet.add(da.getDS_ID());
//				}
//
//				for(DataSourceGRPVO da : dgv) {
//					dsIDSet.add(da.getDS_ID());
//				}

				List<Integer> ids = null;
				//ids.addAll(dsIDSet);

				List<DataSourceVO> query = configService.selectDataSourceList(ids);
				for(DataSourceVO datasourceVO : query) {
					JSONObject datasource2 = new JSONObject();
					datasource2.put("데이터 ID", datasourceVO.getDS_ID());
					datasource2.put("데이터원본 명", datasourceVO.getDS_NM());
					datasource2.put("서버주소 명", datasourceVO.getIP());
					datasource2.put("DB 명", datasourceVO.getDB_NM());
					datasource2.put("DB 유형", datasourceVO.getDBMS_TYPE());
					datasource2.put("소유자", datasourceVO.getOWNER_NM());
					datasource2.put("Port", datasourceVO.getPORT());
					datasource2.put("접속 id", datasourceVO.getUSER_ID());
					datasource2.put("접속 암호", datasourceVO.getPASSWD());
					datasource2.put("접속 유형", datasourceVO.getCONN_TYPE());
					datasource2.put("DATA", datasourceVO.getUSER_AREA_YN());
					datasource2.put("USER NO", datasourceVO.getREG_USER_NO());

					datasources.add(datasource2);
				}

				obj.put("datasources", datasources);
				out.print(obj);
				out.flush();
				out.close();
			//}
		}
	}
	@RequestMapping(value = {"/updateDatasourceInfo.do"}, method = RequestMethod.POST)
	public void updateDatasourceInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject obj = new JSONObject();

		int dsId = Integer.valueOf(SecureUtils.getParameter(request, "newDsId"));
		String dsNm = SecureUtils.getParameter(request, "newDsNm");
		String dbNm = SecureUtils.getParameter(request, "newDbNm");
		String ip = SecureUtils.getParameter(request, "newIp");
		String userId = SecureUtils.getParameter(request, "newUserId");
		String passwd = SecureUtils.getParameter(request, "newPasswd");
		String port = SecureUtils.getParameter(request, "newPort");
		String dbmsType = SecureUtils.getParameter(request, "newDbmsType");
		String ownerNm = SecureUtils.getParameter(request, "newOwnerNm");
		String dsDesc = SecureUtils.getParameter(request, "newDsDesc");
		String dsConnstr = SecureUtils.getParameter(request, "newDsConnstr");
		String regDt = SecureUtils.getParameter(request, "newRegDt");
		//String regUserNo = SecureUtils.getParameter(request, "newRegUserNo");
		String updDt = SecureUtils.getParameter(request, "newUpdDt");
		//String updUserNo = SecureUtils.getParameter(request, "newUpdUserNo");
		String racip = SecureUtils.getParameter(request, "newRacip");
		String racport = SecureUtils.getParameter(request, "newRacport");
		String wfyn = SecureUtils.getParameter(request, "newWfyn");
		String userAreaYn = SecureUtils.getParameter(request, "newUserAreaYn");
		String connType = SecureUtils.getParameter(request, "newConnType");
		String hashYn = SecureUtils.getParameter(request, "newHashYn");

		User user = getSessionUser(request);

		Timestamp currentTime = Timer.formatTime(System.currentTimeMillis());

		DataSourceVO datasource = new DataSourceVO();

		datasource.setDS_ID(dsId);
		datasource.setDS_NM(dsNm);
		datasource.setDB_NM(dbNm);
		datasource.setIP(ip);
		datasource.setUSER_ID(userId);
		datasource.setPASSWD(passwd);
		datasource.setPORT(port);
		datasource.setDBMS_TYPE(dbmsType);
		datasource.setOWNER_NM(ownerNm);
		datasource.setDS_DESC(dsDesc);
		switch(dbmsType) {
		case "ORACLE":
			if ("SID".equals(connType)) {
				dsConnstr = "jdbc:oracle:thin:@" + ip + ":" + port + ":" + dbNm;
			}
			else {
				dsConnstr = "jdbc:oracle:thin:@" + ip + ":" + port + "/" + dbNm;
			}
			break;
		case "MS-SQL":
			dsConnstr = "jdbc:sqlserver://" + ip + ":" + port + ";DatabaseName=" + dbNm;
			break;
		case "TIBERO":
			dsConnstr = "jdbc:tibero:thin:@" + ip + ":" + port + ":" + dbNm;
			break;
		case "TBIN":
			dsConnstr = "jdbc:tibero:thin:@" + ip + ":" + port + ":" + dbNm;
			break;
		case "VERTICA":
			dsConnstr = "jdbc:vertica://" + ip + ":" + port + "/" + dbNm;
			break;
		case "MSPDW":
			dsConnstr = "jdbc:sqlserver://" + ip + ":" + port + ";DatabaseName=" + dbNm;
			break;
		case "MYSQL":
			dsConnstr = "jdbc:mysql://" + ip + ":" + port + "/" + dbNm;
			break;
		case "MARIA":
			dsConnstr = "jdbc:mariadb://" + ip + ":" + port + "/" + dbNm;
			break;
		case "MYIDM":
			dsConnstr = "jdbc:mysql://" + ip + ":" + port + "/" + dbNm;
			break;
		case "DB2BLU":
			dsConnstr = "jdbc:db2://" + ip + ":" + port + "/" + dbNm;
			break;
		case "PETASQL":
			dsConnstr = "jdbc:db2://" + ip + ":" + port + "/" + dbNm;
			break;
		case "POSTGRES":
			dsConnstr = "jdbc:postgresql://" + ip + ":" + port + "/" + dbNm;
			break;
		case "NETEZZA":
			dsConnstr = "jdbc:netezza://" + ip + ":" + port + "/" + dbNm;
			break;
		case "SAPIO":
			dsConnstr = "jdbc:sybase:Tds:" + ip + ":" + port + "/" + dbNm;
			break;
		case "SAPASE":
			dsConnstr = "jdbc:sybase:Tds:" + ip + ":" + port + "/" + dbNm;
			break;
		case "CUBRID":
			dsConnstr = "jdbc:cubrid:" + ip + ":" + port + ":" + dbNm + ":dba::";
			break;
		case "ALTIBASE":
			dsConnstr = "jdbc:Altibase://" + ip + ":" + port + "/" + dbNm;
			break;
		case "GOLDILOCKS":
			dsConnstr = "jdbc:goldilocks://" + ip + ":" + port + "/" + dbNm;
			break;
		case "TERADATA":
			dsConnstr = "jdbc:teradata://" + ip + "/DATABASE=" + dbNm + ",DBS_PORT=" + port + ",CHARSET=UTF8,TMODE=ANSI,ENCRYPTDATA=ON";
			break;
		case "IMPALA":
			dsConnstr = "jdbc:impala://" + ip + ":" + port + "/" + dbNm;
			break;
		}
		datasource.setDS_CONNSTR(dsConnstr);
		datasource.setREG_DT(currentTime);
		datasource.setREG_USER_NO(user.getUSER_NO());
		datasource.setUPD_DT(currentTime);
		datasource.setUPD_USER_NO(user.getUSER_NO());
		datasource.setRACIP(racip);
		datasource.setRACPORT(racport);
		datasource.setWF_YN(wfyn);
		datasource.setUSER_AREA_YN(userAreaYn);
		datasource.setCONN_TYPE(connType);
		datasource.setHASH_YN(hashYn);

		configService.updateDatasourceList(datasource);
		updateSessionUser(request);

		ArrayList<JSONObject> datasources = new ArrayList<JSONObject>();

//		List<DataSourceUserVO> duv = configService.selectDataSourceUserList(user.getUSER_NO());;
//		List<DataSourceGRPVO> dgv = configService.selectDataSourceGRPList(user.getGRP_ID());
//
//		Set<Integer> dsIDSet = new HashSet<Integer>();
//
//		for(DataSourceUserVO da : duv) {
//			dsIDSet.add(da.getDS_ID());
//		}
//
//		for(DataSourceGRPVO da : dgv) {
//			dsIDSet.add(da.getDS_ID());
//		}

		List<Integer> ids = null;
		//ids.addAll(dsIDSet);

		List<DataSourceVO> query = configService.selectDataSourceList(ids);
		for(DataSourceVO datasourceVO : query) {
			JSONObject datasource2 = new JSONObject();
			datasource2.put("데이터 ID", datasourceVO.getDS_ID());
			datasource2.put("데이터원본 명", datasourceVO.getDS_NM());
			datasource2.put("서버주소 명", datasourceVO.getIP());
			datasource2.put("DB 명", datasourceVO.getDB_NM());
			datasource2.put("DB 유형", datasourceVO.getDBMS_TYPE());
			datasource2.put("소유자", datasourceVO.getOWNER_NM());
			datasource2.put("Port", datasourceVO.getPORT());
			datasource2.put("접속 id", datasourceVO.getUSER_ID());
			datasource2.put("접속 암호", datasourceVO.getPASSWD());
			datasource2.put("접속 유형", datasourceVO.getCONN_TYPE());
			datasource2.put("DATA", datasourceVO.getUSER_AREA_YN());
			datasource2.put("USER NO", datasourceVO.getREG_USER_NO());

			datasources.add(datasource2);
		}

		obj.put("datasources", datasources);
		out.print(obj);
		out.flush();
		out.close();
	}
	@RequestMapping(value = {"/updateUserInfo.do"}, method = RequestMethod.POST)
	public void updateUserInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject obj = new JSONObject();

		String selectedUser = SecureUtils.getParameter(request, "selectedUser");	// selectedUser를 받아 쓰는게 없다. 원래 userId를 보냄
		String userId = SecureUtils.getParameter(request, "newUserId");
		String userName = SecureUtils.getParameter(request, "newUserName");
		String userEmail1 = SecureUtils.getParameter(request, "newUserEmail1");
		String userEmail2 = SecureUtils.getParameter(request, "newUserEmail2");
		String userTelNo = SecureUtils.getParameter(request, "newUserTelNo");
		String userMobileNo = SecureUtils.getParameter(request, "newUserMobileNo");
		String userRunMode = SecureUtils.getParameter(request, "newUserRunMode");
		String userRefNo = SecureUtils.getParameter(request, "newUserRefNo");
		String userDesc = SecureUtils.getParameter(request, "newUserDesc");
		String groupIdStr = SecureUtils.getParameter(request, "newGroupId");
		Integer groupId = groupIdStr.equals("")
				? null
				: Integer.parseInt(groupIdStr);

		// input validation
		String emailFormat = 	"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b" +
								"\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(" +
								"?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|" +
								"2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z" +
								"0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0" +
								"c\\x0e-\\x7f])+)\\])";
		String telNoFormat = "\\d{2}-\\d{4}-\\d{4}";
		String mobileNoFormat = "\\d{3}-\\d{4}-\\d{4}";
		if (userId == null || userId.isEmpty() || userName == null || userName.isEmpty()) {
			obj.put("error", "사용자 ID 및 사용자 명 정보가 필수 입니다. 다시 입력 해주세요.");
    		out.print(obj);
    		out.flush();
    		out.close();
    		return;
		}
		
		userEmail1 = default1001(userEmail1);
		userEmail2 = default1001(userEmail2);
		userTelNo = default1001(userTelNo);
		userMobileNo = default1001(userMobileNo);
		userRefNo = default1001(userRefNo);
		userDesc = default1001(userDesc);
		
		UserGroupVO userInfo = new UserGroupVO();
		userInfo.setSelectedUser(selectedUser);
		userInfo.setUSER_ID(userId);
		userInfo.setUSER_NM(userName);
		userInfo.setUSER_EMAIL1(userEmail1);
		userInfo.setUSER_EMAIL2(userEmail2);
		userInfo.setUSER_HP_NO(userTelNo);
		userInfo.setUSER_TEL_NO(userMobileNo);
		userInfo.setGRP_ID(groupId.intValue());
		userInfo.setUSER_RUN_MODE(userRunMode);
		userInfo.setUSER_REL_CD(userRefNo);
		userInfo.setUSER_DESC(userDesc);

		configService.updateUserList(userInfo);
		updateSessionUser(request);
		
		ArrayList<JSONObject> users = new ArrayList<JSONObject>();
		List<UserGroupVO> query = configService.selectUserListAndGroupName();
		
		for (UserGroupVO userGroupVO : query) {
			JSONObject user = new JSONObject();
			user.put("사용자 NO", userGroupVO.getUSER_NO());
			user.put("사용자 ID", userGroupVO.getUSER_ID());
			user.put("사용자 명", userGroupVO.getUSER_NM());
			user.put("그룹 ID", userGroupVO.getGRP_ID());
			user.put("그룹 명", userGroupVO.getGRP_NM());
			user.put("사용자 실행모드", userGroupVO.getUSER_RUN_MODE());
			user.put("그룹 실행모드", userGroupVO.getGRP_RUN_MODE());
			user.put("참조코드", userGroupVO.getUSER_REL_CD());
			user.put("설명", userGroupVO.getUSER_DESC());
			users.add(user);
		}

		obj.put("users", users);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping(value= {"/insertUserInfo.do"}, method = RequestMethod.POST)
	public void insertUserInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject obj = new JSONObject();

		String userId = SecureUtils.getParameter(request, "newUserId");
		String userPassword = SecureUtils.getParameter(request, "newUserPw");
		String userName = SecureUtils.getParameter(request, "newUserName");
		String userEmail1 = SecureUtils.getParameter(request, "newUserEmail1");
		String userEmail2 = SecureUtils.getParameter(request, "newUserEmail2");
		String userTelNo = SecureUtils.getParameter(request, "newUserTelNo");
		String userMobileNo = SecureUtils.getParameter(request, "newUserMobileNo");
		String userRunMode = SecureUtils.getParameter(request, "newUserRunMode");
		String userRefNo = SecureUtils.getParameter(request, "newUserRefNo");
		String userDesc = SecureUtils.getParameter(request, "newUserDesc");
		String groupIdStr = SecureUtils.getParameter(request, "newGroupId");
		Integer groupId = groupIdStr.equals("")
				? null
				: Integer.parseInt(groupIdStr);

		// input validation
		String emailFormat = 	"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b" +
								"\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(" +
								"?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|" +
								"2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z" +
								"0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0" +
								"c\\x0e-\\x7f])+)\\])";
		String telNoFormat = "\\d{2}-\\d{4}-\\d{4}";
		String mobileNoFormat = "\\d{3}-\\d{4}-\\d{4}";
		/* DOGFOOT ktkang 그룹명 사용자 싱행 모드 필수 정보로 입력하도록 수정  20200629 */
		if (userId == null || userId.isEmpty() || userName == null || userName.isEmpty() || groupIdStr == null || groupIdStr.isEmpty()) {
			obj.put("error", "사용자 ID 및 사용자 명, 그룹 명은 필수 입니다. 다시 입력 해주세요.");
    		out.print(obj);
    		out.flush();
    		out.close();
    		return;
		} else if (authenticationService.selectUserById(userId) != null) {
			obj.put("error", "사용자 ID가 중복 입니다. 다시 입력 해주세요.");
    		out.print(obj);
    		out.flush();
    		out.close();
    		return;
		} else if (userPassword == null || userPassword.isEmpty()) {
			obj.put("error", "비밀번효 다시 입력 해주세요.");
			out.print(obj);
    		out.flush();
    		out.close();
    		return;
		}

		UserGroupVO userInfo = new UserGroupVO();
		userInfo.setUSER_ID(userId);
		userInfo.setUSER_PW(userPassword);
		userInfo.setUSER_NM(userName);
		userInfo.setUSER_EMAIL1(userEmail1);
		userInfo.setUSER_EMAIL2(userEmail2);
		userInfo.setUSER_HP_NO(userTelNo);
		userInfo.setUSER_TEL_NO(userMobileNo);
		userInfo.setGRP_ID(groupId);
		userInfo.setUSER_RUN_MODE(userRunMode);
		userInfo.setUSER_REL_CD(userRefNo);
		userInfo.setUSER_DESC(userDesc);
		
		configService.insertNewUser(userInfo);
			
		ArrayList<JSONObject> users = new ArrayList<JSONObject>();
		List<UserGroupVO> query = configService.selectUserListAndGroupName();
		
		for (UserGroupVO userGroupVO : query) {
			JSONObject user = new JSONObject();
			user.put("사용자 NO", userGroupVO.getUSER_NO());
			user.put("사용자 ID", userGroupVO.getUSER_ID());
			user.put("사용자 명", userGroupVO.getUSER_NM());
			user.put("그룹 ID", userGroupVO.getGRP_ID());
			user.put("그룹 명", userGroupVO.getGRP_NM());
			user.put("사용자 실행모드", userGroupVO.getUSER_RUN_MODE());
			user.put("그룹 실행모드", userGroupVO.getGRP_RUN_MODE());
			user.put("참조코드", userGroupVO.getUSER_REL_CD());
			user.put("설명", userGroupVO.getUSER_DESC());
			users.add(user);
		}

		obj.put("users", users);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping(value = {"/deleteDatasourceInfo.do"}, method = RequestMethod.POST)
	public void deleteDatasourceInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject obj = new JSONObject();

		String selectedDatasource = SecureUtils.getParameter(request, "datasource");

		User user = getSessionUser(request);

		// user, group 권한 ds_mstr 모두 삭제로 변경
		DataSourceVO datasource = new DataSourceVO();
		DataSourceUserVO datasourceUser = new DataSourceUserVO();
		DataSourceGRPVO datasourceGrp = new DataSourceGRPVO();

		datasource.setDS_ID(Integer.parseInt(selectedDatasource));
		datasourceUser.setUSER_NO(user.getUSER_NO());
		datasourceUser.setDS_ID(Integer.parseInt(selectedDatasource));
		datasourceGrp.setGRP_ID(user.getGRP_ID());
		datasourceGrp.setDS_ID(Integer.parseInt(selectedDatasource));

		int result = configService.deleteDataSourceInfo(datasource);
		result = configService.deleteDataSourceUserInfo(datasourceUser);
		result = configService.deleteDataSourceGrpInfo(datasourceGrp);

		// if(result>0) {


			ArrayList<JSONObject> datasources = new ArrayList<JSONObject>();

//			List<DataSourceUserVO> duv = configService.selectDataSourceUserList(user.getUSER_NO());;
//			List<DataSourceGRPVO> dgv = configService.selectDataSourceGRPList(user.getGRP_ID());
//
//			Set<Integer> dsIDSet = new HashSet<Integer>();
//
//			for(DataSourceUserVO da : duv) {
//				dsIDSet.add(da.getDS_ID());
//			}
//
//			for(DataSourceGRPVO da : dgv) {
//				dsIDSet.add(da.getDS_ID());
//			}

			List<Integer> ids = null;
			//ids.addAll(dsIDSet);

			List<DataSourceVO> query = configService.selectDataSourceList(ids);
			for(DataSourceVO datasourceVO : query) {
				JSONObject datasource2 = new JSONObject();
				datasource2.put("데이터 ID", datasourceVO.getDS_ID());
				datasource2.put("데이터원본 명", datasourceVO.getDS_NM());
				datasource2.put("서버주소 명", datasourceVO.getIP());
				datasource2.put("DB 명", datasourceVO.getDB_NM());
				datasource2.put("DB 유형", datasourceVO.getDBMS_TYPE());
				datasource2.put("소유자", datasourceVO.getOWNER_NM());
				datasource2.put("Port", datasourceVO.getPORT());
				datasource2.put("접속 id", datasourceVO.getUSER_ID());
				datasource2.put("접속 암호", datasourceVO.getPASSWD());
				datasource2.put("접속 유형", datasourceVO.getCONN_TYPE());
				datasource2.put("DATA", datasourceVO.getUSER_AREA_YN());
				datasource2.put("USER NO", datasourceVO.getREG_USER_NO());

				datasources.add(datasource2);
			}

			obj.put("datasources", datasources);
			out.print(obj);
			out.flush();
			out.close();
		// }
	}

	@RequestMapping(value = {"/deleteUserInfo.do"}, method = RequestMethod.POST)
	public void deleteUserInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject obj = new JSONObject();

		String selectedUser = SecureUtils.getParameter(request, "orgUserId");	// selectedUser를 받아 쓰는게 없다. 원래 userId를 보냄

		UserGroupVO userInfo = new UserGroupVO();
		userInfo.setSelectedUser(selectedUser);
		int startNum = Integer.parseInt(SecureUtils.getParameter(request, "startNum"));
		int endNum = Integer.parseInt(SecureUtils.getParameter(request, "endNum"));
		userInfo.setStartNum(startNum);
		userInfo.setEndNum(endNum);

		configService.deleteUserFromList(userInfo);
		
		ArrayList<JSONObject> users = new ArrayList<JSONObject>();
		List<UserGroupVO> query = configService.selectUserListAndGroupName();
		
		for (UserGroupVO userGroupVO : query) {
			JSONObject user = new JSONObject();
			user.put("사용자 NO", userGroupVO.getUSER_NO());
			user.put("사용자 ID", userGroupVO.getUSER_ID());
			user.put("사용자 명", userGroupVO.getUSER_NM());
			user.put("그룹 ID", userGroupVO.getGRP_ID());
			user.put("그룹 명", userGroupVO.getGRP_NM());
			user.put("사용자 실행모드", userGroupVO.getUSER_RUN_MODE());
			user.put("그룹 실행모드", userGroupVO.getGRP_RUN_MODE());
			user.put("참조코드", userGroupVO.getUSER_REL_CD());
			user.put("설명", userGroupVO.getUSER_DESC());
			users.add(user);
		}

		obj.put("users", users);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping(value = {"/changePassword.do"}, method = RequestMethod.POST)
	public void changePassword(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		JSONObject obj = new JSONObject();

		try {
			request.setCharacterEncoding("utf-8");
			out = response.getWriter();
			String user = SecureUtils.getParameter(request, "user");
			String oldPw = SecureUtils.getParameter(request, "oldPw");
			String newPw = SecureUtils.getParameter(request, "newPw");

			User checkPw = authenticationService.selectLoginUser(user, oldPw);
	    	if(checkPw == null) {
	    		obj.put("error", "기존 비밀번호가 틀렸습니다. 다시 입력 해주세요.");
	    		out.print(obj);
	    		out.flush();
	    		out.close();
	    		return;
	    	} else if (newPw.equals(checkPw.getPASSWD())) {
	    		obj.put("error", "새 비밀번호가 기존 비밀번호와 똑같습니다. 다시 입력 해주세요.");
	    		out.print(obj);
	    		out.flush();
	    		out.close();
	    		return;
	    	}
			Timestamp currentTime = Timer.formatTime(System.currentTimeMillis());
			UserGroupVO userInfo = new UserGroupVO();
			userInfo.setSelectedUser(user);
			userInfo.setNewPw(newPw);
			userInfo.setPW_CHANGE_DT(currentTime);

			configService.changeUserPassword(userInfo);
		} catch (IOException e) {
			e.printStackTrace();
			throw new Error(e);
		}finally {
			out.print(obj);
			out.flush();
			out.close();
		}
	}

	@RequestMapping(value = {"/insertGroupInfo.do"}, method = RequestMethod.POST)
	public void insertGroupInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject obj = new JSONObject();

		String groupName = SecureUtils.getParameter(request, "newGroupName");
		String groupDesc = SecureUtils.getParameter(request, "newGroupDesc");
		String groupRunMode = SecureUtils.getParameter(request, "newGroupRunMode");
		String groupRelCd = SecureUtils.getParameter(request, "newGroupRelCd");
		String[] selectedUsers = SecureUtils.getParameters(request).get("selectedUsers[]");
		List<Integer> userIds = new ArrayList<Integer>();
		if (selectedUsers != null) {
			for (String id : selectedUsers) {
				userIds.add(Integer.parseInt(id));
			}
		}

		// input validation
		if (groupName == null || groupName.isEmpty()) {
			obj.put("error", "사용자 ID 및 사용자 명 정보는 필수 입력사항입니다. 다시 입력 해주세요.");
    		out.print(obj);
    		out.flush();
    		out.close();
    		return;
		} else if (configService.selectGroupIdByGroupName(groupName) != null) {
			obj.put("error", "그룹 명이 중복 입니다. 다시 입력 해주세요.");
    		out.print(obj);
    		out.flush();
    		out.close();
    		return;
		}

		UserGroupVO groupInfo = new UserGroupVO();
		groupInfo.setGRP_NM(groupName);
		groupInfo.setGRP_DESC(groupDesc);
		groupInfo.setGRP_RUN_MODE(groupRunMode);
		groupInfo.setGRP_REL_CD(groupRelCd);
		ArrayList<JSONObject> groups = new ArrayList<JSONObject>();

//		try {
			configService.insertGroupInfo(groupInfo);
			Integer groupId = configService.selectGroupIdByGroupName(groupName);
			groupInfo.setGRP_ID(groupId);
			groupInfo.setSelectedUsers(userIds);
			configService.initGroupUsers(groupId);
			if (selectedUsers != null) {
				configService.updateGroupUsers(groupInfo);
			}
			List<UserGroupVO> query = configService.selectGroupList();
			for (UserGroupVO userGroupVO : query) {
				JSONObject group = new JSONObject();
				group.put("id", userGroupVO.getGRP_ID());
				group.put("name", userGroupVO.getGRP_NM());
				group.put("runMode", userGroupVO.getGRP_RUN_MODE());
				group.put("desc", userGroupVO.getGRP_DESC());
				group.put("relCd", userGroupVO.getGRP_REL_CD());
				groups.add(group);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		obj.put("groups", groups);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping(value = {"/updateGroupInfo.do"}, method = RequestMethod.POST)
	public void updateGroupInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		JSONObject obj = new JSONObject();
		ArrayList<JSONObject> groups = new ArrayList<JSONObject>();

//		try {
			request.setCharacterEncoding("utf-8");
			out = response.getWriter();
			String groupName = SecureUtils.getParameter(request, "newGroupName");
			String groupDesc = SecureUtils.getParameter(request, "newGroupDesc");
			String groupRunMode = SecureUtils.getParameter(request, "newGroupRunMode");
			String groupRelCd = SecureUtils.getParameter(request, "newGroupRelCd");
			Integer selectedGroup = Integer.parseInt(SecureUtils.getParameter(request, "selectedGroup"));
			String selectedGroupName = SecureUtils.getParameter(request, "selectedGroupName");
			String[] selectedUsers = SecureUtils.getParameters(request).get("selectedUsers[]");
			List<Integer> userIds = new ArrayList<Integer>();
			if (selectedUsers != null) {
				for (String id : selectedUsers) {
					userIds.add(Integer.parseInt(id));
				}
			}

			// input validation
			if (groupName == null || groupName.isEmpty()) {
				obj.put("error", "사용자 ID 및 사용자 명 정보가 필수 입력사항입니다. 다시 입력 해주세요.");
	    		out.print(obj);
	    		out.flush();
	    		out.close();
	    		return;
			} else if (!(selectedGroupName.equals(groupName)) && configService.selectGroupIdByGroupName(groupName) != null) {
				obj.put("error", "그룹 명이 중복 입니다. 다시 입력 해주세요.");
	    		out.print(obj);
	    		out.flush();
	    		out.close();
	    		return;
			}

			UserGroupVO groupInfo = new UserGroupVO();
			groupInfo.setGRP_NM(groupName);
			groupInfo.setGRP_DESC(groupDesc);
			groupInfo.setGRP_RUN_MODE(groupRunMode);
			groupInfo.setGRP_REL_CD(groupRelCd);
			groupInfo.setSelectedGroup(selectedGroup);

			configService.updateGroupInfo(groupInfo);
			Integer groupId = configService.selectGroupIdByGroupName(groupName);
			groupInfo.setGRP_ID(groupId);
			groupInfo.setSelectedUsers(userIds);
			configService.initGroupUsers(groupId);
			if (selectedUsers != null) {
				configService.updateGroupUsers(groupInfo);
			}
			List<UserGroupVO> query = configService.selectGroupList();
			for (UserGroupVO userGroupVO : query) {
				JSONObject group = new JSONObject();
				group.put("id", userGroupVO.getGRP_ID());
				group.put("name", userGroupVO.getGRP_NM());
				group.put("runMode", userGroupVO.getGRP_RUN_MODE());
				group.put("desc", userGroupVO.getGRP_DESC());
				group.put("relCd", userGroupVO.getGRP_REL_CD());
				groups.add(group);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}finally {
			obj.put("groups", groups);
			out.print(obj);
			out.flush();
			out.close();
//		}
	}

	@RequestMapping(value = {"/deleteGroupInfo.do"}, method = RequestMethod.POST)
	public void deleteGroupInfo(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		JSONObject obj = new JSONObject();

		try {
			request.setCharacterEncoding("utf-8");
			out = response.getWriter();

			Integer selectedGroup = Integer.parseInt(SecureUtils.getParameter(request, "groupId"));
			UserGroupVO groupInfo = new UserGroupVO();
			groupInfo.setSelectedGroup(selectedGroup);
			configService.deleteGroupInfo(groupInfo);

			ArrayList<JSONObject> groups = new ArrayList<JSONObject>();
			List<UserGroupVO> query = configService.selectGroupList();
			for (UserGroupVO userGroupVO : query) {
				JSONObject group = new JSONObject();
				group.put("id", userGroupVO.getGRP_ID());
				group.put("name", userGroupVO.getGRP_NM());
				group.put("runMode", userGroupVO.getGRP_RUN_MODE());
				group.put("desc", userGroupVO.getGRP_DESC());
				group.put("relCd", userGroupVO.getGRP_REL_CD());
				groups.add(group);
			}
			obj.put("groups", groups);
		} catch (IOException e) {
			e.printStackTrace();
			throw new Error(e);
		}finally {
			out.print(obj);
			out.flush();
			out.close();
		}



	}

	@RequestMapping(value = {"/addUsersToGroup.do"}, method = RequestMethod.POST)
	public void addUsersToGroup(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		JSONObject obj = new JSONObject();

		Integer selectedGroup = Integer.parseInt(SecureUtils.getParameter(request, "groupId"));
		JSONArray selectedUsers = JSONArray.fromObject(SecureUtils.unsecure(SecureUtils.getParameter(request,"users")));

//		try {
			if(selectedUsers != null) {
				for (int i = 0; i < selectedUsers.size(); i++) {
					UserGroupVO user = new UserGroupVO();
					obj = selectedUsers.getJSONObject(i);
					if(obj != null) {
						user.setGRP_ID(selectedGroup);
						user.setUSER_ID(obj.get("사용자 ID")+"");
						configService.addUserToGroup(user);
					}
				}
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
	}

	@RequestMapping(value = {"/removeUsersFromGroup.do"}, method = RequestMethod.POST)
	public void removeUsersFromGroup(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		JSONObject obj = new JSONObject();
		String userString = SecureUtils.unsecure(SecureUtils.getParameter(request, "users"));
		JSONArray selectedUsers = JSONArray.fromObject(userString);


//		try {
			for (int i = 0; i < selectedUsers.size(); i++) {
				UserGroupVO user = new UserGroupVO();
				user.setUSER_ID(selectedUsers.getJSONObject(i).getString("사용자 ID"));
				configService.removeUserFromGroup(user);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
	}

	/*
	 * CONFIG REPORT & FOLDER SERVICES
	 */
	/*dogfoot 환경설정 보고서 관리 폴더,보고서 Key 중복 오류 수정 shlim 20210217*/
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

	@RequestMapping(value= {"/getPublicReportList.do"}, method = RequestMethod.GET)
	public void getPublicReportList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONArray result = new JSONArray();

//		try {
			List<ReportListMasterVO> resultList = null;
			/*dogfoot 환경설정 보고서 관리 폴더,보고서 Key 중복 오류 수정 shlim 20210217*/
			resultList = folderIdUniqueGenerate(configService.selectPublicReportList());
			for (ReportListMasterVO reportItem : resultList) {
				JSONObject item = new JSONObject();
				item.put("ID", reportItem.getID());
				item.put("TEXT", reportItem.getTEXT());
				item.put("UPPERID", reportItem.getUPPERID());
				item.put("ORDINAL", reportItem.getORDINAL());
				item.put("TYPE", reportItem.getTYPE());
				item.put("REPORT_TYPE", reportItem.getREPORT_TYPE());
				item.put("PROMPT", reportItem.getPROMPT());
				item.put("SUBTITLE", reportItem.getSUBTITLE());
				item.put("CREATED_BY", reportItem.getCREATED_BY());
				item.put("CREATED_DATE", reportItem.getCREATED_DATE());
				item.put("TAG", reportItem.getTAG());
				item.put("DESCRIPTION", reportItem.getDESCRIPTION());
				item.put("uniqueKey", reportItem.getUniqueKey());
				item.put("upperKey", reportItem.getUpperKey());
				/* DOGFOOT ktkang KERIS 보고서 폴더 보기에서 쿼리때문에 너무 느려서 뺌  20200130 */
//				if ("DashAny".equals(reportItem.getREPORT_TYPE())) {
//					item.put("QUERY", reportItem.getQueryFromDatasetXml());
//				} else {
//					item.put("QUERY", reportItem.getQUERY());
//				}
				result.add(item);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		out.print(result);
        out.flush();
        out.close();
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	@RequestMapping(value= {"/getUserReportList.do"}, method = RequestMethod.POST)
	public void getUserReportList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONArray result = new JSONArray();

		String user_no = SecureUtils.getParameter(request,"user_no");

//		try {
			List<ReportListMasterVO> resultList = null;
			resultList = configService.selectUserReportList(Integer.parseInt(user_no));
			for (ReportListMasterVO reportItem : resultList) {
				JSONObject item = new JSONObject();
				item.put("ID", reportItem.getID());
				item.put("TEXT", reportItem.getTEXT());
				item.put("UPPERID", reportItem.getUPPERID());
				item.put("ORDINAL", reportItem.getORDINAL());
				item.put("TYPE", reportItem.getTYPE());
				item.put("REPORT_TYPE", reportItem.getREPORT_TYPE());
				item.put("PROMPT", reportItem.getPROMPT());
				item.put("SUBTITLE", reportItem.getSUBTITLE());
				item.put("CREATED_BY", reportItem.getCREATED_BY());
				item.put("CREATED_DATE", reportItem.getCREATED_DATE());
				item.put("TAG", reportItem.getTAG());
				item.put("DESCRIPTION", reportItem.getDESCRIPTION());
				if ("DashAny".equals(reportItem.getREPORT_TYPE())) {
					item.put("QUERY", reportItem.getQueryFromDatasetXml());
				} else {
					item.put("QUERY", reportItem.getQUERY());
				}
				result.add(item);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		out.print(result);
        out.flush();
        out.close();
	}

	@RequestMapping(value= {"/savePublicReport.do"}, method = RequestMethod.POST)
	public void savePublicReportList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		JSONArray result = new JSONArray();
		ReportListMasterVO report = new ReportListMasterVO();

		Integer id = Integer.parseInt(SecureUtils.getParameter(request, "ID"));
		String text = SecureUtils.getParameter(request, "TEXT");
		String subtitle = SecureUtils.getParameter(request, "SUBTITLE");
		String tag = SecureUtils.getParameter(request, "TAG");
		if(tag.equals("1001")) {
			tag = "";
		}
		Integer fldId = Integer.parseInt(SecureUtils.getParameter(request, "FLD_ID"));
		if(fldId == 1001) {
			fldId = 0;
		}
		Integer fldType = Integer.parseInt(SecureUtils.getParameter(request, "FLD_TYPE"));
		Integer ordinal = Integer.parseInt(SecureUtils.getParameter(request, "ORDINAL"));
		String desc = SecureUtils.getParameter(request, "DESCRIPTION");
		String prompt = SecureUtils.getParameter(request, "PROMPT");
		/* DOGFOOT ktkang KERIS 보고서 별 필드 정보 추가기능  20200123 */
		JSONArray reportFieldList = SecureUtils.getJSONArrayParameter(request, "REPORTFIELDLIST");
		
		String directView = SecureUtils.getParameter(request, "DIRECTVIEW");
		
		report.setFLD_ID(fldId);
		report.setID(id);
		report.setTEXT(text);
		report.setSUBTITLE(subtitle);
		report.setTAG(tag);
		report.setORDINAL(ordinal);
		report.setDESCRIPTION(desc);
		report.setPROMPT(prompt);
		report.setDIRECTVIEW(directView);

		/* DOGFOOT ktkang KERIS 보고서 별 필드 정보 추가기능  20200123 */
		this.configService.savePublicReport(report);
		/*
		this.reportService.deleteReportFieldList(id);
		for(int i = 0; i < reportFieldList.size(); i++) {
			JSONObject reportFieldJson = reportFieldList.getJSONObject(i);
			ReportFieldMasterVO reportField = new ReportFieldMasterVO();
			reportField.setREPORT_ID(id);
			reportField.setFIELD_NM(reportFieldJson.getString("FIELD_NM"));
			reportField.setFIELD_TYPE(reportFieldJson.getString("FIELD_TYPE"));

			this.reportService.insertReportField(reportField);
		}
		*/
	}

	@RequestMapping(value= {"/deletePublicReport.do"}, method = RequestMethod.POST)
	public void deletePublicReportList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer id = Integer.parseInt(SecureUtils.getParameter(request, "id"));

//		try {
			configService.deletePublicReport(id);
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
	}

	@RequestMapping(value= {"/getPublicFolderList.do"}, method = RequestMethod.GET)
	public void getPublicFolderList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONArray result = new JSONArray();

//		try {
			List<FolderMasterVO> folders = null;
			folders = configService.getPublicFolderList();
			result = JSONArray.fromObject(folders);
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		out.print(result);
        out.flush();
        out.close();
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	@RequestMapping(value= {"/getUserFolderList.do"}, method = RequestMethod.POST)
	public void getUserFolderList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONArray result = new JSONArray();

		String user_no = SecureUtils.getParameter(request,"user_no");

//		try {
			List<FolderMasterVO> folders = null;
			folders = configService.getUserFolderList(Integer.parseInt(user_no));
			result = JSONArray.fromObject(folders);
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		out.print(result);
        out.flush();
        out.close();
	}

	@RequestMapping(value= {"/createNewPublicFolder.do"}, method = RequestMethod.POST)
	public void createNewPublicFolder(HttpServletRequest request, HttpServletResponse response, Model model) throws UnsupportedEncodingException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		
		String fldNm = SecureUtils.getParameter(request, "name");
		Integer parentFldId = Integer.parseInt(SecureUtils.getParameter(request, "parentFolder"));
		Integer level = 0;
		Integer ordinal = 1;
		FolderMasterVO folder = new FolderMasterVO();
		folder.setFLD_NM(fldNm);
		folder.setPARENT_FLD_ID(parentFldId);

		try {
			// check for duplicate name in parent folder
			FolderMasterVO duplicate = configService.getPublicFolderWithNameAndParent(folder);
			if (duplicate != null) {
				PrintWriter out = response.getWriter();
				out.print("중복 이름 입니다. 다시 선택해주세요.");
				out.flush();
				out.close();
			} else {
				// determine folder level
				if (parentFldId > 0) {
					level = configService.getPublicFolderLevel(parentFldId) + 1;
				}
				// determine folder ordinal
				ordinal = configService.getPublicFolderMaxOrdinal(parentFldId) + 1;
				// add new folder to database
				folder.setFLD_LVL(level);
				folder.setFLD_ORDINAL(ordinal);
				configService.insertPublicFolder(folder);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	@RequestMapping(value= {"/createNewUserFolder.do"}, method = RequestMethod.POST)
	public void createNewUserFolder(HttpServletRequest request, HttpServletResponse response, Model model) throws UnsupportedEncodingException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		String fldNm = SecureUtils.getParameter(request, "name");
		Integer parentFldId = Integer.parseInt(SecureUtils.getParameter(request, "parentFolder"));
		String user_no = SecureUtils.getParameter(request, "user_no");
		Integer level = 0;
		Integer ordinal = 1;
		FolderMasterVO folder = new FolderMasterVO();
		folder.setFLD_NM(fldNm);
		folder.setPARENT_FLD_ID(parentFldId);

		try {
			// check for duplicate name in parent folder
			FolderMasterVO duplicate = configService.getUserFolderWithNameAndParent(folder);
			if (duplicate != null) {
				PrintWriter out = response.getWriter();
				out.print("중복 이름 입니다. 다시 선택해주세요.");
				out.flush();
				out.close();
			} else {
				// determine folder level
				if (parentFldId > 0) {
					level = configService.getUserFolderLevel(parentFldId) + 1;
				}
				// determine folder ordinal
				ordinal = configService.getUserFolderMaxOrdinal(parentFldId) + 1;
				// add new folder to database
				folder.setUSER_NO(Integer.parseInt(user_no));
				folder.setFLD_LVL(level);
				folder.setFLD_ORDINAL(ordinal);
				configService.insertUserFolder(folder);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@RequestMapping(value= {"/editPublicFolderName.do"}, method = RequestMethod.POST)
	public void editPublicFolderName(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		try {
			request.setCharacterEncoding("utf-8");
			String fldNm = SecureUtils.getParameter(request, "name");
			String oldNm = SecureUtils.getParameter(request, "originalName");
			Integer fldId = Integer.parseInt(SecureUtils.getParameter(request, "id"));
			Integer parentId = Integer.parseInt(SecureUtils.getParameter(request, "parentId"));
			FolderMasterVO folder = new FolderMasterVO();
			folder.setFLD_ID(fldId);
			folder.setFLD_NM(fldNm);
			folder.setPARENT_FLD_ID(parentId);
			// check for duplicate name in parent folder
			FolderMasterVO duplicate = configService.getPublicFolderWithNameAndParent(folder);
			if (duplicate != null) {
				PrintWriter out = response.getWriter();
				out.print("중복 이름 입니다. 다시 선택해주세요.");
				out.flush();
				out.close();
			} else {
				// add new folder to database
				configService.editPublicFolderName(folder);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	@RequestMapping(value= {"/editUserFolderName.do"}, method = RequestMethod.POST)
	public void editUserFolderName(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		try {
			request.setCharacterEncoding("utf-8");
			String fldNm = SecureUtils.getParameter(request, "name");
			String oldNm = SecureUtils.getParameter(request, "originalName");
			Integer fldId = Integer.parseInt(SecureUtils.getParameter(request, "id"));
			Integer parentId = Integer.parseInt(SecureUtils.getParameter(request, "parentId"));
			FolderMasterVO folder = new FolderMasterVO();
			folder.setFLD_ID(fldId);
			folder.setFLD_NM(fldNm);
			folder.setPARENT_FLD_ID(parentId);
			// check for duplicate name in parent folder
			FolderMasterVO duplicate = configService.getUserFolderWithNameAndParent(folder);
			if (duplicate != null) {
				PrintWriter out = response.getWriter();
				out.print("중복 이름 입니다. 다시 선택해주세요.");
				out.flush();
				out.close();
			} else {
				// add new folder to database
				configService.editUserFolderName(folder);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@RequestMapping(value= {"/nestedReportsExist.do"}, method = RequestMethod.POST)
	public void nestedReportsExist(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		String[] folderStrings = SecureUtils.getParameters(request).get("folders[]");
		List<Integer> folders = new ArrayList<Integer>();
		for (String id : folderStrings) {
			folders.add(Integer.parseInt(id));
		}
//		try {
			List<ReportMasterVO> reports = configService.selectReportsInFolders(folders);
			char exists = (reports.size() > 0) ? 'Y' : 'N';
			PrintWriter out = response.getWriter();
			out.print(exists);
			out.flush();
			out.close();
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
	}

	@RequestMapping(value= {"/deleteSelectedFolders.do"}, method = RequestMethod.POST)
	public void deleteSelectedFolders(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer folderId = Integer.parseInt(SecureUtils.getParameter(request, "parent"));
		String[] folderStrings = SecureUtils.getParameters(request).get("folders[]");
		List<Integer> folders = new ArrayList<Integer>();
		for (String id : folderStrings) {
			folders.add(Integer.parseInt(id));
		}
//		try {
			configService.deleteChildFolders(folders);
			configService.deleteFolder(folderId);
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
	}

	@RequestMapping(value= {"/deleteSelectedFoldersAndReports.do"}, method = RequestMethod.POST)
	public void deleteSelectedFoldersAndReports(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer folderId = Integer.parseInt(SecureUtils.getParameter(request, "parent"));
		String[] folderStrings = SecureUtils.getParameters(request).get("folders[]");
		List<Integer> folders = new ArrayList<Integer>();
		for (String id : folderStrings) {
			folders.add(Integer.parseInt(id));
		}
//		try {
			configService.deleteChildReports(folders);
			configService.deleteChildFolders(folders);
			configService.deleteFolder(folderId);
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	@RequestMapping(value= {"/deleteUserFolders.do"}, method = RequestMethod.POST)
	public void deleteUserFolders(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer folderId = Integer.parseInt(SecureUtils.getParameter(request, "parent"));
		String[] folderStrings = SecureUtils.getParameters(request).get("folders[]");
		List<Integer> folders = new ArrayList<Integer>();
		for (String id : folderStrings) {
			folders.add(Integer.parseInt(id));
		}
//		try {
			configService.deleteChildUserFolders(folders);
			configService.deleteUserFolder(folderId);
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
	}

	@RequestMapping(value= {"/deleteUserFoldersAndReports.do"}, method = RequestMethod.POST)
	public void deleteUserFoldersAndReports(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer folderId = Integer.parseInt(SecureUtils.getParameter(request, "parent"));
		String[] folderStrings = SecureUtils.getParameters(request).get("folders[]");
		List<Integer> folders = new ArrayList<Integer>();
		for (String id : folderStrings) {
			folders.add(Integer.parseInt(id));
		}
//		try {
			configService.deleteChildReports(folders);
			configService.deleteChildUserFolders(folders);
			configService.deleteUserFolder(folderId);
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
	}

	/*
	 * CONFIG AUTHENTICATION SERVICES
	 */
	@RequestMapping("/getAuthUserDataList.do")
	public void authUserList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		ArrayList<JSONObject> userArrayList = new ArrayList<JSONObject>();
		ArrayList<JSONObject> DSViewArrayList = new ArrayList<JSONObject>();

//		try {
		List<UserGroupVO> userList = configService.selectUserAuthDataList();

		for(UserGroupVO users : userList) {
			JSONObject userjson = new JSONObject();
			userjson.put("AUTH_YN", users.getAuthCount() > 0 ? "Y" : "N");
			userjson.put("사용자NO", users.getUSER_NO());
			userjson.put("사용자ID", users.getUSER_ID());
			userjson.put("사용자명", users.getUSER_NM());
			userjson.put("그룹명", users.getGRP_NM());
			userArrayList.add(userjson);
		}

		List<DSViewVO> dsList = configService.selectDSViewList();
		for(DSViewVO vo : dsList) {
			JSONObject DSViewjson = new JSONObject();
			DSViewjson.put("AUTH_YN", "");
			DSViewjson.put("DS_VIEW_ID", vo.getDS_VIEW_ID());
			DSViewjson.put("DS_VIEW_NM", vo.getDS_VIEW_NM());
			DSViewjson.put("DS_NM", vo.getDS_NM());
			DSViewjson.put("DBMS_TYPE", vo.getDBMS_TYPE());
			DSViewjson.put("OWNER_NM", vo.getOWNER_NM());
			DSViewjson.put("DB_NM",vo.getDB_NM());
			DSViewjson.put("IP",vo.getIP());
			DSViewjson.put("USER_ID",vo.getUSER_ID());
			DSViewjson.put("PASSWD",vo.getPASSWD());
			DSViewjson.put("PORT", vo.getPORT());
			DSViewArrayList.add(DSViewjson);
		}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("userArrayList", userArrayList);
		obj.put("DSViewArrayList", DSViewArrayList);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getAuthGroupDataList.do")
	public void authGroupList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		ArrayList<JSONObject> groupArrayList = new ArrayList<JSONObject>();
		ArrayList<JSONObject> DSViewArrayList = new ArrayList<JSONObject>();

//		try {
			List<UserGroupVO> groupList = configService.selectGroupAuthDataList();

			for(UserGroupVO groups : groupList) {
				JSONObject groupjson = new JSONObject();
				groupjson.put("AUTH_YN", groups.getAuthCount() > 0 ? "Y" : "N");
				groupjson.put("그룹NO", groups.getGRP_ID());
				groupjson.put("그룹명", groups.getGRP_NM());
				groupjson.put("설명", groups.getGRP_DESC());
				groupArrayList.add(groupjson);
			}

			List<DSViewVO> dsList = configService.selectDSViewList();
			for(DSViewVO vo : dsList) {
				JSONObject DSViewjson = new JSONObject();
				DSViewjson.put("AUTH_YN", "");
				DSViewjson.put("DS_VIEW_ID", vo.getDS_VIEW_ID());
				DSViewjson.put("DS_VIEW_NM", vo.getDS_VIEW_NM());
				DSViewjson.put("DS_NM", vo.getDS_NM());
				DSViewjson.put("DBMS_TYPE", vo.getDBMS_TYPE());
				DSViewjson.put("OWNER_NM", vo.getOWNER_NM());
				DSViewjson.put("DB_NM",vo.getDB_NM());
				DSViewjson.put("IP",vo.getIP());
				DSViewjson.put("USER_ID",vo.getUSER_ID());
				DSViewjson.put("PASSWD",vo.getPASSWD());
				DSViewjson.put("PORT", vo.getPORT());
				DSViewArrayList.add(DSViewjson);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("groupArrayList", groupArrayList);
		obj.put("DSViewArrayList", DSViewArrayList);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getUserDSViewAuth.do")
	public void getUserDSViewAuth(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		ArrayList<JSONObject> dsViewList = new ArrayList<JSONObject>();
		JSONObject resultobj = new JSONObject();
		try {
			out = response.getWriter();
			int userNo = Integer.parseInt(SecureUtils.getParameter(request, "userNo"));
			List<UserAuthDataSetVO> dsView = configService.selectUserAuthDataSet(userNo);
			for(UserAuthDataSetVO vo : dsView) {
				JSONObject obj = new JSONObject();
				obj.put("userId", vo.getUserNo());
				obj.put("DataJson", vo.getDataAuthnJson().toString());
				dsViewList.add(obj);
			}
			resultobj.put("dsViewResult", dsViewList);
		} catch (IOException e) {
			e.printStackTrace();
			throw new Error(e);
		}finally {
			out.print(resultobj);
			out.flush();
			out.close();
		}
	}

	@RequestMapping("/getGroupDSViewAuth.do")
	public void getGroupDSViewAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		int groupNo = Integer.parseInt(SecureUtils.getParameter(request, "groupNo"));
		ArrayList<JSONObject> dsViewList = new ArrayList<JSONObject>();
//		try {
			List<GrpAuthDataSetVO> dsView = configService.selectGroupAuthDataSet(groupNo);
			for(GrpAuthDataSetVO vo : dsView) {
				JSONObject obj = new JSONObject();
				obj.put("groupId", vo.getGRP_ID());
				obj.put("DataJson", vo.getDataAuthnJson().toString());
				dsViewList.add(obj);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
		JSONObject obj = new JSONObject();
		obj.put("dsViewResult", dsViewList);
		out.print(obj);
		out.flush();
		out.close();
	}
	
	@RequestMapping("/getAuthGroupDsList.do")
	public void authGroupDsList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		ArrayList<JSONObject> groupArrayList = new ArrayList<JSONObject>();
		ArrayList<JSONObject> dsArrayList = new ArrayList<JSONObject>();

//		try {
			List<UserGroupVO> groupList = configService.selectGroupAuthDsList();

			for(UserGroupVO groups : groupList) {
				JSONObject groupjson = new JSONObject();
				groupjson.put("AUTH_YN", groups.getAuthCount() > 0 ? "Y" : "N");
				groupjson.put("그룹NO", groups.getGRP_ID());
				groupjson.put("그룹명", groups.getGRP_NM());
				groupjson.put("설명", groups.getGRP_DESC());
				groupArrayList.add(groupjson);
			}

			List<DataSourceVO> dsList = configService.selectDsList();
			for(DataSourceVO vo : dsList) {
				JSONObject dsjson = new JSONObject();
				dsjson.put("AUTH_YN", "");
				dsjson.put("DS_ID", vo.getDS_ID());
				dsjson.put("DS_NM", vo.getDS_NM());
				dsjson.put("DBMS_TYPE", vo.getDBMS_TYPE());
				dsjson.put("OWNER_NM", vo.getOWNER_NM());
				dsjson.put("DB_NM",vo.getDB_NM());
				dsjson.put("IP",vo.getIP());
				dsjson.put("USER_ID",vo.getUSER_ID());
				dsjson.put("PASSWD",vo.getPASSWD());
				dsjson.put("PORT", vo.getPORT());
				dsjson.put("CONN_TYPE", vo.getCONN_TYPE());
				dsArrayList.add(dsjson);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("groupArrayList", groupArrayList);
		obj.put("dsArrayList", dsArrayList);
		out.print(obj);
		out.flush();
		out.close();
	}
	
	@RequestMapping("/getAuthUserDsList.do")
	public void authUserDsList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		ArrayList<JSONObject> userArrayList = new ArrayList<JSONObject>();
		ArrayList<JSONObject> dsArrayList = new ArrayList<JSONObject>();

//		try {
			List<UserGroupVO> userList = configService.selectUserAuthDsList();

			for(UserGroupVO users : userList) {
				JSONObject userjson = new JSONObject();
				userjson.put("AUTH_YN", users.getAuthCount() > 0 ? "Y" : "N");
				userjson.put("사용자NO", users.getUSER_NO());
				userjson.put("사용자ID", users.getUSER_ID());
				userjson.put("사용자명", users.getUSER_NM());
				userjson.put("그룹명", users.getGRP_NM());
				userArrayList.add(userjson);
			}


			List<DataSourceVO> dsList = configService.selectDsList();
			for(DataSourceVO vo : dsList) {
				JSONObject dsjson = new JSONObject();
				dsjson.put("AUTH_YN", "");
				dsjson.put("DS_NM", vo.getDS_NM());
				dsjson.put("DS_ID", vo.getDS_ID());
				dsjson.put("DBMS_TYPE", vo.getDBMS_TYPE());
				dsjson.put("OWNER_NM", vo.getOWNER_NM());
				dsjson.put("DB_NM",vo.getDB_NM());
				dsjson.put("IP",vo.getIP());
				dsjson.put("USER_ID",vo.getUSER_ID());
				dsjson.put("PASSWD",vo.getPASSWD());
				dsjson.put("PORT", vo.getPORT());
				dsjson.put("CONN_TYPE", vo.getCONN_TYPE());
				dsArrayList.add(dsjson);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("userArrayList", userArrayList);
		obj.put("dsArrayList", dsArrayList);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getDsInformation.do")
	public void getDsInformation(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
//		int userNo = Integer.parseInt(SecureUtil.getParameter(request, "userNo"));
		int dsViewId = Integer.parseInt(SecureUtils.getParameter(request, "dsViewId"));

		ArrayList<JSONObject> cubeArray = new ArrayList<JSONObject>();
//		try {
			List<CubeVO> CubeVO = configService.selectCubeList(dsViewId);
			JSONObject rootCubeObj = new JSONObject();
			rootCubeObj.put("cubeId", 1);
			rootCubeObj.put("dsViewId", 1);
			rootCubeObj.put("cubeNm", "주제영역");
			rootCubeObj.put("cubeDesc", "");
			rootCubeObj.put("cubeOrdinal", 0);
			rootCubeObj.put("parentId", 0);
			cubeArray.add(rootCubeObj);
			rootCubeObj = null;
			for(CubeVO vo : CubeVO) {
				JSONObject obj = new JSONObject();
				obj.put("cubeId", vo.getCUBE_ID());
				obj.put("dsViewId", vo.getDS_VIEW_ID());
				obj.put("cubeNm", vo.getCUBE_NM());
				obj.put("cubeDesc", vo.getCUBE_DESC());
				obj.put("cubeOrdinal", vo.getCUBE_ORDINAL());
				obj.put("parentId", 1);
				cubeArray.add(obj);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		ArrayList<JSONObject> DSViewDimArray = new ArrayList<JSONObject>();;
//		try {
			List<DSViewDimVO> DSViewDimVO = configService.selectDSViewDimList(dsViewId);
			JSONObject rootDSViewDimObj = new JSONObject();
			rootDSViewDimObj.put("DS_VIEW_ID", 1);
			rootDSViewDimObj.put("DIM_UNI_NM", "차원");
			rootDSViewDimObj.put("DIM_TBL_NM", "차원");
			rootDSViewDimObj.put("ordering", 1);
			rootDSViewDimObj.put("DIM_ORDINAL", 0);
			rootDSViewDimObj.put("parentId", 0);
			DSViewDimArray.add(rootDSViewDimObj);
			rootDSViewDimObj = null;
			int i = 2;
			for(DSViewDimVO vo : DSViewDimVO) {
				JSONObject obj = new JSONObject();
				obj.put("ordering", i++);
				obj.put("DS_VIEW_ID", vo.getDS_VIEW_ID());
				obj.put("DIM_UNI_NM", vo.getDIM_UNI_NM());
				obj.put("DIM_TBL_NM", vo.getTBL_NM());
				obj.put("DIM_ORDINAL", vo.getDIM_ORDINAL());
				obj.put("parentId", 1);
				DSViewDimArray.add(obj);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		ArrayList<JSONObject> DSViewHieArray = new ArrayList<JSONObject>();
//		try {
			List<DSViewHieVO> DSViewHieVO = configService.selectDSViewHieList(dsViewId);
			JSONObject rootDSViewHieObj = new JSONObject();
			rootDSViewHieObj.put("DS_VIEW_ID", 1);
			rootDSViewHieObj.put("DIM_UNI_NM", "멤버");
			rootDSViewHieObj.put("HIE_UNI_NM", "멤버");
			rootDSViewHieObj.put("HIE_CAPTION", "멤버");
			rootDSViewHieObj.put("TBL_NM", "멤버");
			rootDSViewHieObj.put("KEY_COL", "멤버");
			rootDSViewHieObj.put("CAPTION_COL", "멤버");
			rootDSViewHieObj.put("ordering", 1);
			rootDSViewHieObj.put("IS_AUTH", "1");
			rootDSViewHieObj.put("parentId", 0);
			DSViewHieArray.add(rootDSViewHieObj);
			i=2;
			for(DSViewHieVO vo : DSViewHieVO) {
				JSONObject obj = new JSONObject();
				obj.put("DS_VIEW_ID", vo.getDS_VIEW_ID());
				obj.put("DIM_UNI_NM", vo.getDIM_UNI_NM());
				obj.put("HIE_UNI_NM", vo.getHIE_UNI_NM());
//				obj.put("KEY_COL", vo.getKEY_COL());
				obj.put("TBL_NM", vo.getTBL_NM());
				obj.put("KEY_COL", vo.getKEY_COL());
				obj.put("CAPTION_COL", vo.getNAME_COL());
				obj.put("IS_AUTH", vo.getIS_AUTH());
				obj.put("ordering", i++);
				DSViewHieArray.add(obj);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("cubeArray", cubeArray);
		obj.put("DSViewDimArray", DSViewDimArray);
		obj.put("DSViewHieArray", DSViewHieArray);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping(value= "/getMemberDataList.do", method = { RequestMethod.POST })
//	public void getMemberDataList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException, SQLException, ClassNotFoundException {
//		response.setCharacterEncoding("utf-8");
//		PrintWriter out = response.getWriter();
//
//		String IP = SecureUtils.getParameter(request, "IP");
//		String PORT = SecureUtils.getParameter(request, "PORT");
//		String USER_ID = SecureUtils.getParameter(request, "USER_ID");
//		String PASSWD = SecureUtils.getParameter(request, "PASSWD");
//		String DBMS_TYPE = SecureUtils.getParameter(request, "DBMS_TYPE");
//		String DB_NM = SecureUtils.getParameter(request, "DB_NM");
//		String DS_VIEW_ID = SecureUtils.getParameter(request, "DS_VIEW_ID");
//		JSONArray arr = JSONArray.fromObject(request.getParameter("data"));
//
//		JSONObject returnObj = new JSONObject();
//		String driverClass = "";
//		ArrayList<JSONObject> tests = new ArrayList<JSONObject>();
//		Connection conn = null;
//		ResultSet rs = null;
//		PreparedStatement pstmt = null;
//		ResultSetMetaData rsmd;
//
//		if(DBMS_TYPE.equals("MS-SQL")) {
//			driverClass = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
//			Class.forName(driverClass);
//			String url = "jdbc:sqlserver://" + IP + ":" + PORT + ";DatabaseName=" + DB_NM;
//			conn = DriverManager.getConnection(url, USER_ID, PASSWD);
//
//			for(int i=0; i<arr.size();i++) {
//
//				net.sf.json.JSONObject obj = arr.getJSONObject(i);
//				String sql ="SELECT ";
//				sql += obj.getString("KEY_COL") + " AS KEY_COL, "+ obj.getString("KEY_COL") + " AS CAPTION_COL FROM " + obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", "") + " GROUP BY " + obj.getString("KEY_COL") + ", "+ obj.getString("KEY_COL") + " ORDER BY "+obj.getString("KEY_COL")+" ASC";
//				System.out.println("MS-SQL KEY_COL & CAPTION_COL :\n"+sql);
//
//				pstmt = conn.prepareStatement(sql);
//				rs = pstmt.executeQuery();
//				rsmd = rs.getMetaData();
//
//				JSONObject rootElement = new JSONObject();
//				rootElement.put("DS_VIEW_ID", DS_VIEW_ID);
//				rootElement.put("KEY_COL", obj.getString("KEY_COL"));
//				rootElement.put("CAPTION_COL", obj.getString("KEY_COL"));
//				rootElement.put("MEMBER_NM", obj.getString("KEY_COL"));
//				rootElement.put("ParentId", 0);
//				rootElement.put("ID", i+1);
//				tests.add(rootElement);
//				int loop = 1;
//				while (rs.next()) {
//					JSONObject result = new JSONObject();
//					for (int j = 1; j <= rsmd.getColumnCount(); j++) {
//						result.put("MEMBER_NM", rs.getString(j));
//					}
//					result.put("ID", Integer.parseInt((i+1)+""+(loop++)));
//					result.put("DIM_UNI_NM", obj.getString("DIM_UNI_NM"));
//					result.put("HIE_UNI_NM", obj.getString("HIE_UNI_NM"));
//					result.put("KEY_COL", obj.getString("KEY_COL"));
//					result.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
//					result.put("ParentId", i+1);
//
//					tests.add(result);
//				}
//				returnObj.put(obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", ""),tests);
//			}
//		}else if(DBMS_TYPE.equals("DB2BLU")) {
//			driverClass = "com.ibm.db2.jcc.DB2Driver";
//			Class.forName(driverClass);
//			String url = "jdbc:db2://" + IP + ":" + PORT + "/" + DB_NM;
//			conn = DriverManager.getConnection(url, USER_ID, PASSWD);
//			for(int i=0; i<arr.size();i++) {
//				net.sf.json.JSONObject obj = arr.getJSONObject(i);
//				String sql ="SELECT ";
//				sql += obj.getString("KEY_COL") + " AS KEY_COL, "+ obj.getString("KEY_COL") + " AS CAPTION_COL FROM " + obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", "") + " GROUP BY " + obj.getString("KEY_COL") + ", "+ obj.getString("KEY_COL") + " ORDER BY "+obj.getString("KEY_COL")+" ASC";
//				System.out.println("DB2 KEY_COL & CAPTION_COL :\n"+sql);
//
//				pstmt = conn.prepareStatement(sql);
//				rs = pstmt.executeQuery();
//				rsmd = rs.getMetaData();
//
//				JSONObject rootElement = new JSONObject();
//				rootElement.put("KEY_COL", obj.getString("KEY_COL"));
//				rootElement.put("CAPTION_COL", obj.getString("KEY_COL"));
//				rootElement.put("ParentId", 0);
//				rootElement.put("ID", i+1);
//				rootElement.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
//				tests.add(rootElement);
//				int temp = 1;
//				while (rs.next()) {
//
//					JSONObject result = new JSONObject();
//					for (int j = 1; j <= rsmd.getColumnCount(); j++) {
//						result.put(rsmd.getColumnLabel(j), rs.getString(j));
//					}
//					result.put("ID", i+"_"+temp++);
//					result.put("ParentId", i+1);
//					result.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
//					tests.add(result);
//				}
//				returnObj.put(obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", ""),tests);
//			}
//
//		} else if(DBMS_TYPE.equals("ORACLE")) {
//			driverClass = "oracle.jdbc.driver.OracleDriver";
//			Class.forName(driverClass);
//			String url = "jdbc:oracle:thin:@" + IP + ":" + PORT + ":" + DB_NM;
//			conn = DriverManager.getConnection(url, USER_ID, PASSWD);
//
//			for(int i=0; i<arr.size();i++) {
//
//				net.sf.json.JSONObject obj = arr.getJSONObject(i);
//				String sql ="SELECT ";
//				sql += obj.getString("KEY_COL") + " AS KEY_COL, "+ obj.getString("KEY_COL") + " AS CAPTION_COL FROM " + obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", "") + " GROUP BY " + obj.getString("KEY_COL") + ", "+ obj.getString("KEY_COL") + " ORDER BY "+obj.getString("KEY_COL")+" ASC";
//				System.out.println("ORACLE KEY_COL & CAPTION_COL :\n"+sql);
//
//				pstmt = conn.prepareStatement(sql);
//				rs = pstmt.executeQuery();
//				rsmd = rs.getMetaData();
//
//				JSONObject rootElement = new JSONObject();
//				rootElement.put("DS_VIEW_ID", DS_VIEW_ID);
//				rootElement.put("KEY_COL", obj.getString("KEY_COL"));
//				rootElement.put("CAPTION_COL", obj.getString("KEY_COL"));
//				rootElement.put("MEMBER_NM", obj.getString("KEY_COL"));
//				rootElement.put("ParentId", 0);
//				rootElement.put("ID", i+1);
//				tests.add(rootElement);
//				int loop = 1;
//				while (rs.next()) {
//					JSONObject result = new JSONObject();
//					for (int j = 1; j <= rsmd.getColumnCount(); j++) {
//						result.put("MEMBER_NM", rs.getString(j));
//					}
//					result.put("ID", Integer.parseInt((i+1)+""+(loop++)));
//					result.put("DIM_UNI_NM", obj.getString("DIM_UNI_NM"));
//					result.put("HIE_UNI_NM", obj.getString("HIE_UNI_NM"));
//					result.put("KEY_COL", obj.getString("KEY_COL"));
//					result.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
//					result.put("ParentId", i+1);
//
//					tests.add(result);
//				}
//				returnObj.put(obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", ""),tests);
//			}
//
//
//		}
//		JSONObject obj = new JSONObject();
//		obj.put("dataResult", returnObj);
//		out.print(obj);
//		out.close();
////		System.out.println(authArr.toString());
//	}
	public void getMemberDataList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException, Base64DecodingException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String IP = SecureUtils.getParameter(request, "IP");
		String PORT = SecureUtils.getParameter(request, "PORT");
		String USER_ID = SecureUtils.getParameter(request, "USER_ID");
		String PASSWD = SecureUtils.getParameter(request, "PASSWD");
		String DBMS_TYPE = SecureUtils.getParameter(request, "DBMS_TYPE");
		String DB_NM = SecureUtils.getParameter(request, "DB_NM");
		String DS_VIEW_ID = SecureUtils.getParameter(request, "DS_VIEW_ID");
		JSONArray arr = JSONArray.fromObject(new String(Base64.decode(SecureUtils.getParameter(request, "data").getBytes())));

		String driverClass = "";
		ArrayList<JSONObject> members = new ArrayList<JSONObject>();
		Connection conn = null;
		ResultSet rs = null;
		PreparedStatement pstmt = null;
		ResultSetMetaData rsmd;
		if(arr != null) {
			if(DBMS_TYPE.equals("MS-SQL")) {
				driverClass = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
				try {
					Class.forName(driverClass);
					String url = "jdbc:sqlserver://" + IP + ":" + PORT + ";DatabaseName=" + DB_NM;
					conn = DriverManager.getConnection(url, USER_ID, PASSWD);

					for(int i=0; i<arr.size();i++) {

						net.sf.json.JSONObject obj = arr.getJSONObject(i);
						String tbl_nm = SecureUtils.sqlsecure(obj.getString("TBL_NM"));
						String key_col = SecureUtils.sqlsecure(obj.getString("KEY_COL"));
						String sql ="SELECT ";
	//					sql += obj.getString("KEY_COL") + " AS KEY_COL, "+ obj.getString("KEY_COL") + " AS CAPTION_COL FROM " + obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", "") + " GROUP BY " + obj.getString("KEY_COL") + ", "+ obj.getString("KEY_COL") + " ORDER BY "+obj.getString("KEY_COL")+" ASC";
//						sql += key_col + " AS KEY_COL, "+ key_col + " AS CAPTION_COL FROM " + tbl_nm + " GROUP BY " + key_col + ", "+ key_col + " ORDER BY "+key_col+" ASC";

						sql += "TOP(SELECT count(*) FROM " + tbl_nm + ") "+ key_col + " AS KEY_COL, "+ key_col + " AS CAPTION_COL FROM " + tbl_nm + " GROUP BY " + key_col + ", " + key_col + " ORDER BY " + key_col + " ASC";
	//					System.out.println("MS-SQL KEY_COL & CAPTION_COL :\n"+sql);

						pstmt = conn.prepareStatement(sql);
//						pstmt.setString(1, key_col);
//						pstmt.setString(2, key_col);

						rs = pstmt.executeQuery();
						rsmd = rs.getMetaData();


						JSONObject rootElement = new JSONObject();
						rootElement.put("DS_VIEW_ID", DS_VIEW_ID);
						rootElement.put("KEY_COL", key_col);
						rootElement.put("CAPTION_COL", key_col);
						/* DOGFOOT ktkang 주제영역 권한 저장 오류 수정  20200811 */
						rootElement.put("MEMBER_NM", key_col);
						rootElement.put("ParentId", 0);
						rootElement.put("ID", i+1);
						members.add(rootElement);
						int loop = 1;
						while (rs.next()) {
							JSONObject result = new JSONObject();
							for (int j = 1; j <= rsmd.getColumnCount(); j++) {
								result.put(rsmd.getColumnLabel(j), rs.getString("KEY_COL"));
							}
							result.put("ID", i+"_"+loop++);
							result.put("ParentId", i+1);
							result.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
							result.put("DIM_UNI_NM", obj.getString("DIM_UNI_NM"));
							result.put("HIE_UNI_NM", obj.getString("HIE_UNI_NM"));
							result.put("MEMBER_NM", rs.getString("KEY_COL"));
							members.add(result);
						}
					}
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NumberFormatException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (JSONException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
		        	if (pstmt != null) {
		            	try {
		            		pstmt.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		pstmt = null;
		            	}
		            }
		            if (rs != null) {
		            	try {
		            		rs.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		rs = null;
		            	}
		            }
		            if (conn != null) {
		            	try {
		            		conn.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		conn = null;
		            	}
		            }
		        }

			}else if(DBMS_TYPE.equals("DB2BLU")) {
				driverClass = "com.ibm.db2.jcc.DB2Driver";
				try {
					Class.forName(driverClass);
					String url = "jdbc:db2://" + IP + ":" + PORT + "/" + DB_NM;
					conn = DriverManager.getConnection(url, USER_ID, PASSWD);
					for(int i=0; i<arr.size();i++) {
						net.sf.json.JSONObject obj = arr.getJSONObject(i);
						String tbl_nm = SecureUtils.sqlsecure(obj.getString("TBL_NM"));
						String key_col = SecureUtils.sqlsecure(obj.getString("KEY_COL"));
						String sql ="SELECT ";
	//					sql += obj.getString("KEY_COL") + " AS KEY_COL, "+ obj.getString("KEY_COL") + " AS CAPTION_COL FROM " + obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", "") + " GROUP BY " + obj.getString("KEY_COL") + ", "+ obj.getString("KEY_COL") + " ORDER BY "+obj.getString("KEY_COL")+" ASC";
//						sql += obj.getString("KEY_COL") + " AS KEY_COL, "+ key_col + " AS CAPTION_COL FROM " + tbl_nm + " GROUP BY " + key_col + ", "+ key_col + " ORDER BY "+key_col+" ASC";
						sql += " "+ key_col +" AS KEY_COL, "+ key_col +" AS CAPTION_COL FROM " + tbl_nm + " GROUP BY " + key_col + ", " + key_col + " ORDER BY " + key_col + " ASC";
	//					System.out.println("MS-SQL KEY_COL & CAPTION_COL :\n"+sql);

						pstmt = conn.prepareStatement(sql);
//						pstmt.setString(1, key_col);
//						pstmt.setString(2, key_col);

						rs = pstmt.executeQuery();
						rsmd = rs.getMetaData();

						JSONObject rootElement = new JSONObject();
						rootElement.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
						rootElement.put("KEY_COL", key_col);
						rootElement.put("CAPTION_COL", key_col);
						rootElement.put("MEMBER_NM", key_col);
						rootElement.put("ParentId", 0);
						rootElement.put("ID", i+1);
						members.add(rootElement);
						int temp = 1;
						while (rs.next()) {
							JSONObject result = new JSONObject();
							for (int j = 1; j <= rsmd.getColumnCount(); j++) {
								result.put(rsmd.getColumnLabel(j), rs.getString(j));
							}
							result.put("ID", i+"_"+temp++);
							result.put("ParentId", i+1);
							result.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
							result.put("DIM_UNI_NM", obj.getString("DIM_UNI_NM"));
							result.put("HIE_UNI_NM", obj.getString("HIE_UNI_NM"));
							result.put("MEMBER_NM", rs.getString("KEY_COL"));
							members.add(result);
						}
					}
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NumberFormatException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (JSONException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
		        	if (pstmt != null) {
		            	try {
		            		pstmt.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		pstmt = null;
		            	}
		            }
		            if (rs != null) {
		            	try {
		            		rs.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		rs = null;
		            	}
		            }
		            if (conn != null) {
		            	try {
		            		conn.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		conn = null;
		            	}
		            }
		        }


			} else if(DBMS_TYPE.equals("ORACLE")) {
				driverClass = "oracle.jdbc.driver.OracleDriver";
				try {
					Class.forName(driverClass);
					String url = "jdbc:oracle:thin:@" + IP + ":" + PORT + ":" + DB_NM;
					conn = DriverManager.getConnection(url, USER_ID, PASSWD);

					for(int i=0; i<arr.size();i++) {

						net.sf.json.JSONObject obj = arr.getJSONObject(i);
						String sql ="SELECT ";
						String tbl_nm = SecureUtils.sqlsecure(obj.getString("TBL_NM"));
						String key_col = SecureUtils.sqlsecure(obj.getString("KEY_COL"));
	//					sql += obj.getString("KEY_COL") + " AS KEY_COL, "+ obj.getString("KEY_COL") + " AS CAPTION_COL FROM " + obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", "") + " GROUP BY " + obj.getString("KEY_COL") + ", "+ obj.getString("KEY_COL") + " ORDER BY "+obj.getString("KEY_COL")+" ASC";
						sql += " "+ key_col +" AS KEY_COL, "+ key_col +" AS CAPTION_COL FROM " + tbl_nm + " GROUP BY " + key_col + ", " + key_col + " ORDER BY " + key_col + " ASC";
						//					System.out.println("MS-SQL KEY_COL & CAPTION_COL :\n"+sql);

						pstmt = conn.prepareStatement(sql);
//						pstmt.setString(1, key_col);
//						pstmt.setString(2, key_col);

						rs = pstmt.executeQuery();
						rsmd = rs.getMetaData();

						JSONObject rootElement = new JSONObject();
						rootElement.put("DS_VIEW_ID", DS_VIEW_ID);
						rootElement.put("KEY_COL", key_col);
						rootElement.put("CAPTION_COL", key_col);
						rootElement.put("MEMBER_NM", key_col);
						rootElement.put("ParentId", 0);
						rootElement.put("ID", i+1);
						members.add(rootElement);
						int loop = 1;
						while (rs.next()) {
							JSONObject result = new JSONObject();
							for (int j = 1; j <= rsmd.getColumnCount(); j++) {
								result.put(rsmd.getColumnLabel(j), rs.getString(j));
							}
							result.put("ID", i+"_"+loop++);
							result.put("ParentId", i+1);
							result.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
							result.put("DIM_UNI_NM", obj.getString("DIM_UNI_NM"));
							result.put("HIE_UNI_NM", obj.getString("HIE_UNI_NM"));
							result.put("MEMBER_NM", rs.getString("KEY_COL"));
							members.add(result);
						}
					}
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NumberFormatException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (JSONException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
		        	if (pstmt != null) {
		            	try {
		            		pstmt.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		pstmt = null;
		            	}
		            }
		            if (rs != null) {
		            	try {
		            		rs.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		rs = null;
		            	}
		            }
		            if (conn != null) {
		            	try {
		            		conn.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		conn = null;
		            	}
		            }
		        }
			} else if(DBMS_TYPE.equals("TIBERO")) {
				driverClass = "com.tmax.tibero.jdbc.TbDriver";
				try {
					Class.forName(driverClass);
					String url = "jdbc:tibero:thin:@" + IP + ":" + PORT + ":" + DB_NM;
					conn = DriverManager.getConnection(url, USER_ID, PASSWD);

					for(int i=0; i<arr.size();i++) {

						net.sf.json.JSONObject obj = arr.getJSONObject(i);
						String tbl_nm = SecureUtils.sqlsecure(obj.getString("TBL_NM"));
						String key_col = SecureUtils.sqlsecure(obj.getString("KEY_COL"));
						String sql ="SELECT ";
	//					sql += obj.getString("KEY_COL") + " AS KEY_COL, "+ obj.getString("KEY_COL") + " AS CAPTION_COL FROM " + obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", "") + " GROUP BY " + obj.getString("KEY_COL") + ", "+ obj.getString("KEY_COL") + " ORDER BY "+obj.getString("KEY_COL")+" ASC";
						sql += " "+ key_col +" AS KEY_COL, "+ key_col +" AS CAPTION_COL FROM " + tbl_nm + " GROUP BY " + key_col + ", " + key_col + " ORDER BY " + key_col + " ASC";
						//					System.out.println("MS-SQL KEY_COL & CAPTION_COL :\n"+sql);

						pstmt = conn.prepareStatement(sql);
//						pstmt.setString(1, key_col);
//						pstmt.setString(2, key_col);

						rs = pstmt.executeQuery();
						rsmd = rs.getMetaData();

						JSONObject rootElement = new JSONObject();
						rootElement.put("DS_VIEW_ID", DS_VIEW_ID);
						rootElement.put("KEY_COL", key_col);
						rootElement.put("CAPTION_COL", key_col);
						rootElement.put("MEMBER_NM", key_col);
						rootElement.put("ParentId", 0);
						rootElement.put("ID", i+1);
						members.add(rootElement);
						int loop = 1;
						while (rs.next()) {
							JSONObject result = new JSONObject();
							for (int j = 1; j <= rsmd.getColumnCount(); j++) {
								result.put(rsmd.getColumnLabel(j), rs.getString(j));
							}
							result.put("ID", i+"_"+loop++);
							result.put("ParentId", i+1);
							result.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
							result.put("DIM_UNI_NM", obj.getString("DIM_UNI_NM"));
							result.put("HIE_UNI_NM", obj.getString("HIE_UNI_NM"));
							result.put("MEMBER_NM", rs.getString("KEY_COL"));
							members.add(result);
						}
					}
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NumberFormatException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (JSONException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
		        	if (pstmt != null) {
		            	try {
		            		pstmt.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		pstmt = null;
		            	}
		            }
		            if (rs != null) {
		            	try {
		            		rs.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		rs = null;
		            	}
		            }
		            if (conn != null) {
		            	try {
		            		conn.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		conn = null;
		            	}
		            }
		        }
			} else if(DBMS_TYPE.equals("ALTIBASE")) {
				driverClass = "Altibase.jdbc.driver.AltibaseDriver";
				try {
					Class.forName(driverClass);
					String url = "jdbc:Altibase://" + IP + ":" + PORT + "/" + DB_NM;
					conn = DriverManager.getConnection(url, USER_ID, PASSWD);

					for(int i=0; i<arr.size();i++) {

						net.sf.json.JSONObject obj = arr.getJSONObject(i);
						String tbl_nm = SecureUtils.sqlsecure(obj.getString("TBL_NM"));
						String key_col = SecureUtils.sqlsecure(obj.getString("KEY_COL"));
						String sql ="SELECT ";
	//					sql += obj.getString("KEY_COL") + " AS KEY_COL, "+ obj.getString("KEY_COL") + " AS CAPTION_COL FROM " + obj.getString("DIM_UNI_NM").replaceAll("[\\[\\]]", "") + " GROUP BY " + obj.getString("KEY_COL") + ", "+ obj.getString("KEY_COL") + " ORDER BY "+obj.getString("KEY_COL")+" ASC";
						sql += " "+ key_col +" AS KEY_COL, "+ key_col +" AS CAPTION_COL FROM " + tbl_nm + " GROUP BY " + key_col + ", " + key_col + " ORDER BY " + key_col + " ASC";
						//					System.out.println("MS-SQL KEY_COL & CAPTION_COL :\n"+sql);

						pstmt = conn.prepareStatement(sql);
//						pstmt.setString(1, key_col);
//						pstmt.setString(2, key_col);

						rs = pstmt.executeQuery();
						rsmd = rs.getMetaData();

						JSONObject rootElement = new JSONObject();
						rootElement.put("DS_VIEW_ID", DS_VIEW_ID);
						rootElement.put("KEY_COL", key_col);
						rootElement.put("CAPTION_COL", key_col);
						rootElement.put("MEMBER_NM", key_col);
						rootElement.put("ParentId", 0);
						rootElement.put("ID", i+1);
						members.add(rootElement);
						int loop = 1;
						while (rs.next()) {
							JSONObject result = new JSONObject();
							for (int j = 1; j <= rsmd.getColumnCount(); j++) {
								result.put(rsmd.getColumnLabel(j), rs.getString(j));
							}
							result.put("ID", i+"_"+loop++);
							result.put("ParentId", i+1);
							result.put("DS_VIEW_ID", Integer.parseInt(DS_VIEW_ID));
							result.put("DIM_UNI_NM", obj.getString("DIM_UNI_NM"));
							result.put("HIE_UNI_NM", obj.getString("HIE_UNI_NM"));
							result.put("MEMBER_NM", rs.getString("KEY_COL"));
							members.add(result);
						}
					}
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NumberFormatException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (JSONException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
		        	if (pstmt != null) {
		            	try {
		            		pstmt.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		pstmt = null;
		            	}
		            }
		            if (rs != null) {
		            	try {
		            		rs.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		rs = null;
		            	}
		            }
		            if (conn != null) {
		            	try {
		            		conn.close();
		            	} catch (SQLException e) {
		            		e.printStackTrace();
		            		conn = null;
		            	}
		            }
		        }
			}
			JSONObject obj = new JSONObject();
			obj.put("dataResult", members);
			out.print(obj);
			out.close();
		}
//		System.out.println(authArr.toString());
	}

	/* DOGFOOT ktkang 사용자 데이터 권한 오류 수정  20200923 */
	@RequestMapping(value= "/saveAuthUserData.do", method = { RequestMethod.POST })
	public void saveAuthUserData(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		org.json.JSONObject resultObj = new org.json.JSONObject();
		org.json.JSONObject obj =new org.json.JSONObject();
		InsertUserAuthDataSetVO AuthVo = new InsertUserAuthDataSetVO();
//		try {
			String userNo = SecureUtils.getParameter(request,"userId");
			String newData = SecureUtils.getParameter(request,"NewDataSet");
			newData = SecureUtils.unsecure(newData);
			configService.initUserDataAuth(Integer.parseInt(userNo));
			if (newData.length() > 0) {
				obj.put("NewDataSet", new org.json.JSONObject(newData));
				String encodedObj = Base64.encode(XML.toString(obj).getBytes()).toString();
//				System.out.println(encodedObj);
				AuthVo.setUserNo(userNo);
				AuthVo.setDataBase64(encodedObj);
				configService.insertUserAuthData(AuthVo);
			}
			resultObj.put("code",200);
//		} catch(IOException e) {
//			e.printStackTrace();
//			resultObj.put("code", 500);
//		} finally {
			out.print(resultObj);
			out.flush();
			out.close();
//		}
//		System.out.println(userNo + "\n"+obj.toString());
	}

	@RequestMapping(value= "/saveAuthGroupData.do", method = { RequestMethod.POST })
	public void saveAuthGroupData(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		String groupId = request.getParameter("groupId");
		String newData = SecureUtils.unsecure(SecureUtils.getParameter(request,"NewDataSet"));

		org.json.JSONObject resultObj = new org.json.JSONObject();
		org.json.JSONObject obj =new org.json.JSONObject();
		InsertGroupAuthDataSetVO AuthVo = new InsertGroupAuthDataSetVO();
//		try {
			configService.initGroupDataAuth(Integer.parseInt(groupId));
			if(newData != null) {
				if (newData.length() > 0) {
					obj.put("NewDataSet", new org.json.JSONObject(newData));
					String encodedObj = Base64.encode(XML.toString(obj).getBytes()).toString();
//					System.out.println(encodedObj);
					AuthVo.setGroupId(groupId);
					AuthVo.setDataBase64(encodedObj);
					configService.insertGroupAuthData(AuthVo);
				}
			}
			resultObj.put("code",200);
//		}
//		catch(Exception e) {
//			e.printStackTrace();
//			resultObj.put("code", 500);
//		}
//		System.out.println(groupId + "\n"+obj.toString());
		out.print(resultObj);
		out.flush();
		out.close();

	}

	@RequestMapping(value="/getUserAuthReport.do", produces="text/plain;charset=UTF-8")
	public void getUserAuthReport(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
//		System.out.println("request userNo : "+userNo);

		ArrayList<JSONObject> authFolderList = new ArrayList<JSONObject>();
		ArrayList<JSONObject> authReportList = new ArrayList<JSONObject>();
		JSONObject result = new JSONObject();

		try {
			request.setCharacterEncoding("utf-8");
			out = response.getWriter();
			Integer userNo = Integer.parseInt(SecureUtils.getParameter(request, "userNo"));
			List<UserGrpAuthReportListVO> userAuthFldList = configService.selectUserAuthFolderList(userNo);
			for(UserGrpAuthReportListVO authReport: userAuthFldList) {
				if(authReport.getFLD_ID()!=null) {
					JSONObject obj = new JSONObject();
					obj.put("FLD_ID", authReport.getFLD_ID());
					obj.put("AUTH_VIEW", authReport.getAUTH_VIEW().equals("Y"));
					obj.put("AUTH_PUBLISH", authReport.getAUTH_PUBLISH().equals("Y"));
					obj.put("AUTH_DATAITEM", authReport.getAUTH_DATAITEM().equals("Y"));
					obj.put("AUTH_EXPORT", authReport.getAUTH_EXPORT().equals("Y"));
					authFolderList.add(obj);
				}
			}
			result.put("authFolderList", authFolderList);

			ConfigMasterVO configVo = authenticationService.getConfigMstr();
			if (configVo.getAUTH_REPORT_DETAIL_YN().equals("Y")) {
				List<UserGrpAuthReportListVO> userAuthReportList = configService.selectUserAuthReportList(userNo);
				for(UserGrpAuthReportListVO authReport: userAuthReportList) {
					if(authReport.getFLD_ID()!=null) {
						JSONObject obj = new JSONObject();
						obj.put("FLD_ID", authReport.getFLD_ID());
						obj.put("AUTH_VIEW", authReport.getAUTH_VIEW().equals("Y"));
						obj.put("AUTH_PUBLISH", authReport.getAUTH_PUBLISH().equals("Y"));
						obj.put("AUTH_DATAITEM", authReport.getAUTH_DATAITEM().equals("Y"));
						obj.put("AUTH_EXPORT", authReport.getAUTH_EXPORT().equals("Y"));
						obj.put("ROOTYN", authReport.getROOTYN());
						authReportList.add(obj);
					}
				}
				result.put("authResult", authReportList);
			}
		} catch (IOException e) {
			e.printStackTrace();
			throw new Error(e);
		}finally {
			out.print(result);
			out.flush();
			out.close();
		}
	}

	@RequestMapping(value="/getGrpAuthReport.do", produces="text/plain;charset=UTF-8")
	public void getGrpAuthReport(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;

//		System.out.println("request grpId : "+grpId);

		ArrayList<JSONObject> authFolderList = new ArrayList<JSONObject>();
		ArrayList<JSONObject> authReportList = new ArrayList<JSONObject>();
		JSONObject result = new JSONObject();

		try {
			request.setCharacterEncoding("utf-8");
			out = response.getWriter();
			String grpId = SecureUtils.getParameter(request, "grp_id");
			List<UserGrpAuthReportListVO> grpAuthFldList = configService.selectGrpAuthFolderList(grpId);
			for(UserGrpAuthReportListVO authReport: grpAuthFldList) {
				if(authReport.getFLD_ID()!=null) {
					JSONObject obj = new JSONObject();
					obj.put("FLD_ID", authReport.getFLD_ID());
					obj.put("AUTH_VIEW", authReport.getAUTH_VIEW().equals("Y"));
					obj.put("AUTH_PUBLISH", authReport.getAUTH_PUBLISH().equals("Y"));
					obj.put("AUTH_DATAITEM", authReport.getAUTH_DATAITEM().equals("Y"));
					obj.put("AUTH_EXPORT", authReport.getAUTH_EXPORT().equals("Y"));
					authFolderList.add(obj);
				}
			}
			result.put("authFolderList", authFolderList);


			ConfigMasterVO configVo = authenticationService.getConfigMstr();
			if (configVo.getAUTH_REPORT_DETAIL_YN().equals("Y")) {
					List<UserGrpAuthReportListVO> grpAuthReportList = configService.selectGrpAuthReportList(grpId);
					for(UserGrpAuthReportListVO authReport: grpAuthReportList) {
						if(authReport.getFLD_ID()!=null) {
							JSONObject obj = new JSONObject();
							obj.put("FLD_ID", authReport.getFLD_ID());
							obj.put("AUTH_VIEW", authReport.getAUTH_VIEW().equals("Y"));
							obj.put("AUTH_PUBLISH", authReport.getAUTH_PUBLISH().equals("Y"));
							obj.put("AUTH_DATAITEM", authReport.getAUTH_DATAITEM().equals("Y"));
							obj.put("AUTH_EXPORT", authReport.getAUTH_EXPORT().equals("Y"));
							obj.put("ROOTYN", authReport.getROOTYN());
							authReportList.add(obj);
						}
					}
					result.put("authResult", authReportList);
			}

		} catch (IOException e) {
			e.printStackTrace();
			throw new Error(e);
		}finally {
			out.print(result);
			out.flush();
			out.close();
		}

	}

	@RequestMapping(value="/saveUserFldAuth.do", produces="text/plain;charset=UTF-8",method = { RequestMethod.POST })
	@ResponseBody
	public void saveUserFldAuth(HttpServletRequest request, HttpServletResponse response, Model model,@RequestBody String paramData) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
//		System.out.println(paramData);
		JSONArray authArr = JSONArray.fromObject(paramData);
		JSONObject returnVal = new JSONObject();
		try {
			if(authArr.size() == 1) {
				JSONObject obj = JSONObject.fromObject(authArr.get(0).toString());
				configService.initUserFldAuth(Integer.parseInt(obj.getString("masterObj")));
			}
			else {
				JSONObject obj = JSONObject.fromObject(authArr.get(0).toString());
				configService.initUserFldAuth(Integer.parseInt(obj.getString("masterObj")));
				for(int i=1 ;i<authArr.size();i++) {
					JSONObject insertobj = JSONObject.fromObject(authArr.get(i).toString());
					AuthReportVO insertVo = new AuthReportVO();
					if(insertobj.getString("fldId").equals("0")) {
						return ;
					}
					insertVo.setUserNo(insertobj.getInt("userNo"));
					insertVo.setFld_id(insertobj.getString("fldId"));
					insertVo.setAuth_show(insertobj.getString("authShow"));
					insertVo.setAuth_publish(insertobj.getString("authPublish"));
					insertVo.setAuth_dataitem(insertobj.getString("authDataItem"));
					insertVo.setAuth_export(insertobj.getString("authExport"));
					configService.insertUserFldAuth(insertVo);
				}
			}
			returnVal.put("code", 200);
		}catch (NumberFormatException e) {
			// TODO: handle exception
			e.printStackTrace();
			returnVal.put("code", 500);
		}
		out.print(returnVal);
		out.flush();
		out.close();

	}

	@RequestMapping(value="/saveUserReportAuth.do", produces="text/plain;charset=UTF-8",method = { RequestMethod.POST })
	@ResponseBody
	public void saveUserReportAuth(HttpServletRequest request, HttpServletResponse response, Model model,@RequestBody String paramData) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
//		System.out.println(paramData);
		JSONObject returnVal = new JSONObject();
		try {
			out = response.getWriter();
			JSONArray authArr = JSONArray.fromObject(paramData);
			ConfigMasterVO configVo = authenticationService.getConfigMstr();
			if (configVo.getAUTH_REPORT_DETAIL_YN().equals("Y")) {
				if(authArr.size() == 1) {
					JSONObject obj = JSONObject.fromObject(authArr.get(0).toString());
					configService.initUserReportAuth(Integer.parseInt(obj.getString("masterObj")));
				}
				else {
					JSONObject obj = JSONObject.fromObject(authArr.get(0).toString());
					configService.initUserReportAuth(Integer.parseInt(obj.getString("masterObj")));
					for(int i=1 ;i<authArr.size();i++) {
						JSONObject insertobj = JSONObject.fromObject(authArr.get(i).toString());
						AuthReportVO insertVo = new AuthReportVO();
						if(insertobj.getString("fldId").equals("0")) {
							return ;
						}
						insertVo.setUserNo(insertobj.getInt("userNo"));
						insertVo.setReport_id(insertobj.getString("reportId"));
						insertVo.setFld_id(insertobj.getString("fldId"));
						insertVo.setAuth_show(insertobj.getString("authShow"));
						insertVo.setAuth_publish(insertobj.getString("authPublish"));
						insertVo.setAuth_dataitem(insertobj.getString("authDataItem"));
						insertVo.setAuth_export(insertobj.getString("authExport"));
						configService.insertUserReportAuth(insertVo);
					}
				}
			}
			returnVal.put("code", 200);
		}catch (IOException e) {
			// TODO: handle exception
			e.printStackTrace();
			returnVal.put("code", 500);
		}finally {
			out.print(returnVal);
			out.flush();
			out.close();
		}
	}

	@RequestMapping(value="/saveGrpFldAuth.do", produces="text/plain;charset=UTF-8",method = { RequestMethod.POST })
	@ResponseBody
	public void saveGrpFldAuth(HttpServletRequest request, HttpServletResponse response, Model model,@RequestBody String paramData) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
//		System.out.println(paramData);
		JSONObject returnVal = new JSONObject();
		try {
			out = response.getWriter();
			JSONArray authArr = JSONArray.fromObject(paramData);
			if(authArr.size() == 1) {
				JSONObject obj = JSONObject.fromObject(authArr.get(0).toString());
				configService.initGrpFldAuth(Integer.parseInt(obj.getString("masterObj")));
			}
			else {
				JSONObject obj = JSONObject.fromObject(authArr.get(0).toString());
				configService.initGrpFldAuth(Integer.parseInt(obj.getString("masterObj")));
				for(int i=1 ;i<authArr.size();i++) {
					JSONObject insertobj = JSONObject.fromObject(authArr.get(i).toString());
					AuthReportVO insertVo = new AuthReportVO();
					if(insertobj.getString("fldId").equals("0")) {
						return ;
					}
					insertVo.setGrpid(insertobj.getString("grpId"));
					insertVo.setFld_id(insertobj.getString("fldId"));
					insertVo.setAuth_show(insertobj.getString("authShow"));
					insertVo.setAuth_publish(insertobj.getString("authPublish"));
					insertVo.setAuth_dataitem(insertobj.getString("authDataItem"));
					insertVo.setAuth_export(insertobj.getString("authExport"));
					int result = configService.insertGrpFldAuth(insertVo);
				}
			}
			returnVal.put("code", 200);
		}catch (IOException e) {
			// TODO: handle exception
			e.printStackTrace();
			returnVal.put("code", 500);
		}finally {
			out.print(returnVal);
			out.flush();
			out.close();
		}
	}

	@RequestMapping(value="/saveGrpReportAuth.do", produces="text/plain;charset=UTF-8",method = { RequestMethod.POST })
	@ResponseBody
	public void saveGrpReportAuth(HttpServletRequest request, HttpServletResponse response, Model model,@RequestBody String paramData) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
//		System.out.println(paramData);
		JSONArray authArr = JSONArray.fromObject(paramData);
		JSONObject returnVal = new JSONObject();
//		try {
			ConfigMasterVO configVo = authenticationService.getConfigMstr();
			if (configVo.getAUTH_REPORT_DETAIL_YN().equals("Y")) {
				if(authArr.size() == 1) {
					JSONObject obj = JSONObject.fromObject(authArr.get(0).toString());
					configService.initGrpReportAuth(Integer.parseInt(obj.getString("masterObj")));
				}
				else {
					JSONObject obj = JSONObject.fromObject(authArr.get(0).toString());
					configService.initGrpReportAuth(Integer.parseInt(obj.getString("masterObj")));
					for(int i=1 ;i<authArr.size();i++) {
						JSONObject insertobj = JSONObject.fromObject(authArr.get(i).toString());
						AuthReportVO insertVo = new AuthReportVO();
						if(insertobj.getString("fldId").equals("0")) {
							return ;
						}
						insertVo.setGrpid(insertobj.getString("grpId"));
						insertVo.setReport_id(insertobj.getString("reportId"));
						insertVo.setFld_id(insertobj.getString("fldId"));
						insertVo.setAuth_show(insertobj.getString("authShow"));
						insertVo.setAuth_publish(insertobj.getString("authPublish"));
						insertVo.setAuth_dataitem(insertobj.getString("authDataItem"));
						insertVo.setAuth_export(insertobj.getString("authExport"));
						int result = configService.insertGrpReportAuth(insertVo);
					}
				}
			}
			returnVal.put("code", 200);
//		}catch (Exception e) {
//			// TODO: handle exception
//			e.printStackTrace();
//			returnVal.put("code", 500);
//		}
		out.print(returnVal);
		out.flush();
		out.close();

	}

	@RequestMapping("/getUserPublicReportList.do")
	public void getUserPublicReportList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		ArrayList<JSONObject> userArrayList = new ArrayList<JSONObject>();
		List<UserGroupVO> userList = configService.selectUserList();

		for(UserGroupVO user : userList) {
			JSONObject userjson = new JSONObject();
			userjson.put("사용자NO", user.getUSER_NO());
			userjson.put("사용자ID", user.getUSER_ID());
			userjson.put("사용자명", user.getUSER_NM());
			userjson.put("그룹명", user.getGRP_NM());
			userArrayList.add(userjson);
		}

		ArrayList<JSONObject> userFolderList = new ArrayList<JSONObject>();
		List<PublicFolderListVO> userFolder = null;
		ConfigMasterVO configVo = authenticationService.getConfigMstr();
		if (configVo.getAUTH_REPORT_DETAIL_YN().equals("Y")) {
			userFolder = configService.selectPubFolderReportList();
		} else {
			userFolder = configService.selectPubFolderList();
		}
		for(PublicFolderListVO folder : userFolder) {
			JSONObject userjson = new JSONObject();
			userjson.put("FLD_ID", folder.getFLD_ID());
			userjson.put("FLD_NM", folder.getFLD_NM());
			userjson.put("PARENT_FLD_ID", folder.getPARENT_FLD_ID());
			userjson.put("FLD_ORDINAL", folder.getFLD_ORDINAL());
			userjson.put("FLD_SHOW", false);
			userjson.put("FLD_PUBLISH", false);
			userjson.put("FLD_DATAITEM", false);
			userjson.put("FLD_EXPORT", false);
			userjson.put("TYPE", folder.getTYPE());
			userjson.put("REPORT_TYPE", folder.getREPORT_TYPE());
			userFolderList.add(userjson);
		}

		JSONObject obj = new JSONObject();
		obj.put("userResult", userArrayList);
		obj.put("folderResult", userFolderList);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getGrpPublicReportList.do")
	public void getGrpPublicReportList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		ArrayList<JSONObject> grpArrayList = new ArrayList<JSONObject>();
		List<GrpListVO> grpList = configService.selectGrpList();

		for(GrpListVO grp : grpList) {
			JSONObject grpjson = new JSONObject();
			grpjson.put("그룹ID", grp.getGRP_ID());
			grpjson.put("그룹명", grp.getGRP_NM());
			grpArrayList.add(grpjson);
		}

		ArrayList<JSONObject> grpFolderList = new ArrayList<JSONObject>();
		List<PublicFolderListVO> grpFolder = null;
		ConfigMasterVO configVo = authenticationService.getConfigMstr();
		if (configVo.getAUTH_REPORT_DETAIL_YN().equals("Y")) {
			grpFolder = configService.selectPubFolderReportList();
		} else {
			grpFolder = configService.selectPubFolderList();
		}

		for(PublicFolderListVO folder : grpFolder) {
			JSONObject grpjson = new JSONObject();
			grpjson.put("FLD_ID", folder.getFLD_ID());
			grpjson.put("FLD_NM", folder.getFLD_NM());
			grpjson.put("PARENT_FLD_ID", folder.getPARENT_FLD_ID());
			grpjson.put("FLD_ORDINAL", folder.getFLD_ORDINAL());
			grpjson.put("FLD_SHOW", false);
			grpjson.put("FLD_PUBLISH", false);
			grpjson.put("FLD_DATAITEM", false);
			grpjson.put("FLD_EXPORT", false);
			grpjson.put("TYPE", folder.getTYPE());
			grpjson.put("REPORT_TYPE", folder.getREPORT_TYPE());
			grpFolderList.add(grpjson);
		}

		JSONObject obj = new JSONObject();
		obj.put("groupResult", grpArrayList);
		obj.put("folderResult", grpFolderList);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getUserDatasetList.do")
	public void getUserDatasetList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		ArrayList<JSONObject> userArrayList = new ArrayList<JSONObject>();
		List<UserGroupVO> userList = configService.selectUserDatasetList();

		for(UserGroupVO user : userList) {
			JSONObject userjson = new JSONObject();
			userjson.put("AUTH_YN", user.getAuthCount() > 0 ? "Y" : "N");
			userjson.put("사용자NO", user.getUSER_NO());
			userjson.put("사용자ID", user.getUSER_ID());
			userjson.put("사용자명", user.getUSER_NM());
			userjson.put("그룹명", user.getGRP_NM());
			userArrayList.add(userjson);
		}

		ArrayList<JSONObject> userDatasetFolderList = new ArrayList<JSONObject>();
		List<FolderMasterVO> userDatasetFolder = configService.selectDatasetFolderList();

		for(FolderMasterVO folder : userDatasetFolder) {
			JSONObject userjson = new JSONObject();
			userjson.put("FLD_ID", folder.getFLD_ID());
			userjson.put("FLD_NM", folder.getFLD_NM());
			userjson.put("PARENT_FLD_ID", folder.getPARENT_FLD_ID());
			userjson.put("FLD_ORDINAL", folder.getFLD_ORDINAL());
			userDatasetFolderList.add(userjson);
		}

		JSONObject obj = new JSONObject();
		obj.put("userResult", userArrayList);
		obj.put("folderResult", userDatasetFolderList);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getGrpDatasetList.do")
	public void getGrpDatasetList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		ArrayList<JSONObject> groupArrayList = new ArrayList<JSONObject>();
		List<UserGroupVO> groupList = configService.selectGroupDatasetList();

		for(UserGroupVO grp : groupList) {
			JSONObject groupjson = new JSONObject();
			groupjson.put("AUTH_YN", grp.getAuthCount() > 0 ? "Y" : "N");
			groupjson.put("그룹ID", grp.getGRP_ID());
			groupjson.put("그룹명", grp.getGRP_NM());
			groupjson.put("그룹설명", grp.getGRP_DESC());
			groupArrayList.add(groupjson);
		}

		ArrayList<JSONObject> grpDatasetFolderList = new ArrayList<JSONObject>();
		List<FolderMasterVO> grpDatasetFolder = configService.selectDatasetFolderList();

		for(FolderMasterVO folder : grpDatasetFolder) {
			JSONObject groupjson = new JSONObject();
			groupjson.put("FLD_ID", folder.getFLD_ID());
			groupjson.put("FLD_NM", folder.getFLD_NM());
			groupjson.put("PARENT_FLD_ID", folder.getPARENT_FLD_ID());
			groupjson.put("FLD_ORDINAL", folder.getFLD_ORDINAL());
			//dogfoot syjin 20210323 권한(그룹 데이터 집합) epxanded 옵션 추가
			groupjson.put("expanded", true);
			grpDatasetFolderList.add(groupjson);
		}

		JSONObject obj = new JSONObject();
		obj.put("groupResult", groupArrayList);
		obj.put("folderResult", grpDatasetFolderList);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getUserDatasetAuth.do")
	public void getUserDatasetAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		Integer userNo = Integer.parseInt(SecureUtils.getParameter(request, "userNo"));

		List<Integer> authFolderList = new ArrayList<Integer>();
//		try {
			List<FolderMasterVO> userAuthFldList = configService.selectUserDatasetAuth(userNo);
			for(FolderMasterVO authFolder : userAuthFldList) {
				authFolderList.add(authFolder.getFLD_ID());
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("authFolderList", authFolderList);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getGrpDatasetAuth.do")
	public void getGrpDatasetAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		String grpId = SecureUtils.getParameter(request, "grp_id");

		List<Integer> authFolderList = new ArrayList<Integer>();
//		try {
			List<FolderMasterVO> grpAuthFldList = configService.selectGrpDatasetAuth(grpId);
			for(FolderMasterVO authFolder : grpAuthFldList) {
				authFolderList.add(authFolder.getFLD_ID());
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("authFolderList", authFolderList);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping(value= {"/saveUserDatasetAuth.do"}, method = RequestMethod.POST)
	public void saveUserDatasetAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer userNo = Integer.parseInt(SecureUtils.getParameter(request, "selectedUser"));
		String[] folders = SecureUtils.getParameters(request).get("selectedFolders[]");
		try {
			configService.initUserDatasetAuth(userNo);
			if (folders != null) {
				for (int i = 0; i < folders.length; i++) {
					UserAuthDataSetVO userAuthVo = new UserAuthDataSetVO();
					userAuthVo.setUserNo(userNo);
					userAuthVo.setFldId(Integer.parseInt(folders[i]));

					configService.insertUserDatasetAuth(userAuthVo);
				}
			}
		} catch (NumberFormatException e) {
			e.printStackTrace();
			throw new Error(e);
		}
	}

	@RequestMapping(value= {"/saveGrpDatasetAuth.do"}, method = RequestMethod.POST)
	public void saveGrpDatasetAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer grpId = Integer.parseInt(SecureUtils.getParameter(request, "selectedGroup"));
		String[] folders = SecureUtils.getParameters(request).get("selectedFolders[]");
		try {
			configService.initGrpDatasetAuth(grpId);
			if (folders != null) {
				for (int i = 0; i < folders.length; i++) {
					GrpAuthDataSetVO grpAuthVo = new GrpAuthDataSetVO();
					grpAuthVo.setGRP_ID(grpId);
					grpAuthVo.setFLD_ID(Integer.parseInt(folders[i]));

					configService.insertGrpDatasetAuth(grpAuthVo);
				}
			}
		} catch (NumberFormatException e) {
			e.printStackTrace();
			throw new Error(e);
		}
	}
	/*
	 * GENERAL CONFIG SERVICES
	 */

	@RequestMapping("/getConfigMstr.do")
	public void getConfigMstr(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		ConfigMasterVO config = null;
		WebConfigMasterVO webConfig = null;
		JSONObject configJson = new JSONObject();
		JSONObject obj = new JSONObject();
		try {
			out = response.getWriter();
			config = this.authenticationService.getConfigMstr();
			webConfig = this.authenticationService.getWebConfigMstr();

			configJson.put("MAIN_TITLE", config.getMAIN_TITLE());
			configJson.put("LICENSES_KEY", config.getLICENSES_KEY());
			configJson.put("WEB_URL", config.getWEB_URL());
			configJson.put("HOME_ENABLE", config.getHOME_ENABLE());
			configJson.put("VISUAL_WEB_URL", config.getVISUAL_WEB_URL());
			configJson.put("SHOW_TYPE", config.getSHOW_TYPE());
			configJson.put("INMEMORY_YN", config.getINMEMORY_YN());
			configJson.put("DEFAULT_LANG", config.getDEFAULT_LANG());
			configJson.put("BKG_IMG", config.getBKG_IMG());
			configJson.put("ST_NOTICE_YN", config.getST_NOTICE_YN());
			configJson.put("ST_REPORT_ID", config.getST_REPORT_ID());
			configJson.put("REFRESH_BTN_VISIBLE", config.getREFRESH_BTN_VISIBLE());
			configJson.put("MENU_ICON", config.getMENU_ICON());
			configJson.put("LOGIN_IMG", config.getLOGIN_IMG());
			configJson.put("RADIAL_MENU", config.getRADIAL_MENU());
			configJson.put("TREE_MENU", config.getTREE_MENU());
			configJson.put("ALLOW_NON_TBL_REL", config.getALLOW_NON_TBL_REL());
			configJson.put("SITE_NM", config.getSITE_NM());
			configJson.put("SSO_EXT", config.getSSO_EXT());
			configJson.put("SSO_PAGE", config.getSSO_PAGE());
			configJson.put("LOGIN_EXT", config.getLOGIN_EXT());
			configJson.put("MART_WEB_SVC_URL", config.getMART_WEB_SVC_URL());
			configJson.put("ADHOC_DEFAULT_CUBE_YN", config.getADHOC_DEFAULT_CUBE_YN());
			configJson.put("ADHOC_MULTY_CUBE_YN", config.getADHOC_MULTY_CUBE_YN());
			configJson.put("SCHEMA_SEARCH_YN", config.getSCHEMA_SEARCH_YN());
			configJson.put("DOWNLOAD_LIMIT_COUNT", config.getDOWNLOAD_LIMIT_COUNT());
			configJson.put("DOWNLOAD_DIV_COUNT", config.getDOWNLOAD_DIV_COUNT());
			configJson.put("SEARCH_LIMIT_TYPE", config.getSEARCH_LIMIT_TYPE());
			configJson.put("SEARCH_LIMIT_SIZE", config.getSEARCH_LIMIT_SIZE());
			configJson.put("LIMIT_WORKS", config.getLIMIT_WORKS());
			configJson.put("SINGLE_ID_YN", config.getSINGLE_ID_YN());
			configJson.put("LIMIT_CONNECTIONS", config.getLIMIT_CONNECTIONS());
			configJson.put("USE_TERM", config.getUSE_TERM());
			configJson.put("PW_CHANGE_PERIOD", config.getPW_CHANGE_PERIOD());
			configJson.put("PW_CHANGE_EXT", config.getPW_CHANGE_EXT());
			configJson.put("PW_CHANGE_PAGE", config.getPW_CHANGE_PAGE());
			configJson.put("LOGIN_DESIGN_XML", config.getLOGIN_DESIGN_XML());
			configJson.put("LOGIN_BTN_IMG", config.getLOGIN_BTN_IMG());
			configJson.put("DRILLTHROUGHT_LIMIT_COUNT", config.getDRILLTHROUGHT_LIMIT_COUNT());
			configJson.put("DRILLTHROUGHT_DIV_COUNT", config.getDRILLTHROUGHT_DIV_COUNT());
			configJson.put("DATASETEX_YN", config.getDATASETEX_YN());
			configJson.put("SHOW_DEL_MSG_YN", config.getSHOW_DEL_MSG_YN());
			configJson.put("LOGIN_LOCK_CNT", config.getLOGIN_LOCK_CNT());
			configJson.put("PWS_RULE", config.getPWS_RULE());
			configJson.put("ANALYTICS_YN", config.getANALYTICS_YN());
			configJson.put("ANALYTICS_PROC", config.getANALYTICS_PROC());
			configJson.put("ANALYTICS_TITLE", config.getANALYTICS_TITLE());
			configJson.put("DEFAULT_LAYOUT", config.getDEFAULT_LAYOUT());
			configJson.put("TRANS_REPORT_YN", config.getTRANS_REPORT_YN());
			configJson.put("TRANS_REPORT_TYPE", config.getTRANS_REPORT_TYPE());
			configJson.put("MAIN_DEFAULT_LAYOUT", config.getMAIN_DEFAULT_LAYOUT());
			configJson.put("AUTH_REPORT_DETAIL_YN", config.getAUTH_REPORT_DETAIL_YN());
			configJson.put("DBMS_TYPE", config.getDBMS_TYPE());
			configJson.put("DATASET_ORDINAL", config.getDATASET_ORDINAL());
			configJson.put("REPORT_ORDINAL", config.getREPORT_ORDINAL());
			configJson.put("DATASOURCE_DETAIL_YN", config.getDATASOURCE_DETAIL_YN());
			configJson.put("DATASET_NOTI", config.getDATASET_NOTI());
			configJson.put("WORDREPORTEX_YN", config.getWORDREPORTEX_YN());
			configJson.put("USE_SUMMARY_YN", config.getUSE_SUMMARY_YN());
			configJson.put("ADHOC_AUTOFIT_YN", config.getADHOC_AUTOFIT_YN());
			configJson.put("MAIN_TAB_USE_TYPE", config.getMAIN_TAB_USE_TYPE());
			configJson.put("HELP_WEB_YN", config.getHELP_WEB_YN());
			configJson.put("DATA_ITEM_EXPAND_YN", config.getDATA_ITEM_EXPAND_YN());
			configJson.put("DATA_ITEM_FIX_YN", config.getDATA_ITEM_FIX_YN());
			configJson.put("DASH_LAYOUT_FILE_YN", config.getDASH_LAYOUT_FILE_YN());
			configJson.put("SORT_COL_EX_YN", config.getSORT_COL_EX_YN());
			configJson.put("NULL_VALUE_YN", config.getNULL_VALUE_YN());
			configJson.put("NULL_VALUE_STRING", config.getNULL_VALUE_STRING());
			configJson.put("USE_HASH_YN", config.getUSE_HASH_YN());
			configJson.put("HASH_ALGORITHM", config.getHASH_ALGORITHM());
			configJson.put("SORT_EX_YN", config.getSORT_EX_YN());
			configJson.put("MODIFY_PWD_YN", config.getMODIFY_PWD_YN());
			configJson.put("PARAM_CHANGE_SAVE_YN", config.getPARAM_CHANGE_SAVE_YN());
			configJson.put("SEARCH_LIMIT_TIME", config.getSEARCH_LIMIT_TIME());
			configJson.put("FILTEREX_YN", config.getFILTEREX_YN());
			configJson.put("PROTECT_DATA_YN", config.getPROTECT_DATA_YN());
			configJson.put("DOWNLOAD_BIND_YN", config.getDOWNLOAD_BIND_YN());
			configJson.put("DASHBOARD_DEFAULT_PALETTE", config.getDASHBOARD_DEFAULT_PALETTE());
			configJson.put("DASHBOARD_LAYOUT", webConfig.getDASHBOARD_LAYOUT());
			configJson.put("LOGIN_IMAGE", webConfig.getLOGIN_IMAGE());
			configJson.put("LOGO", webConfig.getLOGO());
			configJson.put("MENU_CONFIG", webConfig.getMENU_CONFIG());
			configJson.put("FONT_CONFIG", webConfig.getFONT_CONFIG());
			configJson.put("SPREAD_JS_LICENSE", webConfig.getSPREAD_JS_LICENSE());
			configJson.put("PIVOT_ALIGN_CENTER", webConfig.getPIVOT_ALIGN_CENTER());
			configJson.put("GRID_AUTO_ALIGN", webConfig.getGRID_AUTO_ALIGN());
			configJson.put("REPORT_LOG_CLEAN_HOUR", webConfig.getREPORT_LOG_CLEAN_HOUR());
			configJson.put("EXCEL_DOWNLOAD_SERVER_COUNT", webConfig.getEXCEL_DOWNLOAD_SERVER_COUNT());
			configJson.put("REPORT_DIRECT_VIEW", webConfig.getREPORT_DIRECT_VIEW());
			/* DOGFOOT syjin LAYOUT_CONFIG 추가  20200814 */
			configJson.put("LAYOUT_CONFIG", webConfig.getLAYOUT_CONFIG());
			/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
			configJson.put("GRID_DATA_PAGING", webConfig.getGRID_DATA_PAGING());
			/* DOGFOOT syjin KAKAO_MAP_API_KEY 추가  20200814 */
			configJson.put("KAKAO_MAP_API_KEY", webConfig.getKAKAO_MAP_API_KEY());
			/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
			configJson.put("DOWNLOAD_FILTER_YN", webConfig.getDOWNLOAD_FILTER_YN());
			/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
			configJson.put("OLD_SCHEDULE_YN", webConfig.getOLD_SCHEDULE_YN());
			configJson.put("PIVOT_DRILL_UPDOWN", webConfig.getPIVOT_DRILL_UPDOWN());
		} catch (IOException e) {
			e.printStackTrace();
		}finally {
			obj.put("configJson", configJson);
			out.print(obj);
			out.flush();
			out.close();
		}
	}

	@RequestMapping(value="/saveConfigMstr.do", produces="text/plain;charset=UTF-8",method = { RequestMethod.POST })
	public void saveConfigMstr(HttpServletRequest request, HttpServletResponse response, Model model) throws UnsupportedEncodingException {
		response.setCharacterEncoding("utf-8");
		JSONObject returnVal = new JSONObject();
		ConfigMasterVO configVo = new ConfigMasterVO();

		String licensesKey = SecureUtils.getParameter(request, "LICENSES_KEY");
		String mainTitle = SecureUtils.getParameter(request, "MAIN_TITLE");
		String webUrl = SecureUtils.getParameter(request, "WEB_URL");
		String searchLimitTime = SecureUtils.getParameter(request, "SEARCH_LIMIT_TIME");
		// 2020.01.16 mksong searchLimitSize 타입 변경 dogfoot
		int searchLimitSize = Integer.parseInt(SecureUtils.getParameter(request, "SEARCH_LIMIT_SIZE"));
		/* DOGFOOT ktkang 동시 작업 제한 기능 구현  20200923 */
		String limitWorks = SecureUtils.getParameter(request, "LIMIT_WORKS");
		String useTerm = SecureUtils.getParameter(request, "USE_TERM");
		String limitConnections = SecureUtils.getParameter(request, "LIMIT_CONNECTIONS");
		String pwChangePeriod = SecureUtils.getParameter(request, "PW_CHANGE_PERIOD");
		String loginLockCnt = SecureUtils.getParameter(request, "LOGIN_LOCK_CNT");
		String reportLogCleanHour = SecureUtils.getParameter(request, "REPORT_LOG_CLEAN_HOUR");
		String authReportDetailYn = SecureUtils.getParameter(request, "AUTH_REPORT_DETAIL_YN");
		String defaultLayout = SecureUtils.getParameter(request, "DEFAULT_LAYOUT");
		String nullValueYn = SecureUtils.getParameter(request, "NULL_VALUE_YN");
		String nullValueString = SecureUtils.getParameter(request, "NULL_VALUE_STRING");
		String dashboardDefaultPalette = SecureUtils.getParameter(request, "DASHBOARD_DEFAULT_PALETTE");
		String dashboardLayout = SecureUtils.getParameter(request, "DASHBOARD_LAYOUT");
		String loginImage = SecureUtils.getParameter(request, "LOGIN_IMAGE");
		String logo = SecureUtils.getParameter(request, "LOGO");
		String menuConfig = SecureUtils.getParameter(request, "MENU_CONFIG").replaceAll("&quot;", "\"");
		String fontConfig = SecureUtils.getParameter(request, "FONT_CONFIG").replaceAll("&quot;", "\"");
		String spreadJsLicense = SecureUtils.getParameter(request, "SPREAD_JS_LICENSE");
		/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
		String downloadFilter = SecureUtils.getParameter(request, "DOWNLOAD_FILTER_YN");
		/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
		String oldSchedule = SecureUtils.getParameter(request, "OLD_SCHEDULE_YN");
		String pivotAlignCenter = SecureUtils.getParameter(request, "PIVOT_ALIGN_CENTER");
		String pivotDrillUpDown = SecureUtils.getParameter(request, "PIVOT_DRILL_UPDOWN");
		String gridAutoAlign = SecureUtils.getParameter(request, "GRID_AUTO_ALIGN");
		String gridDataPaging = SecureUtils.getParameter(request, "GRID_DATA_PAGING");
		String excelDownloadServerCount = SecureUtils.getParameter(request, "EXCEL_DOWNLOAD_SERVER_COUNT");
		/* DOGFOOT ktkang 보고서 바로 조회 기능 옵션 추가  20201015 */
		String reportDirectView = SecureUtils.getParameter(request, "REPORT_DIRECT_VIEW");

		/* DOGFOOT syjin LAYOUT_CONFIG 추가  20200814 */
		String layoutConfig = SecureUtils.getParameter(request, "LAYOUT_CONFIG").replaceAll("&quot;", "\"");
		/* DOGFOOT syjin KAKAO_MAP_API_KEY 추가  20200819 */
		String kakaoMapApiKey = SecureUtils.getParameter(request, "KAKAO_MAP_API_KEY").replaceAll("&quot;", "\"");

		configVo.setLICENSES_KEY(licensesKey);
		configVo.setMAIN_TITLE(mainTitle);
		configVo.setWEB_URL(webUrl);
		configVo.setSEARCH_LIMIT_TIME(searchLimitTime);
		configVo.setSEARCH_LIMIT_SIZE(searchLimitSize);
		configVo.setUSE_TERM(useTerm);
		configVo.setLIMIT_CONNECTIONS(limitConnections);
		configVo.setPW_CHANGE_PERIOD(pwChangePeriod);
		configVo.setLOGIN_LOCK_CNT(loginLockCnt);
		configVo.setAUTH_REPORT_DETAIL_YN(authReportDetailYn);
		configVo.setDEFAULT_LAYOUT(defaultLayout);
		configVo.setNULL_VALUE_YN(nullValueYn);
		configVo.setNULL_VALUE_STRING(nullValueString);
		configVo.setDASHBOARD_DEFAULT_PALETTE(dashboardDefaultPalette);
		configVo.setLIMIT_WORKS(limitWorks);
		/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
		/* DOGFOOT syjin KAKAO_MAP_API_KEY 추가  20200819 */
		WebConfigMasterVO webConfigVo = new WebConfigMasterVO(dashboardLayout, loginImage, logo, menuConfig, fontConfig, spreadJsLicense, reportLogCleanHour, excelDownloadServerCount, pivotAlignCenter, gridAutoAlign, layoutConfig, gridDataPaging, kakaoMapApiKey, downloadFilter, pivotDrillUpDown, reportDirectView, oldSchedule);
		configService.updateConfigMstr(configVo);
		configService.updateWebConfigMstr(webConfigVo);

		returnVal.put("code", 200);
		try {
			PrintWriter out = response.getWriter();
			out.print(returnVal);
			out.flush();
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@RequestMapping(value = "/uploadLoginImage.do")
	public void uploadLoginImage(@RequestParam("files[]") MultipartFile uploadFile, HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String ext = null;
		switch(uploadFile.getContentType()) {
			case "image/jpeg":
				ext = ".jpg";
				break;
			case "image/png":
				ext = ".png";
				break;
			case "image/gif":
				ext = ".gif";
				break;
			case "image/x-icon":
				ext = ".ico";
				break;
		}
		Long timestamp = new Date().getTime() / 1000;
		String fileName = "login_visual" + timestamp + ext;

		String uploadPath = null;
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		if(osBean.getName().indexOf("Windows") > -1) {
			uploadPath = request.getServletContext().getRealPath("\\resources\\main\\images\\custom\\" + fileName);
		} else {
			uploadPath = request.getServletContext().getRealPath("/resources/main/images/custom/" + fileName);
		}

		File file = new File(uploadPath);
		uploadFile.transferTo(file);

		out.print(fileName);
		out.flush();
		out.close();
	}

	@RequestMapping(value = "/uploadLogo.do", method = {RequestMethod.POST})
	public void uploadLogo(@RequestParam("files[]") MultipartFile uploadFile, HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String ext = null;
		switch(uploadFile.getContentType()) {
			case "image/jpeg":
				ext = ".jpg";
				break;
			case "image/png":
				ext = ".png";
				break;
			case "image/gif":
				ext = ".gif";
				break;
			case "image/x-icon":
				ext = ".ico";
				break;
		}
		Long timestamp = new Date().getTime() / 1000;
		String fileName = "logo" + timestamp + ext;

		String uploadPath = null;
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		if(osBean.getName().indexOf("Windows") > -1) {
			uploadPath = request.getServletContext().getRealPath("\\resources\\main\\images\\custom\\" + fileName);
		} else {
			uploadPath = request.getServletContext().getRealPath("/resources/main/images/custom/" + fileName);
		}

		File file = new File(uploadPath);
		uploadFile.transferTo(file);

		out.print(fileName);
		out.flush();
		out.close();
	}

	/*
	 * CONFIG LOG SERVICES
	 */
	@RequestMapping("/getAuditResource.do")
	public void getAuditResource(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		String StartDate =  SecureUtils.getParameter(request, "startdate");
		String EndDate =  SecureUtils.getParameter(request, "enddate");
		String selectType =  SecureUtils.getParameter(request, "selectType");
		LogParamVO paramVo = new LogParamVO();
		paramVo.setStartdate(StartDate);
		paramVo.setEnddate(EndDate);

		ArrayList<JSONObject> logs = new ArrayList<JSONObject>();

		try {
			int i = 0;
			if (selectType.equals("User")) {
				List<DashLoginOutMasterVO> listlog = configService.selectDashLoginOutMaster(paramVo);

				SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd");

				for (DashLoginOutMasterVO DashLoginOutMasterVO : listlog) {
					JSONObject login = new JSONObject();
					Date d1 = f.parse(DashLoginOutMasterVO.getEVENT_DT());
					Date d2 = f.parse(DashLoginOutMasterVO.getMOD_DT());
					login.put("logNo", i++);
					login.put("일자", f.format(d1));
					login.put("시간", DashLoginOutMasterVO.getEVENT_TIME());
					login.put("로그 유형", DashLoginOutMasterVO.getLOG_TYPE());
					login.put("사용자 ID", DashLoginOutMasterVO.getUSER_ID());
					login.put("사용자 명", DashLoginOutMasterVO.getUSER_NM());
					login.put("그룹 명", DashLoginOutMasterVO.getGRP_NM());
					login.put("접속 IP", DashLoginOutMasterVO.getACCESS_IP());
					login.put("수정일자", f.format(d2));
					logs.add(login);
				}
			}
			else if (selectType.equals("Report")) {
				List<DashReportMasterVO> listlog = configService.selectDashReportUseMaster(paramVo);

				for (DashReportMasterVO dashReportMasterVO : listlog) {
					JSONObject login = new JSONObject();
					login.put("logNo", i++);
					login.put("상태", dashReportMasterVO.getSTATUS_CD());
					login.put("LogSeq", dashReportMasterVO.getLOG_SEQ());
					login.put("보고서 ID", dashReportMasterVO.getREPORT_ID());
					login.put("보고서 명", dashReportMasterVO.getREPORT_NM());
					login.put("보고서 유형", dashReportMasterVO.getREPORT_TYPE());
					login.put("시작시간", dashReportMasterVO.getST_DT());
					if(dashReportMasterVO.getED_DT() != null) {
						login.put("종료시간", dashReportMasterVO.getED_DT());
					} else {
						login.put("종료시간", "0");
					}
					login.put("수행시간", dashReportMasterVO.getEVENT_TIME());
					login.put("사용자 ID", dashReportMasterVO.getUSER_ID());
					login.put("사용자 명", dashReportMasterVO.getUSER_NM());
					login.put("그룹 명", dashReportMasterVO.getGRP_NM());
					login.put("접속 IP", dashReportMasterVO.getACCESS_IP());

					logs.add(login);
				}
			} else if (selectType.equals("Export")) {
				List<ExportLogVO> listlog = configService.selectExportLog(paramVo);
				for (ExportLogVO exportLogVO : listlog) {
					JSONObject exportLog = new JSONObject();
					exportLog.put("logNo", i++);
					exportLog.put("일자", exportLogVO.getEVENT_DT());
					exportLog.put("시간", exportLogVO.getEVENT_TIME());
					exportLog.put("보고서 명", exportLogVO.getREPORT_NM());
					exportLog.put("보고서 유형", exportLogVO.getREPORT_TYPE());
					exportLog.put("사용자 ID", exportLogVO.getUSER_ID());
					exportLog.put("사용자 명", exportLogVO.getUSER_NM());
					exportLog.put("그룹 명", exportLogVO.getGRP_NM());
					exportLog.put("접속 IP", exportLogVO.getACCESS_IP());
					exportLog.put("컨트롤 아이디", exportLogVO.getCTRL_ID());
					exportLog.put("컨트롤 이름", exportLogVO.getCTRL_CAPTION());
					logs.add(exportLog);
				}
			} else if (selectType.contentEquals("Query")) {
				List<QueryLogVO> listlog = configService.selectQueryLog(paramVo);
				for (QueryLogVO queryLogVO : listlog) {
					JSONObject queryLog = new JSONObject();
					queryLog.put("logNo", i++);
					queryLog.put("일자", queryLogVO.getEVENT_DT());
					queryLog.put("시간", queryLogVO.getEVENT_TIME());
					queryLog.put("보고서 유형", queryLogVO.getREPORT_TYPE());
					queryLog.put("사용자 ID", queryLogVO.getUSER_ID());
					queryLog.put("사용자 명", queryLogVO.getUSER_NM());
					queryLog.put("그룹 명", queryLogVO.getGRP_NM());
					queryLog.put("접속 IP", queryLogVO.getACCESS_IP());
					queryLog.put("데이터 원본 명", queryLogVO.getDS_NM());
					queryLog.put("DB 명", queryLogVO.getDB_NM());
					queryLog.put("서버 주소(명)", queryLogVO.getDB_IP());
					queryLog.put("DB 유형", queryLogVO.getDBMS_TYPE());
					queryLog.put("수행 시간", queryLogVO.getRUN_TIME());
					queryLog.put("sql", queryLogVO.getSqlQueryString());
					logs.add(queryLog);
				}
			} else if (selectType.equals("Analysis")) {
				List<AnalysisLogVO> listlog = configService.selectAnalysisLog();
				for (AnalysisLogVO analysisLogVO : listlog) {
					JSONObject analysisLog = new JSONObject();
					analysisLog.put("logNo", i++);
					analysisLog.put("비정형 보고서", analysisLogVO.getREPORT_NM());
					analysisLog.put("데이터 원본 명", analysisLogVO.getDS_NM());
					analysisLog.put("DB 명", analysisLogVO.getDB_NM());
					analysisLog.put("서버 주소(명)", analysisLogVO.getIP());
					analysisLog.put("DB 유형", analysisLogVO.getDBMS_TYPE());
					analysisLog.put("소유자", analysisLogVO.getOWNER_NM());
					analysisLog.put("테이블 물리명", analysisLogVO.getTBL_NM());
					analysisLog.put("테이블 논리명", analysisLogVO.getTBL_CAPTION());
					analysisLog.put("컬럼 물리명", analysisLogVO.getCOL_NM());
					analysisLog.put("컬럼 논리명", analysisLogVO.getCOL_CAPTION());
					logs.add(analysisLog);
				}
			} else {
				throw new Exception("Incorrect select type.");
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw new Error(e);
		}

		JSONObject obj = new JSONObject();
		obj.put("logResult", logs);
		out.print(obj);
		out.flush();
		out.close();
	}

	/*
	 * CONFIG SESSION SERVICES
	 */
	@RequestMapping("/getCurrentProcesses.do")
	public void getCurrentProcesses(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException, SQLException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String ds_id = SecureUtils.getParameter(request, "ds_id");
		List<CurrentSqlVO> currentSqlList = configService.selectCurrentSqlList(ds_id);

		ArrayList<JSONObject> processes = new ArrayList<JSONObject>();

		for (CurrentSqlVO currentSql : currentSqlList) {
			JSONObject process = new JSONObject();
			process.put("RUNTIME", currentSql.getRUNTIME());
			process.put("SESSION_ID", currentSql.getSESSION_ID());
			process.put("SQL_TEXT", currentSql.getSQL_TEXT());
			process.put("WAIT_INFO", currentSql.getWAIT_INFO());
			processes.add(process);
		}

		JSONObject obj = new JSONObject();
		obj.put("sqlResult", processes);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/stopProcess.do")
	public void stopProcess(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException, SQLException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String sessionId = SecureUtils.getParameter(request, "SESSION_ID");
		String ds_id = SecureUtils.getParameter(request, "DS_ID");
		int rerutnStopPro = configService.stopProcess(sessionId, ds_id);

		JSONObject obj = new JSONObject();
		obj.put("rerutnStopPro", rerutnStopPro);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getUserSession.do")
	public void getUserSession(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out;
		try {
			out = response.getWriter();

			String StartDate =  SecureUtils.getParameter(request, "startdate");
			String EndDate =  SecureUtils.getParameter(request, "enddate");
			String logStatus = SecureUtils.getParameter(request, "logstatus");
			SessionParamVO paramVo = new SessionParamVO();
			paramVo.setStartDate(StartDate);
			paramVo.setEndDate(EndDate);
			paramVo.setLogStatus(logStatus);

			ArrayList<JSONObject> sessions = new ArrayList<JSONObject>();

			/* DOGFOOT ktkang 동시 접속자 현황에서 하루 지난 로그인 아이디 삭제  20200922 */
			SimpleDateFormat f = new SimpleDateFormat("yyyyMMdd");
			Date now = new Date();
			String nowString = f.format(now);
			SessionParamVO paramVo2 = new SessionParamVO();
			paramVo2.setStartDate(nowString);
			configService.deleteUserSessionsByDate(paramVo2);

			SimpleDateFormat f2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			List<UserSessionVO> userSessions = configService.selectUserSessions(paramVo);
			for (UserSessionVO sessionVo : userSessions) {
				JSONObject session = new JSONObject();
				session.put("사용자 ID", sessionVo.getUSER_ID());
				session.put("사용자 No", sessionVo.getUSER_NO());
				session.put("로그 유형", sessionVo.getLOG_TYPE());
				session.put("접속 IP", sessionVo.getACCESS_IP());
				session.put("일시", f2.format(sessionVo.getMOD_DT()));
				session.put("수정자 ID", sessionVo.getMOD_USER_ID());
				session.put("사용자 세션 키", sessionVo.getUSER_SESSION_KEY());
				sessions.add(session);
			}

			JSONObject obj = new JSONObject();
			obj.put("sessions", sessions);
			out.print(obj);
			out.flush();
			out.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

//	@RequestMapping("/endUserSession.do")
//	public void endUserSession(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
//		request.setCharacterEncoding("utf-8");
//		response.setCharacterEncoding("utf-8");
//		String sessionId =  SecureUtils.getParameter(request, "sessionId");
//		HttpSession session = WiseSessionListener.getSession(sessionId);
//		if (session == null) {
//			PrintWriter out = response.getWriter();
//			out.print("찾는 사용자가 왭세션이 없습니다.");
//			out.flush();
//			out.close();
//		} else {
//			session.invalidate();
//		}
//	}

	@RequestMapping("/updateUserSession.do")
	public void updateUserSession(HttpServletRequest request, HttpServletResponse response, Model model) {
		try {
			request.setCharacterEncoding("utf-8");
			String userId = SecureUtils.getParameter(request, "userId");
			Integer userNo =  Integer.parseInt(SecureUtils.getParameter(request, "userNo"));
			User admin = getSessionUser(request);
			User user = new User();
			user.setUSER_ID(userId);
			user.setUSER_NO(userNo);
			UserSessionVO sessionVo = authenticationService.selectUserSessionLog(user);
			Timestamp currentTime = new Timestamp(System.currentTimeMillis());
			sessionVo.setLOG_TYPE("LOGOUT");
			sessionVo.setLAST_MSG_DT(currentTime);
			sessionVo.setMOD_USER_NO(admin.getUSER_NO());
			sessionVo.setMOD_DT(currentTime);
			authenticationService.updateUserSessionLog(sessionVo);
		} catch (IOException e) {
			e.printStackTrace();
			throw new Error(e);
		}
	}

	@RequestMapping("/unlockUserSession.do")
	public void unlockUserSession(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		Integer userNo =  Integer.parseInt(SecureUtils.getParameter(request, "userNo"));

		User user = new User();
		user.setUSER_NO(userNo);
		user.setLOCK_CNT(0);
//		try {
			authenticationService.updateUserLockCount(user);
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}
	}

	@RequestMapping("/getInactiveUserSession.do")
	public void getInactiveUserSession(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		String idNo = SecureUtils.getParameter(request, "idno");
		String idNoFilter = SecureUtils.getParameter(request, "idnofilter");
		SessionParamVO paramVo = new SessionParamVO();
		paramVo.setIdNo(idNo);
		paramVo.setIdNoFilter(idNoFilter);

		ArrayList<JSONObject> sessions = new ArrayList<JSONObject>();

//		try {
			SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			List<UserSessionVO> userSessions = configService.selectInactiveUserSessions(paramVo);
			for (UserSessionVO sessionVo : userSessions) {
				JSONObject session = new JSONObject();
				session.put("사용자 ID", sessionVo.getUSER_ID());
				session.put("사용자 No", sessionVo.getUSER_NO());
				session.put("로그 유형", sessionVo.getLOG_TYPE());
				session.put("접속 IP", sessionVo.getACCESS_IP());
				session.put("일시", f.format(sessionVo.getMOD_DT()));
				session.put("수정자 ID", sessionVo.getMOD_USER_ID());
				session.put("사용자 세션 키", sessionVo.getUSER_SESSION_KEY());
				session.put("미사용 기간", sessionVo.getInactiveDays());
				sessions.add(session);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("sessions", sessions);
		out.print(obj);
		out.flush();
		out.close();
	}

	@RequestMapping("/getLockedUserSession.do")
	public void getLockedUserSession(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		ArrayList<JSONObject> sessions = new ArrayList<JSONObject>();

//		try {
			List<UserGroupVO> users = configService.selectLockedUserSessions();
			for (UserGroupVO user : users) {
				JSONObject session = new JSONObject();
				session.put("사용자 No", user.getUSER_NO());
				session.put("사용자 ID", user.getUSER_ID());
				session.put("사용자 명", user.getUSER_NM());
				session.put("그룹 명", user.getGRP_NM());
				session.put("실행 타입", user.getUSER_RUN_MODE());
				sessions.add(session);
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("sessions", sessions);
		out.print(obj);
		out.flush();
		out.close();
	}

	/*
	 * DATASET CONFIG SERVICES
	 */
	@RequestMapping("/getDataSetList.do")
	public void getDataSetList(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		JSONObject ret = new JSONObject();
		String dataSourceType = "";
//        Timer timer = new Timer();
		try {
			out = response.getWriter();
	        dataSourceType = SecureUtils.getParameter(request, "dstype");
	        String userId = SecureUtils.getParameter(request, "userId");

	        ArrayList<JSONObject> dataSetFolders = new ArrayList<JSONObject>();

	        List<FolderMasterVO> listDataSetFolder = new ArrayList<FolderMasterVO>();
	        List<DataSetInfoMasterVO> listDataSetInfo = new ArrayList<DataSetInfoMasterVO>();



            listDataSetFolder = this.dataSetService.selectUserAuthDataSetFolderList(userId);
            if(listDataSetFolder.size() == 0) {
            	listDataSetFolder = this.dataSetService.selectGrpAuthDataSetFolderList(userId);
            }
            listDataSetInfo = this.dataSetService.selectDataSetInfoList();
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

            	datasetinfo.put("FLD_ID", dataSetInfo.getDATASET_ID());
            	datasetinfo.put("FLD_NM", dataSetInfo.getDATASET_NM());
            	datasetinfo.put("PARENT_FLD_ID", dataSetInfo.getPARENT_FLD_ID());
            	datasetinfo.put("DATASET_ID", dataSetInfo.getDATASET_ID());
            	datasetinfo.put("DATASRC_ID", dataSetInfo.getDATASRC_ID());
            	datasetinfo.put("DATASRC_TYPE", dataSetInfo.getDATASRC_TYPE());
            	datasetinfo.put("DATASET_TYPE", dataSetInfo.getDATASET_TYPE());
            	datasetinfo.put("DATASET_DESC", dataSetInfo.getDATASET_DESC());
            	dataSetFolders.add(datasetinfo);
            }

            ret.put("dataSetFolders", dataSetFolders);
        } catch (IOException e) {
            response.setStatus(500);
            ret = new AjaxMessageConverter(930, "Can Not Query SQL. See Server Log. - " + dataSourceType).toJson();
        }finally {
        	out.print(ret);
    		out.flush();
    		out.close();
        }

		return;
	}

	@RequestMapping("/getAuthDSList.do")
	public void getAuthDSList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String userNo = SecureUtils.getParameter(request,"userNo");
		List<SubjectMasterVO> listDSList = this.dataSetService.selectUserAuthDsList(userNo);
        if(listDSList == null || listDSList.size() == 0) {
        	listDSList = this.dataSetService.selectGrpAuthDsList(userNo);
        }
        JSONArray dsListarr = new JSONArray();
        int i=0;
        if(listDSList != null) {
        	for(SubjectMasterVO vo:listDSList) {
        		JSONObject obj = new JSONObject();
        		obj.put("ID", i);
        		obj.put("DS_ID", vo.getDS_ID());

        		obj.put("DS_NM", vo.getDS_NM());
        		obj.put("데이터 원본 명",  vo.getDS_NM());
        		obj.put("데이터원본 명", vo.getDS_NM());

        		obj.put("DB_NM", vo.getDB_NM());
        		obj.put("DB 명", vo.getDB_NM());

        		obj.put("IP", vo.getIP());
        		obj.put("서버 주소(명)", vo.getIP());

        		obj.put("USER_ID", vo.getUSER_ID());
        		obj.put("접속 ID", vo.getUSER_ID());

        		obj.put("PORT", vo.getPORT());
        		obj.put("Port", vo.getPORT());

        		obj.put("DBMS_TYPE", vo.getDBMS_TYPE());
        		obj.put("DB 유형", vo.getDBMS_TYPE());

        		obj.put("OWNER_NM", vo.getOWNER_NM());
        		obj.put("소유자", vo.getOWNER_NM());

        		obj.put("DS_DESC", vo.getDS_DESC());
        		obj.put("설명", vo.getDS_DESC());

        		obj.put("WF_YN", vo.getWF_YN());

        		obj.put("USER_AREA_YN", vo.getUSER_AREA_YN());
        		obj.put("사용자 데이터", vo.getUSER_AREA_YN());

        		dsListarr.add(obj);
        		i++;
        	}
        }
        out.print(dsListarr);
		out.flush();
		out.close();
		return;
	}
	@RequestMapping("/getDSViewList.do")
	public void getDSViewList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {

	}
	@RequestMapping("/getQueryList.do")
	public void getQueryList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {

	}
	@RequestMapping("/getSingleTBLList.do")
	public void getSingleTBLList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String userNo = SecureUtils.getParameter(request,"userNo");
//		System.out.println("userNo"+userNo);
		List<SubjectMasterVO> listDSList = this.dataSetService.selectUserAuthDsList(userNo);
        if(listDSList == null || listDSList.size() == 0) {
        	listDSList = this.dataSetService.selectGrpAuthDsList(userNo);
        }
        JSONArray dsListarr = new JSONArray();
        int i=0;
        if(listDSList != null) {
        	for(SubjectMasterVO vo:listDSList) {
            	JSONObject obj = new JSONObject();
            	obj.put("ID", i);
            	obj.put("DS_ID", vo.getDS_ID());

            	obj.put("DS_NM", vo.getDS_NM());
            	obj.put("데이터 원본 명",  vo.getDS_NM());
            	obj.put("데이터원본 명", vo.getDS_NM());

            	obj.put("DB_NM", vo.getDB_NM());
            	obj.put("DB 명", vo.getDB_NM());

            	obj.put("IP", vo.getIP());
            	obj.put("서버 주소(명)", vo.getIP());

            	obj.put("USER_ID", vo.getUSER_ID());
            	obj.put("접속 ID", vo.getUSER_ID());

            	obj.put("PORT", vo.getPORT());
            	obj.put("Port", vo.getPORT());

            	obj.put("DBMS_TYPE", vo.getDBMS_TYPE());
            	obj.put("DB 유형", vo.getDBMS_TYPE());

            	obj.put("OWNER_NM", vo.getOWNER_NM());
            	obj.put("소유자", vo.getOWNER_NM());

            	obj.put("DS_DESC", vo.getDS_DESC());
            	obj.put("설명", vo.getDS_DESC());

            	obj.put("WF_YN", vo.getWF_YN());

            	obj.put("USER_AREA_YN", vo.getUSER_AREA_YN());
            	obj.put("사용자 데이터", vo.getUSER_AREA_YN());

            	dsListarr.add(obj);
            	i++;
            }
        }
        out.print(dsListarr);
		out.flush();
		out.close();

	}
	@RequestMapping("/getSingleViewTBLList.do")
	public void getSingleViewTBLList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String userNo = SecureUtils.getParameter(request,"userNo");
		List<SubjectMasterVO> listDSList = this.dataSetService.selectUserAuthDsViewList(userNo);
        if(listDSList == null || listDSList.size() == 0) {
        	listDSList = this.dataSetService.selectGrpAuthDsViewList(userNo);
        }
        JSONArray dsListarr = new JSONArray();
        int i=0;
        if(listDSList != null) {
        for(SubjectMasterVO vo:listDSList) {
        	JSONObject obj = new JSONObject();
        	obj.put("ID", i);
        	obj.put("DS_ID", vo.getDS_ID());

        	obj.put("DS_NM", vo.getDS_NM());
        	obj.put("데이터 원본 명",  vo.getDS_NM());
        	obj.put("데이터원본 명", vo.getDS_NM());

        	obj.put("DB_NM", vo.getDB_NM());
        	obj.put("DB 명", vo.getDB_NM());

        	obj.put("IP", vo.getIP());
        	obj.put("서버 주소(명)", vo.getIP());

        	obj.put("USER_ID", vo.getUSER_ID());
        	obj.put("접속 ID", vo.getUSER_ID());

        	obj.put("PORT", vo.getPORT());
        	obj.put("Port", vo.getPORT());

        	obj.put("DBMS_TYPE", vo.getDBMS_TYPE());
        	obj.put("DB 유형", vo.getDBMS_TYPE());

        	obj.put("OWNER_NM", vo.getOWNER_NM());
        	obj.put("소유자", vo.getOWNER_NM());

        	obj.put("DS_DESC", vo.getDS_DESC());
        	obj.put("설명", vo.getDS_DESC());

        	obj.put("WF_YN", vo.getWF_YN());

        	obj.put("USER_AREA_YN", vo.getUSER_AREA_YN());
        	obj.put("사용자 데이터", vo.getUSER_AREA_YN());

        	obj.put("DS_VIEW_ID", vo.getDS_VIEW_ID());

        	obj.put("DS_VIEW_NM", vo.getDS_VIEW_NM());

        	dsListarr.add(obj);
        	i++;
        }
        }
        out.print(dsListarr);
		out.flush();
		out.close();

	}

	@RequestMapping("/getCUBEList.do")
	public void getCUBEList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String userNo = request.getParameter("userNo");
        List<SubjectCubeMasterVO> listDSList = this.dataSetService.selectUserAuthCubeList(userNo);
        if(listDSList == null || listDSList.size() == 0) {
        	listDSList = this.dataSetService.selectGrpAuthCubeList(userNo);
        }
        JSONArray dsListarr = new JSONArray();
        int i=0;
        if(listDSList != null) {
//        try {
        	for(SubjectCubeMasterVO vo:listDSList) {
            	JSONObject obj = new JSONObject();
            	obj.put("ID", i);
            	obj.put("DS_ID", vo.getDS_ID());

            	obj.put("DS_NM", vo.getDS_NM());
            	obj.put("데이터 원본 명",  vo.getDS_NM());
            	obj.put("데이터원본 명", vo.getDS_NM());

            	obj.put("DB_NM", vo.getDB_NM());
            	obj.put("DB 명", vo.getDB_NM());

            	obj.put("IP", vo.getIP());
            	obj.put("서버 주소(명)", vo.getIP());

            	obj.put("USER_ID", vo.getUSER_ID());
            	obj.put("접속 ID", vo.getUSER_ID());

            	obj.put("PORT", vo.getPORT());
            	obj.put("Port", vo.getPORT());

            	obj.put("DBMS_TYPE", vo.getDBMS_TYPE());
            	obj.put("DB 유형", vo.getDBMS_TYPE());

            	obj.put("OWNER_NM", vo.getOWNER_NM());
            	obj.put("소유자", vo.getOWNER_NM());

            	obj.put("DS_DESC", vo.getDS_DESC());
            	obj.put("설명", vo.getDS_DESC());

            	obj.put("WF_YN", vo.getWF_YN());

            	obj.put("USER_AREA_YN", vo.getUSER_AREA_YN());
            	obj.put("사용자 데이터", vo.getUSER_AREA_YN());

            	obj.put("DS_VIEW_ID", vo.getDS_VIEW_ID());

            	obj.put("DS_VIEW_NM", vo.getDS_VIEW_NM());

            	obj.put("CUBE_ID", vo.getCUBE_ID());
            	obj.put("CUBE_NM", vo.getCUBE_NM());
            	dsListarr.add(obj);
            	i++;
            }
//        }catch (Exception e) {
//			// TODO: handle exception
//        	e.printStackTrace();
//		}
        }
        out.print(dsListarr);
		out.flush();
		out.close();

	}

	/*
	 * ACCOUNT SERVICES
	 */
	@RequestMapping(value= "/getUserInfo.do", method = { RequestMethod.POST })
	public void getUserInfo(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");

		Integer userNo = Integer.parseInt(SecureUtils.getParameter(request, "userNo"));
		User user = authenticationService.selectUserByNo(userNo);
		if (user != null) {
			PrintWriter out = response.getWriter();
			UserConfigVO userConfig = configService.selectUserConfig(userNo);
			JSONObject userJson = new JSONObject();
			userJson.put("userId", user.getUSER_ID());
			userJson.put("userName", user.getUSER_NM());
			userJson.put("email1", user.getE_MAIL1());
			userJson.put("email2", user.getE_MAIL2());
			userJson.put("telNo", user.getHP_NO());
			userJson.put("mobileNo", user.getTEL_NO());
			userJson.put("userImage", userConfig.getUSER_IMAGE());
			userJson.put("datasetId", userConfig.getDEFAULT_DATASET_ID());
			userJson.put("reportId", userConfig.getDEFAULT_REPORT_ID());
			userJson.put("item", userConfig.getDEFAULT_ITEM());
			userJson.put("palette", userConfig.getDEFAULT_PALETTE());
			userJson.put("viewerReportId", userConfig.getDEFAULT_VIEWER_REPORT_ID());
			userJson.put("fontConfig", userConfig.getFONT_CONFIG());
			out.print(userJson);
			out.flush();
			out.close();
		} else {
			throw new Error();
		}
	}
	@RequestMapping("/getDataSetFolderList.do")
	public void getDataSetFolderList(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

        String dataSourceType = SecureUtils.getParameter(request, "dstype");
        String userId = SecureUtils.getParameter(request, "userId");

        ArrayList<JSONObject> dataSetFolders = new ArrayList<JSONObject>();

        List<FolderMasterVO> listDataSetFolder = new ArrayList<FolderMasterVO>();

        JSONObject ret = new JSONObject();

//        try {
            listDataSetFolder = this.dataSetService.selectUserAuthDataSetFolderList(userId);
            if(listDataSetFolder.size() == 0) {
            	listDataSetFolder = this.dataSetService.selectGrpAuthDataSetFolderList(userId);
            }
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
            ret.put("dataSetFolders", dataSetFolders);
//        }
//        catch (Exception e) {
//            response.setStatus(500);
//            ret = new AjaxMessageConverter(930, "Can Not Query SQL. See Server Log. - " + dataSourceType).toJson();
//        }

        out.print(ret);
		out.flush();
		out.close();
		return;
	}

	@RequestMapping(value = {"/saveDataSet.do"}, method = RequestMethod.POST)
	public void saveDataSet(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
//        Timer timer = new Timer();
		JSONObject ret = new JSONObject();
		try {
			request.setCharacterEncoding("utf-8");
			out = response.getWriter();
			String reportMeta = SecureUtils.unsecure(SecureUtils.getParameter(request,"JSON_DATASET"));
			org.json.JSONObject obj = new org.json.JSONObject(reportMeta);
			this.dataSetService.saveDataSet(obj);
			ret.put("code", 200);
		}catch (IOException e) {
			// TODO: handle exception
			e.printStackTrace();
			ret.put("code", 500);
		}finally {
			out.print(ret);
			out.flush();
			out.close();
		}
		return;
	}

	@RequestMapping(value = {"/deleteDataSet.do"}, method = RequestMethod.POST)
	public void deleteDataSet(HttpServletRequest request, HttpServletResponse response, Model model) {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		JSONObject ret = new JSONObject();
		try {
			request.setCharacterEncoding("utf-8");
			out = response.getWriter();
			String datasetId = SecureUtils.getParameter(request, "dataSetId");
			this.dataSetService.deleteDataSet(datasetId);
			ret.put("code", 200);
		}catch (IOException e) {
			// TODO: handle exception
			e.printStackTrace();
			ret.put("code", 500);
		}finally {
			out.print(ret);
			out.flush();
			out.close();
		}
	}

	@RequestMapping(value = {"/DatasetGenerate.do"}, method = RequestMethod.POST)
	public void DatasetGenerate(HttpServletRequest request, HttpServletResponse response, Model model){
		response.setCharacterEncoding("utf-8");
		PrintWriter out = null;
		JSONObject ret= new JSONObject();
		try {
			request.setCharacterEncoding("utf-8");
			out = response.getWriter();

			String reportMeta = SecureUtils.unsecure(SecureUtils.getParameter(request, "JSON_DATASET"));
			org.json.JSONObject obj = new org.json.JSONObject(reportMeta);

			Json2Xml parser = new Json2Xml();
			String sql_xml = parser.sortDataSetXMLForDataSetDS(obj,new org.json.JSONObject(),false);
			org.json.JSONObject parsingJSON = XML.toJSONObject(sql_xml);
			JSONObject sql_obj = JSONObject.fromObject(parsingJSON.toString());
			JSONObject dataset_json = sql_obj.getJSONObject("DATA_SET");
			dataset_json.put("DATASET_NM", obj.get("datasetNm")+"");
			dataset_json.put("DATASET_TYPE", "DataSetDs");
			dataset_json.put("DATASRC_ID",  obj.get("DATASRC_ID")+"");
			dataset_json.put("DATASRC_TYPE", "DS");
			dataset_json.put("SQL_QUERY",  obj.get("SQL_QUERY")+"");
			ret.put("DATA_SET", dataset_json);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  finally{
			out.print(ret);
			out.flush();
			out.close();
		}
		return;
	}
	@RequestMapping(value = {"/DatasetGenerateSingle.do"}, method = RequestMethod.POST)
	public void DatasetGenerateSingle(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		request.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
//        Timer timer = new Timer();

		String reportMeta = SecureUtils.unsecure(SecureUtils.getParameter(request, "JSON_DATASET"));
		org.json.JSONObject obj = new org.json.JSONObject(reportMeta);
		JSONObject ret = new JSONObject();
//		try {
			Json2Xml parser = new Json2Xml();
			String sql_xml = parser.sortDataSetXMLForDataSetSingle(obj,new org.json.JSONObject(),false);
			org.json.JSONObject parsingJSON = XML.toJSONObject(sql_xml);
			JSONObject sql_obj = JSONObject.fromObject(parsingJSON.toString());
			JSONObject dataset_json = sql_obj.getJSONObject("DATA_SET");
			dataset_json.put("DATASET_NM", obj.getString("datasetNm"));
			if((obj.get("DataSetType")+"").equalsIgnoreCase("DataSetSingleDs")) {
				dataset_json.put("DATASET_TYPE", "DataSetSingleDs");
				dataset_json.put("DATASRC_TYPE", "DS");
			}else {
				dataset_json.put("DATASET_TYPE", "DataSetSingleDsView");
				dataset_json.put("DATASRC_TYPE", "DS_VIEW");
			}
			dataset_json.put("DATASRC_ID",  obj.get("DATASRC_ID")+"");
			dataset_json.put("SQL_QUERY",  obj.get("SQL_QUERY")+"");
			ret.put("DATA_SET", dataset_json);
//		}catch (Exception e) {
//			// TODO: handle exception
//			e.printStackTrace();
//		}
        out.print(ret);
		out.flush();
		out.close();
		return;
	}
	@RequestMapping(value = {"/DatasetGenerateCube.do"}, method = RequestMethod.POST)
	public void DatasetGenerateCube(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		request.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
//        Timer timer = new Timer();

		String reportMeta = SecureUtils.unsecure(SecureUtils.getParameter(request, "JSON_DATASET"));
		org.json.JSONObject obj = new org.json.JSONObject(reportMeta);
		JSONObject ret = new JSONObject();

		Map<String,List<CubeTableVO>> cubeTableInfo = this.dataSetService.selectCubeReportTableInfoList(Integer.parseInt(obj.get("DATASRC_ID")+""),obj.getString("userId"));
//		try {
			Json2Xml parser = new Json2Xml();
			String sql_xml = parser.sortDataSetXMLForDataSetCUBE(obj,new org.json.JSONObject(),false,cubeTableInfo);
			org.json.JSONObject parsingJSON = XML.toJSONObject(sql_xml);
			JSONObject sql_obj = JSONObject.fromObject(parsingJSON.toString());
			JSONObject dataset_json = sql_obj.getJSONObject("DATA_SET");
			dataset_json.put("DATASET_NM", obj.getString("datasetNm"));
			dataset_json.put("DATASET_TYPE", "DataSetCube");
			dataset_json.put("DATASRC_ID",  obj.get("DATASRC_ID")+"");
			dataset_json.put("DATASRC_TYPE", "CUBE");
			dataset_json.put("SQL_QUERY",  obj.get("SQL_QUERY")+"");
			ret.put("DATA_SET", dataset_json);
//		}catch (Exception e) {
//			// TODO: handle exception
//			e.printStackTrace();
//		}
        out.print(ret);
		out.flush();
		out.close();
		return;
	}


	@RequestMapping(value = "/uploadUserImage.do", method = {RequestMethod.POST})
	public void uploadUserImage(@RequestParam("files[]") MultipartFile uploadFile, HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.setCharacterEncoding("utf-8");
		User user = getSessionUser(request);

		if (user != null) {
			int userNo = user.getUSER_NO();
			String ext = "";
			switch(uploadFile.getContentType()) {
				case "image/jpeg":
					ext = ".jpg";
					break;
				case "image/png":
					ext = ".png";
					break;
				case "image/gif":
					ext = ".gif";
					break;
				case "image/x-icon":
					ext = ".ico";
					break;
				default:
					// 이미지 파일이 아닐 경우
					throw new Error("Invalid file type.");
			}
			Long timestamp = new Date().getTime() / 1000;
			String fileName = timestamp + ext;

			String uploadPath = null;
			java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
			if(osBean.getName().indexOf("Windows") > -1) {
				uploadPath = request.getServletContext().getRealPath("\\images\\users\\" + userNo + "\\" + fileName);
			} else {
				uploadPath = request.getServletContext().getRealPath("/images/users/" + userNo + "/" + fileName);
			}

			File file = new File(uploadPath);
			// "/images/users" 에 사용자의 폴더가 없으면 폴더를 새로 만들기
			file.getParentFile().mkdirs();
			uploadFile.transferTo(file);

			PrintWriter out = response.getWriter();
			out.print(fileName);
			out.flush();
			out.close();
		} else {
			// 사용자 세션이 없을 경우
			throw new Error("User not found.");
		}
	}

	@RequestMapping(value = "/saveAccountProfile.do", method = {RequestMethod.POST})
	public void saveAccountProfile(HttpServletRequest request, HttpServletResponse response) {
		response.setCharacterEncoding("utf-8");
		User user = getSessionUser(request);
		PrintWriter out = null;
		try {
			if (user != null) {
				out = response.getWriter();
				int userNo = user.getUSER_NO();
				String userName = SecureUtils.getParameter(request, "userName");
				String userEmail1 = SecureUtils.getParameter(request, "email1");
				String userEmail2 = SecureUtils.getParameter(request, "email2");
				String userTelNo = SecureUtils.getParameter(request, "telNo");
				String userMobileNo = SecureUtils.getParameter(request, "mobileNo");
				String image = SecureUtils.getParameter(request, "image");

				// input validation
				String emailFormat = 	"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b" +
										"\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(" +
										"?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|" +
										"2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z" +
										"0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0" +
										"c\\x0e-\\x7f])+)\\])";
				String telNoFormat = "\\d{2,3}-\\d{4}-\\d{4}";
				String mobileNoFormat = "\\d{3}-\\d{4}-\\d{4}";
				if (userName == null || userName.length() == 0) {
					out.print("사용자 명 포맷 맞게 다시 입력 해주세요.\r\n(빈값은 가능하지 않습니다)");
		    		out.flush();
		    		out.close();
		    		return;
				} else if (userEmail1 != null && !(userEmail1.isEmpty()) && !(userEmail1.matches(emailFormat))) {
					out.print("이메일 포맷 맞게 다시 입력 해주세요.\r\n(예: name@email.com)");
		    		out.flush();
		    		out.close();
		    		return;
				} else if (userEmail2 != null && !(userEmail2.isEmpty()) && !(userEmail2.matches(emailFormat))) {
					out.print("이메일 포맷 맞게 다시 입력 해주세요.\r\n(예: name@email.com)");
		    		out.flush();
		    		out.close();
		    		return;
				} else if (userTelNo != null && !(userTelNo.isEmpty()) && !(userTelNo.matches(telNoFormat))) {
					out.print("전화번호 포맷 맞게 다시 입력 해주세요.\r\n(예: 02-1234-5678)");
		    		out.flush();
		    		out.close();
		    		return;
				} else if (userMobileNo != null && !(userMobileNo.isEmpty()) && !(userMobileNo.matches(mobileNoFormat))) {
					out.print("휴대전화번호 포맷 맞게 다시 입력 해주세요.\r\n(예: 010-1234-5678)");
		    		out.flush();
		    		out.close();
		    		return;
				}
				user.setUSER_NM(userName);
				user.setE_MAIL1(userEmail1);
				user.setE_MAIL2(userEmail2);
				user.setHP_NO(userTelNo);
				user.setTEL_NO(userMobileNo);
				UserConfigVO userConfig = new UserConfigVO(userNo, image, null, null, null, null, null, null);

				configService.updateUserProfile(user, userConfig);
				out.print("저장 되었습니다.");
			} else {
				// 사용자 세션이 없을 경우
				throw new Error("User not found.");
			}
		} catch (IOException e) {
			e.printStackTrace();
			throw new Error(e);
		}finally {
			out.flush();
			out.close();
		}
	}

	@RequestMapping(value = "/saveAccountDatasetId.do", method = {RequestMethod.POST})
	public void saveAccountDatasetId(HttpServletRequest request, HttpServletResponse response) {
		User user = getSessionUser(request);

		if (user != null) {
			int userNo = user.getUSER_NO();
			Integer datasetId = Integer.parseInt(SecureUtils.getParameter(request, "datasetId"));
			if (datasetId == 0) {
				datasetId = null;
			}
			UserConfigVO userConfig = new UserConfigVO(userNo, null, datasetId, null, null, null, null, null);

//			try {
				configService.updateUserDatasetId(userConfig);
//			} catch (Exception e) {
//				e.printStackTrace();
//				throw new Error(e);
//			}
		} else {
			// 사용자 세션이 없을 경우
			throw new Error("User not found.");
		}
	}

	@RequestMapping(value = "/saveAccountReportInfo.do", method = {RequestMethod.POST})
	public void saveAccountReportInfo(HttpServletRequest request, HttpServletResponse response){
		User user = getSessionUser(request);

		if (user != null) {
			int userNo = user.getUSER_NO();
			Integer reportId = Integer.parseInt(SecureUtils.getParameter(request, "reportId"));
			String reportNm = null;
			String reportType = null;
			if (reportId == 0) {
				reportId = null;
			} else {
				reportNm = SecureUtils.getParameter(request, "reportNm");
				reportType = SecureUtils.getParameter(request, "reportType");
			}
			UserConfigVO userConfig = new UserConfigVO(userNo, null, null, reportId, null, null, null, null);

			configService.updateUserReportInfo(userConfig);
		} else {
			// 사용자 세션이 없을 경우
			throw new Error("User not found.");
		}
	}

	@RequestMapping(value = "/saveAccountItem.do", method = {RequestMethod.POST})
	public void saveAccountItem(HttpServletRequest request, HttpServletResponse response) throws IOException {
		User user = getSessionUser(request);

		if (user != null) {
			int userNo = user.getUSER_NO();
			String item = SecureUtils.getParameter(request, "item");
			if ("None".equals(item)) {
				item = null;
			}
			UserConfigVO userConfig = new UserConfigVO(userNo, null, null, null, item, null, null, null);

//			try {
				configService.updateUserItem(userConfig);
//			} catch (Exception e) {
//				e.printStackTrace();
//				throw new Error(e);
//			}
		} else {
			// 사용자 세션이 없을 경우
			throw new Error("User not found.");
		}
	}

	@RequestMapping(value = "/saveAccountPalette.do", method = {RequestMethod.POST})
	public void saveAccountPalette(HttpServletRequest request, HttpServletResponse response) throws IOException {
		User user = getSessionUser(request);

		if (user != null) {
			int userNo = user.getUSER_NO();
			String palette = SecureUtils.getParameter(request, "palette");
			if ("None".equals(palette)) {
				palette = null;
			}
			UserConfigVO userConfig = new UserConfigVO(userNo, null, null, null, null, palette, null, null);

//			try {
				configService.updateUserPalette(userConfig);
//			} catch (Exception e) {
//				e.printStackTrace();
//				throw new Error(e);
//			}
		} else {
			// 사용자 세션이 없을 경우
			throw new Error("User not found.");
		}
	}

	@RequestMapping(value = "/saveAccountViewerReportInfo.do", method = {RequestMethod.POST})
	public void saveAccountViewerReportInfo(HttpServletRequest request, HttpServletResponse response) throws IOException {
		User user = getSessionUser(request);

		if (user != null) {
			int userNo = user.getUSER_NO();
			Integer reportId = Integer.parseInt(SecureUtils.getParameter(request, "reportId"));
			String reportNm = null;
			String reportType = null;
			if (reportId == 0) {
				reportId = null;
			} else {
				reportNm = SecureUtils.getParameter(request, "reportNm");
				reportType = SecureUtils.getParameter(request, "reportType");
			}
			UserConfigVO userConfig = new UserConfigVO(userNo, null, null, null, null, null, reportId, null);

//			try {
				configService.updateUserViewerReportInfo(userConfig);
//			} catch (Exception e) {
//				e.printStackTrace();
//				throw new Error(e);
//			}
		} else {
			// 사용자 세션이 없을 경우
			throw new Error("User not found.");
		}
	}

	@RequestMapping(value = "/saveAccountFontConfig.do", method = {RequestMethod.POST})
	public void saveAccountFontConfig(HttpServletRequest request, HttpServletResponse response) throws IOException {
		User user = getSessionUser(request);

		if (user != null) {
			int userNo = user.getUSER_NO();
			String fontConfig = SecureUtils.getParameter(request, "fontConfig").replaceAll("&quot;", "\"");;
			UserConfigVO userConfig = new UserConfigVO(userNo, null, null, null, null, null, null, fontConfig);

//			try {
				configService.updateUserFontConfig(userConfig);
//			} catch (Exception e) {
//				e.printStackTrace();
//				throw new Error(e);
//			}
		} else {
			// 사용자 세션이 없을 경우
			throw new Error("User not found.");
		}
	}

	@RequestMapping(value = "/openDataSet.do", method = {RequestMethod.POST})
	public void openDataSet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();

		String dataSetID = SecureUtils.getParameter(request, "dataSetID");
		String dataSrcID = SecureUtils.getParameter(request,"dataSrcID");
		String dataSrcType = SecureUtils.getParameter(request,"dataSrcType");
		if(dataSetID != null && dataSrcID != null && dataSrcType != null) {
			String userNo = SecureUtils.getParameter(request,"userNo");

			List<SubjectMasterVO> listDSList = this.dataSetService.selectUserAuthDsList(dataSrcID,userNo);
	        if(listDSList.size() == 0) {
	        	listDSList = this.dataSetService.selectGrpAuthDsList(dataSrcID,userNo);
	        }

			DataSetInfoVO datasetInfo = this.dataSetService.openDataSet(dataSetID, dataSrcID,dataSrcType);
			JSONObject ret = new JSONObject();

			if(datasetInfo != null) {
				ret.put("DATASET_ID", datasetInfo.getDATASET_ID());
				ret.put("DATASET_NM", datasetInfo.getDATASET_NM());
				ret.put("FLD_ID", datasetInfo.getFLD_ID());
				ret.put("DATASRC_ID", datasetInfo.getDATASRC_ID());
				ret.put("DATASRC_TYPE", datasetInfo.getDATASRC_TYPE());
				ret.put("DATASET_TYPE", datasetInfo.getDATASET_TYPE());
				try {
					String datasetString = "";
					if(datasetInfo.getSQL_XML() != null) {
						datasetString = datasetInfo.getSQL_XML();
					}
//					ret.put("SQL_XML", XML.toString(new String(Base64.decode(datasetInfo.getSQL_XML()))));
					String decodedSQL_XML = new String(Base64.decode(datasetString.getBytes()), "UTF-8");
					org.json.JSONObject json = XML.toJSONObject(decodedSQL_XML);
					ret.put("SQL_XML", json.toString());
				} catch (Base64DecodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				try {
					ret.put("SQL_QUERY", new String(Base64.decode(datasetInfo.getSQL_QUERY())));
				} catch (Base64DecodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				ret.put("DATASET_DESC", datasetInfo.getDATASET_DESC());
				ret.put("DATASET_ORDINAL", datasetInfo.getDATASET_ORDINAL());
				ret.put("REG_USER_NO", datasetInfo.getREG_USER_NO());
				ret.put("PRIVACY_YN", datasetInfo.getPRIVACY_YN());
				int i = 0;
				for (SubjectMasterVO vo : listDSList) {
					JSONObject obj = new JSONObject();
					obj.put("ID", i);
					obj.put("DS_ID", vo.getDS_ID());
					obj.put("DS_NM", vo.getDS_NM());
					obj.put("DB_NM", vo.getDB_NM());
					obj.put("IP", vo.getIP());
					obj.put("USER_ID", vo.getUSER_ID());
					obj.put("PORT", vo.getPORT());
					obj.put("DBMS_TYPE", vo.getDBMS_TYPE());
					obj.put("OWNER_NM", vo.getOWNER_NM());
					obj.put("DS_DESC", vo.getDS_DESC());
					obj.put("WF_YN", vo.getWF_YN());
					obj.put("USER_AREA_YN", vo.getUSER_AREA_YN());
					ret.put("DS_Info", obj);
					i++;
				}

			}
			out.print(ret);
			out.flush();
			out.close();
		}
	}

	// 고운산 - 조회 루틴 변경  20210913
	@RequestMapping(value = {"/vldQry.do"}, method = RequestMethod.POST)
	public @ResponseBody List<JSONObject> validationQueryProc(HttpServletRequest request, HttpServletResponse response, Model model) {
		try {
			String dataSourceIdStr = SecureUtils.getParameter(request, "id");
			if(dataSourceIdStr.indexOf(",")>-1) {
				String[] dataSourceIdArr = dataSourceIdStr.split(",");
				dataSourceIdStr = dataSourceIdArr[0];
			}
			int dataSourceId = Integer.parseInt(dataSourceIdStr);
			String dataSourceType = SecureUtils.getParameter(request, "type");
			JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
			String dbType = SecureUtils.getParameter(request, "dbType");

			String sql = Configurator.getInstance()
					.getConfig("wise.ds.repository.mart.connection.pool." + dbType + ".validationQuery");

			List<JSONObject> objData = dataSetService.querySql(dataSourceId, dataSourceType, sql, params, -1, "");
			return objData;

		} catch (Exception e) {
			e.printStackTrace();
			return new JSONArray();
		}
	}
	
	@RequestMapping(value = {"/getUserWbList.do"})
	public void getUserWbList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		
		ArrayList<JSONObject> userArrayList = new ArrayList<JSONObject>();
		List<UserGroupVO> userList = configService.selectUserWbList();
		
		for (UserGroupVO user : userList) {
			JSONObject userjson = new JSONObject();
			userjson.put("AUTH_YN", user.getAuthCount() > 0 ? "Y" : "N");
			userjson.put("사용자NO", user.getUSER_NO());
			userjson.put("사용자ID", user.getUSER_ID());
			userjson.put("사용자명", user.getUSER_NM());
			userjson.put("그룹명", user.getGRP_NM());
			userArrayList.add(userjson);
		}
		
		JSONObject obj = new JSONObject();

		obj.put("userResult", userArrayList);
		out.print(obj);
		out.flush();
		out.close();
	}
	
	@RequestMapping(value = {"/getGrpWbList.do"})
	public void getGrpWbList(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		
		ArrayList<JSONObject> userArrayList = new ArrayList<JSONObject>();
		List<UserGroupVO> groupList = configService.selectGroupWbList();
		
		for (UserGroupVO grp : groupList) {
			JSONObject groupjson = new JSONObject();
			groupjson.put("AUTH_YN", grp.getAuthCount() > 0 ? "Y" : "N");
			groupjson.put("그룹ID", grp.getGRP_ID());
			groupjson.put("그룹명", grp.getGRP_NM());
			groupjson.put("그룹설명", grp.getGRP_DESC());
			userArrayList.add(groupjson);
		}
		
		JSONObject obj = new JSONObject();

		obj.put("groupResult", userArrayList);
		out.print(obj);
		out.flush();
		out.close();
	}
	
	//20210705 AJKIM 메뉴 권한 추가 dogfoot
		@RequestMapping("/getUserWbAuth.do")
		public void getUserWbAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			PrintWriter out = response.getWriter();
			Integer userNo = Integer.parseInt(SecureUtils.getParameter(request, "userNo"));

			List<HashMap> userAuthList = configService.selectUserWbAuth(userNo);

			JSONObject obj = new JSONObject();
			
			if(userAuthList.size() > 0) {
				obj.put("ADHOC", userAuthList.get(0).get("ADHOC_AUTH"));
				obj.put("DASH", userAuthList.get(0).get("DASH_AUTH"));
				obj.put("EXCEL", userAuthList.get(0).get("EXCEL_AUTH"));
				obj.put("ANAL", userAuthList.get(0).get("ANAL_AUTH"));
				obj.put("DS", userAuthList.get(0).get("DS_AUTH"));
				obj.put("CONFIG", userAuthList.get(0).get("CONFIG_AUTH"));
				obj.put("DSVIEWER", userAuthList.get(0).get("DS_VIEWER_AUTH"));
				obj.put("DS_DETAIL", userAuthList.get(0).get("DS_AUTH_DETAIL"));
			}
			
			out.print(obj);
			out.flush();
			out.close();
		}

		@RequestMapping("/getGrpWbAuth.do")
		public void getGrpWbAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
			request.setCharacterEncoding("utf-8");
			response.setCharacterEncoding("utf-8");
			PrintWriter out = response.getWriter();
			String grpId = SecureUtils.getParameter(request, "grp_id");

			
			List<HashMap> grpAuthList = configService.selectGrpWbAuth(grpId);

			JSONObject obj = new JSONObject();
			
			if(grpAuthList.size() > 0) {
				obj.put("ADHOC", grpAuthList.get(0).get("ADHOC_AUTH"));
				obj.put("DASH", grpAuthList.get(0).get("DASH_AUTH"));
				obj.put("EXCEL", grpAuthList.get(0).get("EXCEL_AUTH"));
				obj.put("ANAL", grpAuthList.get(0).get("ANAL_AUTH"));
				obj.put("DS", grpAuthList.get(0).get("DS_AUTH"));
				obj.put("CONFIG", grpAuthList.get(0).get("CONFIG_AUTH"));
				obj.put("DSVIEWER", grpAuthList.get(0).get("DS_VIEWER_AUTH"));
				obj.put("DS_DETAIL", grpAuthList.get(0).get("DS_AUTH_DETAIL"));
			}
			
			System.out.println(obj.get("DS_DETAIL"));

			out.print(obj);
			out.flush();
			out.close();
		}
	
	@RequestMapping("/getUserDsAuth.do")
	public void getUserDsAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		Integer userNo = Integer.parseInt(SecureUtils.getParameter(request, "userNo"));

		List<Integer> authDsList = new ArrayList<Integer>();
//		try {
			List<DataSourceUserVO> userAuthDsList = configService.selectUserDsAuth(userNo);
			for(DataSourceUserVO authDs : userAuthDsList) {
				authDsList.add(authDs.getDS_ID());
			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new Error(e);
//		}

		JSONObject obj = new JSONObject();
		obj.put("authDsList", authDsList);
		out.print(obj);
		out.flush();
		out.close();
	}
	
	@RequestMapping("/getGrpDsAuth.do")
	public void getGrpDsAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		request.setCharacterEncoding("utf-8");
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		String grpId = SecureUtils.getParameter(request, "grpId");

		List<Integer> authDsList = new ArrayList<Integer>();
		
		List<DataSourceGRPVO> userAuthDsList = configService.selectGrpDsAuth(grpId);
		
		for(DataSourceGRPVO authDs : userAuthDsList) {
			authDsList.add(authDs.getDS_ID());
		}

		JSONObject obj = new JSONObject();
		obj.put("authDsList", authDsList);
		out.print(obj);
		out.flush();
		out.close();
	}
	
	//20210520 AJKIM 데이터 원본 권한 추가 dogfoot
	@RequestMapping(value= {"/saveGrpDsAuth.do"}, method = RequestMethod.POST)
	public void saveGrpDsAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer grpId = Integer.parseInt(SecureUtils.getParameter(request, "selectedGroup"));
		String[] dsIds = SecureUtils.getParameters(request).get("selectedDs[]");
		try {
			configService.initGrpDsAuth(grpId);
			if (dsIds != null) {
				for (int i = 0; i < dsIds.length; i++) {
					DataSourceGRPVO grpAuthVo = new DataSourceGRPVO();
					grpAuthVo.setGRP_ID(grpId);
					grpAuthVo.setDS_ID(Integer.parseInt(dsIds[i]));

					configService.insertGrpDsAuth(grpAuthVo);
				}
			}
		} catch (NumberFormatException e) {
			e.printStackTrace();
			throw new Error(e);
		}
	}
	
	@RequestMapping(value= {"/saveUserDsAuth.do"}, method = RequestMethod.POST)
	public void saveUserDsAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer userNo = Integer.parseInt(SecureUtils.getParameter(request, "selectedUser"));
		String[] dsIds = SecureUtils.getParameters(request).get("selectedDs[]");
		try {
			configService.initUserDsAuth(userNo);
			if (dsIds != null) {
				for (int i = 0; i < dsIds.length; i++) {
					DataSourceUserVO userAuthVo = new DataSourceUserVO();
					userAuthVo.setUSER_NO(userNo);
					userAuthVo.setDS_ID(Integer.parseInt(dsIds[i]));

					configService.insertUserDsAuth(userAuthVo);
				}
			}
		} catch (NumberFormatException e) {
			e.printStackTrace();
			throw new Error(e);
		}
	}

	
	@RequestMapping(value= {"/saveGrpWbAuth.do"}, method = RequestMethod.POST)
	public void saveGrpWbAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer grpId = Integer.parseInt(SecureUtils.getParameter(request, "selectedGroup"));
		org.json.JSONObject jsonData = new org.json.JSONObject(SecureUtils.getParameter(request, "data").replaceAll("&quot;", "\""));
		String resetConfig = SecureUtils.getParameter(request, "resetConfig");
		try {
			configService.initGrpWbAuth(grpId);
			if(!resetConfig.equals("true")) {
				HashMap grpAuth = new HashMap();
				
				grpAuth.put("GRP_ID", grpId);
				grpAuth.put("ADHOC", jsonData.getBoolean("ADHOC")? 'Y' : 'N');
				grpAuth.put("DASH", jsonData.getBoolean("DASH")? 'Y' : 'N');
				grpAuth.put("EXCEL", jsonData.getBoolean("EXCEL")? 'Y' : 'N');
				grpAuth.put("ANAL", jsonData.getBoolean("ANAL")? 'Y': 'N');
				grpAuth.put("DS", jsonData.getBoolean("DS")? 'Y': 'N');
				grpAuth.put("CONFIG", jsonData.getBoolean("CONFIG")? 'Y': 'N');
				grpAuth.put("DSVIEWER", jsonData.getBoolean("DSVIEWER")? 'Y': 'N');
				grpAuth.put("DS_DETAIL", jsonData.getString("DS_DETAIL"));

				configService.insertGrpWbAuth(grpAuth);
			}
		} catch (NumberFormatException e) {
			e.printStackTrace();
			throw new Error(e);
		}
	}
	
	@RequestMapping(value= {"/saveUserWbAuth.do"}, method = RequestMethod.POST)
	public void saveUserWbAuth(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		request.setCharacterEncoding("utf-8");
		Integer userNo = Integer.parseInt(SecureUtils.getParameter(request, "selectedUser"));
		System.out.println(SecureUtils.getParameter(request, "data"));
		String resetConfig = SecureUtils.getParameter(request, "resetConfig");
		org.json.JSONObject jsonData = new org.json.JSONObject(SecureUtils.getParameter(request, "data").replaceAll("&quot;", "\""));
		try {
			configService.initUserWbAuth(userNo);
			if(!resetConfig.equals("true")) {
				HashMap grpAuth = new HashMap();

				grpAuth.put("USER_NO", userNo);
				grpAuth.put("ADHOC", jsonData.getBoolean("ADHOC")? 'Y' : 'N');
				grpAuth.put("DASH", jsonData.getBoolean("DASH")? 'Y' : 'N');
				grpAuth.put("EXCEL", jsonData.getBoolean("EXCEL")? 'Y' : 'N');
				grpAuth.put("ANAL", jsonData.getBoolean("ANAL")? 'Y': 'N');
				grpAuth.put("DS", jsonData.getBoolean("DS")? 'Y': 'N');
				grpAuth.put("CONFIG", jsonData.getBoolean("CONFIG")? 'Y': 'N');
				grpAuth.put("DSVIEWER", jsonData.getBoolean("DSVIEWER")? 'Y': 'N');
				grpAuth.put("DS_DETAIL", jsonData.getString("DS_DETAIL"));

				configService.insertUserWbAuth(grpAuth);
			}
		} catch (NumberFormatException e) {
			e.printStackTrace();
			throw new Error(e);
		}
	}
	
	private String default1001(String value) {
		if(value.equals("1001")) {
			value = "";
		}
		return value;
	}
}
