package com.wise.ds.repository.service.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.wise.ds.repository.AnalysisLogVO;
import com.wise.authn.ConfigMasterVO;
import com.wise.authn.DataSourceGRPVO;
import com.wise.authn.DataSourceUserVO;
import com.wise.authn.DataSourceVO;
import com.wise.authn.User;
import com.wise.authn.UserSessionVO;
import com.wise.authn.WebConfigMasterVO;
import com.wise.ds.repository.CubeVO;
import com.wise.ds.repository.CurrentSqlVO;
import com.wise.ds.repository.DSViewDimVO;
import com.wise.ds.repository.DSViewHieVO;
import com.wise.ds.repository.DSViewVO;
import com.wise.ds.repository.DashLoginOutMasterVO;
import com.wise.ds.repository.DashReportMasterVO;
import com.wise.ds.repository.DataSetMasterVO;
import com.wise.ds.repository.ExportLogVO;
import com.wise.ds.repository.FolderMasterVO;
import com.wise.ds.repository.GrpAuthDataSetVO;
import com.wise.ds.repository.UserGrpAuthReportListVO;
import com.wise.ds.repository.AuthReportVO;
import com.wise.ds.repository.GrpListVO;
import com.wise.ds.repository.InsertGroupAuthDataSetVO;
import com.wise.ds.repository.InsertUserAuthDataSetVO;
import com.wise.ds.repository.JobListVO;
import com.wise.ds.repository.LogParamVO;
import com.wise.ds.repository.QueryLogVO;
import com.wise.ds.repository.ReportListMasterVO;
import com.wise.ds.repository.ReportMasterVO;
import com.wise.ds.repository.SameTimeConVO;
import com.wise.ds.repository.SessionParamVO;
import com.wise.ds.repository.UserAuthDataSetVO;
import com.wise.ds.repository.UserConfigVO;
import com.wise.ds.repository.PublicFolderListVO;
import com.wise.authn.UserGroupVO;
import com.wise.ds.repository.dao.ConfigDAO;
import com.wise.ds.repository.dao.DataSetDAO;
import com.wise.ds.repository.service.ConfigService;
import com.wise.ds.repository.service.DataSetService;

@Service("configService")
public class ConfigServiceImpl implements ConfigService {
	final static private Logger logger = LoggerFactory.getLogger(ConfigServiceImpl.class);

	@Resource(name = "configDAO")
	private ConfigDAO configDao;

    @Resource(name = "dataSetDAO")
    private DataSetDAO dataSetDAO;

    @Resource(name = "dataSetService")
    private DataSetService dataSetService;

	@Override
	public List<JobListVO> selectJobListMaster() {
		return this.configDao.selectJobListMaster();
	}

	@Override
	public List<SameTimeConVO> selectSameTimeConMaster() {
		return this.configDao.selectSameTimeConMaster();
	}

	@Override
	public List<DataSourceVO> selectDataSourceList(List<Integer> id) {
		return this.configDao.selectDataSourceList(id);
	}

	@Override
	public List<DataSourceUserVO> selectDataSourceUserList(int no) {
		// TODO Auto-generated method stub
		return this.configDao.selectDataSourceUserList(no);
	}

	@Override
	public List<DataSourceGRPVO> selectDataSourceGRPList(int no) {
		// TODO Auto-generated method stub
		return this.configDao.selectDataSourceGRPList(no);
	}

	@Override
	public List<UserGroupVO> selectUserListAndGroupName() {
		return this.configDao.selectUserListAndGroupName();
	}
	
	@Override
	public int selectUserCnt() {
		return this.configDao.selectUserCnt();
	}

	@Override
	public Integer selectGroupIdByGroupName(String groupName) {
		return this.configDao.selectGroupIdByGroupName(groupName);
	}

	@Override
	public void updateUserList(UserGroupVO userInfo) {
		this.configDao.updateUserList(userInfo);
	}

	@Override
	public void insertNewUser(UserGroupVO userInfo) {
		this.configDao.insertNewUser(userInfo);

	}

	@Override
	public List<UserGroupVO> selectGroupList() {
		return this.configDao.selectGroupList();
	}

	@Override
	public void deleteUserFromList(UserGroupVO userInfo) {
		this.configDao.deleteUserFromList(userInfo);
	}

	@Override
	public void changeUserPassword(UserGroupVO userInfo) {
		this.configDao.changeUserPassword(userInfo);

	}

	@Override
	public int insertNewDatasource(DataSourceVO datasource) {
		return this.configDao.insertNewDatasource(datasource);
	}

	@Override
	public int insertNewDatasourceUser(DataSourceUserVO datasourceUser) {
		return this.configDao.insertNewDatasourceUser(datasourceUser);
	}

	@Override
	public void insertGroupInfo(UserGroupVO groupInfo) {
		this.configDao.insertGroupInfo(groupInfo);
	}

	@Override
	public void updateGroupInfo(UserGroupVO groupInfo) {
		this.configDao.updateGroupInfo(groupInfo);
	}

	@Override
	public void deleteGroupInfo(UserGroupVO groupInfo) {
		this.configDao.deleteGroupInfo(groupInfo);
	}

	@Override
	public List<UserGroupVO> selectUserList() {
		return this.configDao.selectUserList();
	}

	@Override
	public List<DSViewVO> selectDSViewList() {
		return this.configDao.selectDSViewList();
	}

	@Override
	public List<UserAuthDataSetVO> selectUserAuthDataSet(int userNo) {
		return this.configDao.selectUserAuthDataSet(userNo);
	}

	@Override
	public List<CubeVO> selectCubeList(int dsViewId) {
		return this.configDao.selectCubeList(dsViewId);
	}

	@Override
	public List<DSViewDimVO> selectDSViewDimList(int dsViewId) {
		return this.configDao.selectDSViewDimList(dsViewId);
	}

	@Override
	public List<DSViewHieVO> selectDSViewHieList(int dsViewId) {
		return this.configDao.selectDSViewHieList(dsViewId);
	}

	@Override
	public void initUserDataAuth(int userNo) {
		this.configDao.initUserDataAuth(userNo);
	}

	@Override
	public void insertUserAuthData(InsertUserAuthDataSetVO authVo) {
		this.configDao.insertUserAuthData(authVo);
	}

	@Override
	public List<UserGrpAuthReportListVO> selectGrpAuthFolderList(String grpId) {
		return this.configDao.selectGrpAuthFolderList(grpId);
	}

	@Override
	public List<UserGrpAuthReportListVO> selectGrpAuthReportList(String grpId) {
		return this.configDao.selectGrpAuthReportList(grpId);
	}

	@Override
	public void initGrpFldAuth(int grpId) {
		this.configDao.initGrpFldAuth(grpId);
	}

	@Override
	public int insertGrpFldAuth(AuthReportVO insertVo) {
		return this.configDao.insertGrpFldAuth(insertVo);
	}

	@Override
	public void initGrpReportAuth(int grpId) {
		this.configDao.initGrpReportAuth(grpId);
	}

	@Override
	public int insertGrpReportAuth(AuthReportVO insertVo) {
		return this.configDao.insertGrpReportAuth(insertVo);
	}

	@Override
	public List<GrpListVO> selectGrpList() {
		return this.configDao.selectGrpList();
	}

	@Override
	public List<PublicFolderListVO> selectPubFolderList() {
		return this.configDao.selectPubFolderList();
	}

	@Override
	public List<PublicFolderListVO> selectPubFolderReportList() {
		return this.configDao.selectPubFolderReportList();
	}

	@Override
	public void updateConfigMstr(ConfigMasterVO configVo) {
		this.configDao.updateConfigMstr(configVo);
	}
	@Override
	public List<CurrentSqlVO> selectCurrentSqlList(String ds_id) {
		Connection connection = null;
		PreparedStatement pstmt = null;
		ResultSet resultSet = null;
		List<CurrentSqlVO> list = new ArrayList<CurrentSqlVO>();

		try {
			int dataSourceId = Integer.parseInt(ds_id);
			DataSetMasterVO dataSetMaster = this.dataSetDAO.selectDataSetMaster(dataSourceId);
			String dbtype = dataSetMaster.getDatabaseType();
			connection = this.dataSetService.getConnection(dataSourceId, "DS");
			String sql = "";
			if(dbtype.equals("MS-SQL")) {
				sql = "Select\r\n" +
					" CONVERT (VARCHAR, DATEADD (S, REQ.TOTAL_ELAPSED_TIME / 1000, '' ), 8) AS RUN_TIME\r\n" +
					", REQ.SESSION_ID AS SESSION_ID\r\n" +
					", SQLTEXT.TEXT AS SQL_TEXT\r\n" +
					", REQ.STATUS AS WAIT_INFO\r\n" +
					" FROM SYS.DM_EXEC_REQUESTS REQ\r\n" +
					" CROSS APPLY SYS.DM_EXEC_SQL_TEXT(SQL_HANDLE) AS SQLTEXT\r\n" +
					" WHERE CONVERT (VARCHAR, DATEADD (S, REQ.TOTAL_ELAPSED_TIME / 1000, '' ), 8) != '00:00:00'";
			} else if(dbtype.equals("ORACLE")) {
				sql = "SELECT\r\n" +
					" SUBSTR(TO_CHAR(SYSTIMESTAMP - A.SQL_EXEC_START ,'YYYYMMDD HH24MISS') ,12,8) AS RUN_TIME\r\n" +
					", A.SID ||','|| A.SERIAL# AS SESSION_ID\r\n" +
					", B.SQL_TEXT AS SQL_TEXT\r\n" +
					", A.STATUS AS WAIT_INFO\r\n" +
					" FROM V$SESSION A, V$SQLAREA B\r\n" +
					" WHERE A.SQL_HASH_VALUE = B.HASH_VALUE\r\n" +
					" AND A.SQL_ADDRESS=B.ADDRESS\r\n" +
					" AND A.STATUS='ACTIVE'";
			} else if(dbtype.equals("DB2BLU")) {
				sql = "SELECT\r\n" +
					" elapsed_time_sec AS RUN_TIME\r\n" +
					", application_handle AS SESSION_ID\r\n" +
					", stmt_text AS SQL_TEXT\r\n" +
					", CASE WHEN activity_state = 'IDLE' THEN 'RUNNING' ELSE activity_state END AS WAIT_INFO\r\n" +
					" FROM sysibmadm.mon_current_sql\r\n" +
					" WHERE activity_state != 'EXECUTING'\r\n" +
					" ORDER BY elapsed_time_sec DESC";
			} else if(dbtype.equals("TIBERO") || dbtype.equals("TBIN")) {
				sql = "SELECT\r\n" +
					" (Round(A.SQL_ET/1000/(60*60)))||':'||LPad(Round(Mod((A.SQL_ET/1000/60),60)),2,0)||':' ||LPad(Round(Mod(A.SQL_ET/1000,60)),2,0) AS RUN_TIME\r\n" +
					", A.SID ||','|| A.SERIAL# AS SESSION_ID\r\n" +
					", B.SQL_TEXT AS SQL_TEXT\r\n" +
					", A.STATUS AS WAIT_INFO\r\n" +
					" From V$SESSION A, V$SQLAREA B\r\n" +
					" WHERE A.SQL_ID=B.SQL_ID\r\n" +
					" AND status='RUNNING'";
			} else if(dbtype.equals("MARIA") || dbtype.equals("MYSQL")) {
				sql = "select time AS RUN_TIME\r\n" +
					", id AS SESSION_ID\r\n" +
					", info AS SQL_TEXT\r\n" +
					", state AS WAIT_INFO\r\n" +
					"from information_schema.processlist \r\n" +
					"where COMMAND  = 'Query'\r\n" +
					"AND info not like 'SET STATEMENT %'\r\n" +
					"AND state not like 'Filling schema table%' ";
			}
			if(!"".equals(sql)) {
				logger.debug("database type = "+dbtype);
				logger.debug("database session list query = "+sql);
				pstmt = connection.prepareStatement(sql);
				resultSet = pstmt.executeQuery();
				while(resultSet.next()) {
					CurrentSqlVO vo = new CurrentSqlVO();
					vo.setRUNTIME(resultSet.getString("RUN_TIME"));
					vo.setSESSION_ID(resultSet.getString("SESSION_ID"));
					vo.setSQL_TEXT(resultSet.getString("SQL_TEXT"));
					vo.setWAIT_INFO(resultSet.getString("WAIT_INFO"));
					list.add(vo);
				}
				logger.debug("database session list size = "+list.size());
			}
		} catch (Exception e) {
			e.printStackTrace();
        } finally {
        	if (resultSet != null) {
        		try {
             		resultSet.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		resultSet = null;
             	}
        	}
        	if (pstmt != null) {
             	try {
             		pstmt.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		pstmt = null;
             	}
        	}
        	if (connection != null) {
             	try {
             		connection.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		connection = null;
             	}
        	}
		}
		return list;
	}

	@Override
	public int stopProcess(String session_id, String ds_id) {
		Connection connection = null;
		Statement stmt = null;

		try {
			int dataSourceId = Integer.parseInt(ds_id);
			DataSetMasterVO dataSetMaster = this.dataSetDAO.selectDataSetMaster(dataSourceId);
			String dbtype = dataSetMaster.getDatabaseType();
			connection = this.dataSetService.getConnection(dataSourceId, "DS");
			String sql = "";
			if(dbtype.equals("MS-SQL")) {
				sql = "KILL "+session_id;
			} else if(dbtype.equals("ORACLE")) {
				sql = "ALTER SYSTEM KILL SESSION "+session_id;
			} else if(dbtype.equals("DB2BLU")) {
				sql = "CALL SYSPROC.ADMIN_CMD('force application ("+session_id+")')";
			} else if(dbtype.equals("TIBERO") || dbtype.equals("TBIN")) {
				sql = "ALTER SYSTEM KILL SESSION "+session_id;
			} else if(dbtype.equals("MARIA") || dbtype.equals("MYSQL")) {
				sql = "KILL QUERY "+session_id;
			}
			if(!"".equals(sql)) {
				logger.debug("database session kill query = "+sql);
				stmt = connection.createStatement();
				stmt.execute(sql);
			}
		} catch (Exception e) {
			e.printStackTrace();
        } finally {
        	if (stmt != null) {
        		try {
        			stmt.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		stmt = null;
             	}
        	}
        	if (connection != null) {
             	try {
             		connection.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		connection = null;
             	}
        	}
		}
		return 0;
	}
	@Override
	public List<DashLoginOutMasterVO> selectDashLoginOutMaster(LogParamVO paramVo) {
		return this.configDao.selectDashLoginOutMaster(paramVo);
	}

	@Override
	public List<DashReportMasterVO> selectDashReportUseMaster(LogParamVO paramVo) {
		return this.configDao.selectDashReportUseMaster(paramVo);
	}

	@Override
	public List<ExportLogVO> selectExportLog(LogParamVO paramVo) {
		return this.configDao.selectExportLog(paramVo);
	}

	@Override
	public List<AnalysisLogVO> selectAnalysisLog() {
		return this.configDao.selectAnalysisLog();
	}

	@Override
	public List<QueryLogVO> selectQueryLog(LogParamVO paramVo) {
		return this.configDao.selectQueryLog(paramVo);
	}

	@Override
	public List<ReportListMasterVO> selectPublicReportList() {
		return this.configDao.selectPublicReportList();
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	@Override
	public List<ReportListMasterVO> selectUserReportList(int user_id) {
		return this.configDao.selectUserReportList(user_id);
	}

	@Override
	public void deletePublicReport(Integer id) {
		this.configDao.deletePublicReport(id);
		this.configDao.deleteLinkedReport(id);
	}

	@Override
	public void savePublicReport(ReportListMasterVO report) {
		this.configDao.savePublicReport(report);
	}

	@Override
	public void addUserToGroup(UserGroupVO user) {
		this.configDao.addUserToGroup(user);
	}

	@Override
	public void removeUserFromGroup(UserGroupVO user) {
		this.configDao.removeUserFromGroup(user);
	}

	@Override
	public List<FolderMasterVO> getPublicFolderList() {
		return this.configDao.getPublicFolderList();
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	@Override
	public List<FolderMasterVO> getUserFolderList(int user_no) {
		return this.configDao.getUserFolderList(user_no);
	}

	@Override
	public int getPublicFolderLevel(Integer parentFldId) {
		return this.configDao.getPublicFolderLevel(parentFldId);
	}

	@Override
	public int getPublicFolderMaxOrdinal(Integer parentFldId) {
		return this.configDao.getPublicFolderMaxOrdinal(parentFldId);
	}

	@Override
	public void insertPublicFolder(FolderMasterVO folder) {
		this.configDao.insertPublicFolder(folder);
	}

	@Override
	public FolderMasterVO getPublicFolderWithNameAndParent(FolderMasterVO folder) {
		return this.configDao.getPublicFolderWithNameAndParent(folder);
	}

	@Override
	public void editPublicFolderName(FolderMasterVO folder) {
		this.configDao.editPublicFolderName(folder);
	}

	@Override
	public List<ReportMasterVO> selectReportsInFolders(List<Integer> folders) {
		return this.configDao.selectReportsInFolders(folders);
	}

	@Override
	public void deleteChildFolders(List<Integer> folders) {
		this.configDao.deleteChildFolders(folders);
	}

	@Override
	public void deleteChildReports(List<Integer> folders) {
		this.configDao.deleteChildReports(folders);
	}

	@Override
	public void deleteFolder(Integer folderId) {
		this.configDao.deleteFolder(folderId);
	}

	@Override
	public List<UserSessionVO> selectUserSessions(SessionParamVO paramVo) {
		if (paramVo.getLogStatus().equals("All")) {
			return configDao.selectUserSessionsByDate(paramVo);
		}
		return configDao.selectUserSessionsByDateAndStatus(paramVo);
	}
	/* DOGFOOT ktkang 동시 접속자 현황에서 하루 지난 로그인 아이디 삭제  20200922 */
	@Override
	public void deleteUserSessionsByDate(SessionParamVO paramVo) {
		configDao.deleteUserSessionsByDate(paramVo);
	}

	@Override
	public List<UserSessionVO> selectInactiveUserSessions(SessionParamVO paramVo) {
		String filter = paramVo.getIdNoFilter();
		if (filter.isEmpty()) {
			return configDao.selectInactiveUserSessions();
		} else {
			paramVo.setIdNoFilter("%" + filter + "%");
			if (paramVo.getIdNo().equals("USER_ID")) {
				return configDao.selectInactiveUserSessionsById(paramVo);
			}
			return configDao.selectInactiveUserSessionsByNo(paramVo);
		}
	}

	@Override
	public List<UserGroupVO> selectLockedUserSessions() {
		return configDao.selectLockedUserSessions();
	}

	@Override
	public List<FolderMasterVO> selectDatasetFolderList() {
		return configDao.selectDatasetFolderList();
	}

	@Override
	public List<FolderMasterVO> selectGrpDatasetAuth(String grpId) {
		return configDao.selectGrpDatasetAuth(grpId);
	}

	@Override
	public void initGrpDatasetAuth(Integer grpId) {
		configDao.initGrpDatasetAuth(grpId);
	}

	@Override
	public void insertGrpDatasetAuth(GrpAuthDataSetVO grpAuthVo) {
		configDao.insertGrpDatasetAuth(grpAuthVo);
	}

	@Override
	public List<GrpAuthDataSetVO> selectGroupAuthDataSet(int groupNo) {
		return configDao.selectGroupAuthDataSet(groupNo);
	}

	@Override
	public void initGroupDataAuth(int groupId) {
		configDao.initGroupDataAuth(groupId);
	}

	@Override
	public void insertGroupAuthData(InsertGroupAuthDataSetVO authVo) {
		configDao.insertGroupAuthData(authVo);
	}

	@Override
	public List<UserGrpAuthReportListVO> selectUserAuthFolderList(Integer userNo) {
		return configDao.selectUserAuthFolderList(userNo);
	}

	@Override
	public List<UserGrpAuthReportListVO> selectUserAuthReportList(Integer userNo) {
		return configDao.selectUserAuthReportList(userNo);
	}
	
	@Override
	public List<UserGroupVO> selectGroupAuthDsList() {
		return configDao.selectGroupAuthDsList();
	}
	
	@Override
	public List<UserGroupVO> selectUserAuthDsList() {
		return configDao.selectUserAuthDsList();
	}
	
	@Override
	public List<DataSourceVO> selectDsList() {
		return this.configDao.selectDsList();
	}
	
	@Override
	public List<DataSourceUserVO> selectUserDsAuth(Integer userNo) {
		return configDao.selectUserDsAuth(userNo);
	}
	
	@Override
	public List<DataSourceGRPVO> selectGrpDsAuth(String grpId) {
		return configDao.selectGrpDsAuth(grpId);
	}

	@Override
	public void initGrpDsAuth(Integer grpId) {
		configDao.initGrpDsAuth(grpId);
	}

	@Override
	public void insertGrpDsAuth(DataSourceGRPVO grpAuthVo) {
		configDao.insertGrpDsAuth(grpAuthVo);
	}
	
	@Override
	public void initUserDsAuth(Integer userNo) {
		configDao.initUserDsAuth(userNo);
	}

	@Override
	public void insertUserDsAuth(DataSourceUserVO userAuthVo) {
		configDao.insertUserDsAuth(userAuthVo);
	}
	@Override
	public void initUserFldAuth(int userNo) {
		configDao.initUserFldAuth(userNo);
	}

	@Override
	public void insertUserFldAuth(AuthReportVO insertVo) {
		configDao.insertUserFldAuth(insertVo);
	}

	@Override
	public void initUserReportAuth(int userNo) {
		configDao.initUserReportAuth(userNo);
	}

	@Override
	public void insertUserReportAuth(AuthReportVO insertVo) {
		configDao.insertUserReportAuth(insertVo);
	}

	@Override
	public List<FolderMasterVO> selectUserDatasetAuth(Integer userNo) {
		return configDao.selectUserDatasetAuth(userNo);
	}

	@Override
	public void initUserDatasetAuth(Integer userNo) {
		configDao.initUserDatasetAuth(userNo);
	}

	@Override
	public void insertUserDatasetAuth(UserAuthDataSetVO userAuthVo) {
		configDao.insertUserDataSetAuth(userAuthVo);
	}

	@Override
	public void updateWebConfigMstr(WebConfigMasterVO webConfigVo) {
		configDao.updateWebConfigMstr(webConfigVo);
	}

	@Override
	public void initGroupUsers(Integer groupId) {
		configDao.initGroupUsers(groupId);
	}

	@Override
	public void updateGroupUsers(UserGroupVO userGroupVo) {
		configDao.updateGroupUsers(userGroupVo);
	}

	@Override
	public List<UserGroupVO> selectUserAuthDataList() {
		return configDao.selectUserAuthDataList();
	}

	@Override
	public List<UserGroupVO> selectGroupAuthDataList() {
		return configDao.selectGroupAuthDataList();
	}

	@Override
	public List<UserGroupVO> selectUserDatasetList() {
		return configDao.selectUserDatasetList();
	}

	@Override
	public List<UserGroupVO> selectGroupDatasetList() {
		return configDao.selectGroupDatasetList();
	}

	@Override
	public UserConfigVO selectUserConfig(Integer userNo) {
		UserConfigVO userConfig = configDao.selectUserConfig(userNo);
		if (userConfig == null) {
			userConfig = new UserConfigVO(userNo, null, null, null, null, null, null, null);
			insertUserConfig(userConfig);
		}
		return userConfig;
	}

	@Override
	public void insertUserConfig(UserConfigVO userConfig) {
		configDao.insertUserConfig(userConfig);
	}

	@Override
	public void updateUserProfile(User user, UserConfigVO userConfig) {
		configDao.updateUserProfileInfo(user);
		configDao.updateUserImage(userConfig);
	}

	@Override
	public void updateUserDatasetId(UserConfigVO userConfig) {
		configDao.updateUserDatasetId(userConfig);
	}

	@Override
	public void updateUserReportInfo(UserConfigVO userConfig) {
		configDao.updateUserReportInfo(userConfig);
	}

	@Override
	public void updateUserItem(UserConfigVO userConfig) {
		configDao.updateUserItem(userConfig);
	}

	@Override
	public void updateUserPalette(UserConfigVO userConfig) {
		configDao.updateUserPalette(userConfig);
	}

	@Override
	public void updateUserViewerReportInfo(UserConfigVO userConfig) {
		configDao.updateUserViewerReportInfo(userConfig);
	}

	@Override
	public void updateUserFontConfig(UserConfigVO userConfig) {
		configDao.updateUserFontConfig(userConfig);
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public void deleteChildUserFolders(List<Integer> folders) {
		configDao.deleteChildUserFolders(folders);
	}
	public void deleteUserFolder(int folderId) {
		configDao.deleteUserFolder(folderId);
	}

	@Override
	public FolderMasterVO getUserFolderWithNameAndParent(FolderMasterVO folder) {
		return this.configDao.getUserFolderWithNameAndParent(folder);
	}

	@Override
	public void editUserFolderName(FolderMasterVO folder) {
		this.configDao.editUserFolderName(folder);
	}

	@Override
	public int getUserFolderLevel(Integer parentFldId){
		return this.configDao.getUserFolderLevel(parentFldId);
	}

	@Override
	public int getUserFolderMaxOrdinal(Integer parentFldId) {
		return this.configDao.getUserFolderMaxOrdinal(parentFldId);
	}

	@Override
	public void insertUserFolder(FolderMasterVO folder) {
		this.configDao.insertUserFolder(folder);
	}

	@Override
	public void updateDatasourceList(DataSourceVO datasource) {

		this.configDao.updateDatasourceList(datasource);
	}

	@Override
	public int deleteDataSourceInfo(DataSourceVO datasource) {

		return this.configDao.deleteDataSourceInfo(datasource);
	}

	@Override
	public int deleteDataSourceUserInfo(DataSourceUserVO datasourceUser) {

		return this.configDao.deleteDataSourceUserInfo(datasourceUser);
	}

	@Override
	public int deleteDataSourceGrpInfo(DataSourceGRPVO datasourceGrp) {

		return this.configDao.deleteDataSourceGrpInfo(datasourceGrp);
	}
	
	@Override
	public List<HashMap> selectGrpWbAuth(String grpId) {
		return configDao.selectGrpWbAuth(grpId);
	}
	
	@Override
	public List<HashMap> selectUserWbAuth(Integer userNo) {
		return configDao.selectUserWbAuth(userNo);
	}
	
	@Override
	public List<UserGroupVO> selectUserWbList() {
		return configDao.selectUserWbList();
	}
	
	@Override
	public List<UserGroupVO> selectGroupWbList() {
		return configDao.selectGroupWbList();
	}
	
	@Override
	public void initUserWbAuth(Integer userNo) {
		configDao.initUserWbAuth(userNo);
	}
	
	@Override
	public void insertUserWbAuth(HashMap userAuth) {
		configDao.insertUserWbAuth(userAuth);
	}
	
	@Override
	public void initGrpWbAuth(Integer grpId) {
		configDao.initGrpWbAuth(grpId);
	}
	
	@Override
	public void insertGrpWbAuth(HashMap grpAuth) {
		configDao.insertGrpWbAuth(grpAuth);
	}
}
