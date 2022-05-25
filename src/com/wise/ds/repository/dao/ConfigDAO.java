package com.wise.ds.repository.dao;

import java.util.HashMap;
import java.util.List;

import org.springframework.stereotype.Repository;

import com.wise.common.jdbc.SqlSessionDaoSupport;
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


@Repository("configDAO")
public class ConfigDAO extends SqlSessionDaoSupport {

	public List<JobListVO> selectJobListMaster() {
		return super.getSqlSession().selectList("Config.selectJobListMaster");
	}
	
	public List<SameTimeConVO> selectSameTimeConMaster() {
		return super.getSqlSession().selectList("Config.selectSameTimeConMaster");
	}

	public List<UserGroupVO> selectUserListAndGroupName() {
		return super.getSqlSession().selectList("Config.selectUserListAndGroupName");
	}
	
	public int selectUserCnt() {
		Integer result = super.getSqlSession().selectOne("Config.selectUserCnt");
		return result;
	}

	public List<DataSourceVO> selectDataSourceList(List<Integer> id) {
		return super.getSqlSession().selectList("Config.selectDataSourceList", id);
	}
	
	public List<DataSourceUserVO> selectDataSourceUserList(int no) {
		return super.getSqlSession().selectList("Config.selectDataSourceUserList", no);
	}
	
	public List<DataSourceGRPVO> selectDataSourceGRPList(int no) {
		return super.getSqlSession().selectList("Config.selectDataSourceGRPList", no);
	}
	
	public Integer selectGroupIdByGroupName(String groupName) {
		Integer result = super.getSqlSession().selectOne("Config.selectGroupIdByGroupName", groupName);
		return result;
	}

	public void updateUserList(UserGroupVO userInfo) {
		super.getSqlSession().insert("Config.updateUserList", userInfo);
	}

	public void updateDatasourceList(DataSourceVO datasource) {
		super.getSqlSession().insert("Config.updateDatasourceList", datasource);
	}
	
	public void insertNewUser(UserGroupVO userInfo) {
		super.getSqlSession().insert("Config.insertNewUser", userInfo);
	}
	
	//2020.12.21 syjin 환경 설정 원본 추가 insert 설정
	public int insertNewDatasource(DataSourceVO datasource) {
		return super.getSqlSession().insert("Config.insertNewDatasource", datasource);
	}
	
	public int insertNewDatasourceUser(DataSourceUserVO datasourceUser) {
		return super.getSqlSession().insert("Config.insertNewDatasourceUser", datasourceUser);
	}

	public List<UserGroupVO> selectGroupList() {
		return super.getSqlSession().selectList("Config.selectGroupList");
	}

	public void deleteUserFromList(UserGroupVO userInfo) {
		super.getSqlSession().insert("Config.deleteUserFromList", userInfo);
	}

	public int deleteDataSourceInfo(DataSourceVO datasource) {
		return super.getSqlSession().delete("Config.deleteDataSourceInfo", datasource);
	}
	
	public int deleteDataSourceUserInfo(DataSourceUserVO datasourceUser) {
		return super.getSqlSession().delete("Config.deleteDataSourceUserInfo", datasourceUser);
	}

	public int deleteDataSourceGrpInfo(DataSourceGRPVO datasourceGrp) {
		return super.getSqlSession().delete("Config.deleteDataSourceGrpInfo", datasourceGrp);
	}

	public void changeUserPassword(UserGroupVO userInfo) {
		super.getSqlSession().insert("Config.changeUserPassword", userInfo);
	}

	public void insertGroupInfo(UserGroupVO groupInfo) {
		super.getSqlSession().insert("Config.insertGroupInfo", groupInfo);
	}

	public void updateGroupInfo(UserGroupVO groupInfo) {
		super.getSqlSession().insert("Config.updateGroupInfo", groupInfo);
	}

	public void deleteGroupInfo(UserGroupVO groupInfo) {
		super.getSqlSession().insert("Config.deleteGroupInfo", groupInfo);
	}

	public List<UserGroupVO> selectUserList() {
		return super.getSqlSession().selectList("Config.selectUserList");
	}

	public List<DSViewVO> selectDSViewList() {
		return super.getSqlSession().selectList("Config.selectDSViewList");
	}

	public List<UserAuthDataSetVO> selectUserAuthDataSet(int userNo) {
		return super.getSqlSession().selectList("Config.selectUserAuthDataSet", userNo);
	}

	public List<CubeVO> selectCubeList(int dsViewId) {
		return super.getSqlSession().selectList("Config.selectCubeList", dsViewId);
	}

	public List<DSViewDimVO> selectDSViewDimList(int dsViewId) {
		return super.getSqlSession().selectList("Config.selectDSViewDimList", dsViewId);
	}

	public List<DSViewHieVO> selectDSViewHieList(int dsViewId) {
		return super.getSqlSession().selectList("Config.selectDSViewHieList", dsViewId);
	}

	public void initUserDataAuth(int userNo) {
		super.getSqlSession().delete("Config.initUserDataAuth", userNo);
	}

	public void insertUserAuthData(InsertUserAuthDataSetVO authVo) {
		super.getSqlSession().insert("Config.insertUserDataAuth", authVo);
	}

	public List<UserGrpAuthReportListVO> selectGrpAuthFolderList(String grpId) {
		return super.getSqlSession().selectList("Config.selectGrpAuthFolderList", grpId);
	}

	public List<UserGrpAuthReportListVO> selectGrpAuthReportList(String grpId) {
		return super.getSqlSession().selectList("Config.selectGrpAuthReportList", grpId);
	}

	public void initGrpFldAuth(int grpId) {
		super.getSqlSession().insert("Config.initGrpFldAuth", grpId);
	}

	public int insertGrpFldAuth(AuthReportVO insertVo) {
		return super.getSqlSession().insert("Config.insertGrpFldAuth", insertVo);
	}

	public void initGrpReportAuth(int grpId) {
		super.getSqlSession().delete("Config.initGrpReportAuth", grpId);
	}

	public int insertGrpReportAuth(AuthReportVO insertVo) {
		return super.getSqlSession().insert("Config.insertGrpReportAuth", insertVo);
	}

	public List<GrpListVO> selectGrpList() {
		return super.getSqlSession().selectList("Config.selectGrpList");
	}

	public List<PublicFolderListVO> selectPubFolderList() {
		return super.getSqlSession().selectList("Config.selectPubFldlist");
	}
	
	public List<PublicFolderListVO> selectPubFolderReportList() {
		return super.getSqlSession().selectList("Config.selectPubFldReportlist");
	}

	public void updateConfigMstr(ConfigMasterVO configVo) {
		super.getSqlSession().insert("Config.updateConfigMstr", configVo);
	}

	public List<DashLoginOutMasterVO> selectDashLoginOutMaster(LogParamVO paramVo) {
		return super.getSqlSession().selectList("Config.selectLoginLog",paramVo);
	}

	public List<DashReportMasterVO> selectDashReportUseMaster(LogParamVO paramVo) {
		return super.getSqlSession().selectList("Config.selectReportLog",paramVo);
	}

	public List<ExportLogVO> selectExportLog(LogParamVO paramVo) {
		return super.getSqlSession().selectList("Config.selectExportLog", paramVo);
	}

	public List<AnalysisLogVO> selectAnalysisLog() {
		return super.getSqlSession().selectList("Config.selectAnalysisLog");
	}

	public List<QueryLogVO> selectQueryLog(LogParamVO paramVo) {
		return super.getSqlSession().selectList("Config.selectQueryLog", paramVo);
	}

	public List<ReportListMasterVO> selectPublicReportList() {
		return super.getSqlSession().selectList("Config.selectPublicReportList");
	}
	
	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public List<ReportListMasterVO> selectUserReportList(int user_id) {
		return super.getSqlSession().selectList("Config.selectUserReportList", user_id);
	}

	public void deletePublicReport(Integer id) {
		super.getSqlSession().insert("Config.deletePublicReport", id);
	}
	
	public void deleteLinkedReport(Integer id) {
		super.getSqlSession().delete("Config.deleteLinkedReport", id);
	}

	public void savePublicReport(ReportListMasterVO report) {
		super.getSqlSession().insert("Config.savePublicReport", report);
	}

	public void addUserToGroup(UserGroupVO user) {
		super.getSqlSession().update("Config.addUserToGroup", user);
	}

	public void removeUserFromGroup(UserGroupVO user) {
		super.getSqlSession().update("Config.removeUserFromGroup", user);
	}

	public List<FolderMasterVO> getPublicFolderList() {
		return super.getSqlSession().selectList("Config.getPublicFolderList");
	}
	
	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public List<FolderMasterVO> getUserFolderList(int user_no) {
		return super.getSqlSession().selectList("Config.getUserFolderList", user_no);
	}

	public int getPublicFolderLevel(Integer parentFldId) {
		Integer result = super.getSqlSession().selectOne("Config.getPublicFolderLevel", parentFldId);
		if (result == null) {
			result = 0;
		}
		return result;
	}

	public int getPublicFolderMaxOrdinal(Integer parentFldId) {
		Integer result = super.getSqlSession().selectOne("Config.getPublicFolderMaxOrdinal", parentFldId);
		if (result == null) {
			result = 0;
		}
		return result;
	}

	public void insertPublicFolder(FolderMasterVO folder) {
		super.getSqlSession().insert("Config.insertPublicFolder", folder);
	}

	public FolderMasterVO getPublicFolderWithNameAndParent(FolderMasterVO folder) {
		return super.getSqlSession().selectOne("Config.getPublicFolderWithNameAndParent", folder);
	}

	public void editPublicFolderName(FolderMasterVO folder) {
		super.getSqlSession().update("Config.editPublicFolderName", folder);
	}

	public List<ReportMasterVO> selectReportsInFolders(List<Integer> folders) {
		return super.getSqlSession().selectList("Config.selectReportsInFolders", folders);
	}

	public void deleteChildFolders(List<Integer> folders) {
		super.getSqlSession().delete("Config.deleteChildFolders", folders);
	}
	
	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public void deleteChildUserFolders(List<Integer> folders) {
		super.getSqlSession().delete("Config.deleteChildUserFolders", folders);
	}

	public void deleteChildReports(List<Integer> folders) {
		super.getSqlSession().update("Config.deleteChildReports", folders);
	}

	public void deleteFolder(Integer folderId) {
		super.getSqlSession().delete("Config.deleteFolder", folderId);
	}
	
	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public void deleteUserFolder(Integer folderId) {
		super.getSqlSession().delete("Config.deleteUserFolder", folderId);
	}

	public List<UserSessionVO> selectUserSessionsByDate(SessionParamVO paramVo) {
		return super.getSqlSession().selectList("Config.selectUserSessionsByDate", paramVo);
	}
	/* DOGFOOT ktkang 동시 접속자 현황에서 하루 지난 로그인 아이디 삭제  20200922 */
	public void deleteUserSessionsByDate(SessionParamVO paramVo) {
		super.getSqlSession().delete("Config.deleteUserSessionsByDate", paramVo);
	}

	public List<UserSessionVO> selectUserSessionsByDateAndStatus(SessionParamVO paramVo) {
		return super.getSqlSession().selectList("Config.selectUserSessionsByDateAndStatus", paramVo);
	}

	public List<UserSessionVO> selectInactiveUserSessions() {
		return super.getSqlSession().selectList("Config.selectInactiveUserSessions");
	}

	public List<UserSessionVO> selectInactiveUserSessionsById(SessionParamVO paramVo) {
		return super.getSqlSession().selectList("Config.selectInactiveUserSessionsById", paramVo);
	}

	public List<UserSessionVO> selectInactiveUserSessionsByNo(SessionParamVO paramVo) {
		return super.getSqlSession().selectList("Config.selectInactiveUserSessionsByNo", paramVo);
	}

	public List<UserGroupVO> selectLockedUserSessions() {
		return super.getSqlSession().selectList("Config.selectLockedUserSessions");
	}

	public List<FolderMasterVO> selectDatasetFolderList() {
		return super.getSqlSession().selectList("Config.selectDatasetFolderList");
	}

	public List<FolderMasterVO> selectGrpDatasetAuth(String grpId) {
		return super.getSqlSession().selectList("Config.selectGrpDatasetAuth", grpId);
	}

	public void initGrpDatasetAuth(Integer grpId) {
		super.getSqlSession().delete("Config.initGrpDatasetAuth", grpId);
	}

	public void insertGrpDatasetAuth(GrpAuthDataSetVO grpAuthVo) {
		super.getSqlSession().insert("Config.insertGrpDatasetAuth", grpAuthVo);
	}

	public List<GrpAuthDataSetVO> selectGroupAuthDataSet(int groupNo) {
		return super.getSqlSession().selectList("Config.selectGroupAuthDataSet", groupNo);
	}

	public void initGroupDataAuth(int groupId) {
		super.getSqlSession().delete("Config.initGroupDataAuth", groupId);
	}

	public void insertGroupAuthData(InsertGroupAuthDataSetVO authVo) {
		super.getSqlSession().insert("Config.insertGroupDataAuth", authVo);
	}

	public List<UserGrpAuthReportListVO> selectUserAuthFolderList(Integer userNo) {
		return super.getSqlSession().selectList("Config.selectUserAuthFolderList", userNo);
	}

	public List<UserGrpAuthReportListVO> selectUserAuthReportList(Integer userNo) {
		return super.getSqlSession().selectList("Config.selectUserAuthReportList", userNo);
	}

	public void initUserFldAuth(int userNo) {
		super.getSqlSession().delete("Config.initUserFldAuth", userNo);
	}

	public void insertUserFldAuth(AuthReportVO insertVo) {
		super.getSqlSession().insert("Config.insertUserFldAuth", insertVo);
	}

	public void initUserReportAuth(int userNo) {
		super.getSqlSession().delete("Config.initUserReportAuth", userNo);
	}

	public void insertUserReportAuth(AuthReportVO insertVo) {
		super.getSqlSession().insert("Config.insertUserReportAuth", insertVo);
	}

	public List<FolderMasterVO> selectUserDatasetAuth(Integer userNo) {
		return super.getSqlSession().selectList("Config.selectUserDatasetAuth", userNo);
	}

	public void initUserDatasetAuth(Integer userNo) {
		super.getSqlSession().delete("Config.initUserDatasetAuth", userNo);
	}

	public void insertUserDataSetAuth(UserAuthDataSetVO userAuthVo) {
		super.getSqlSession().insert("Config.insertUserDatasetAuth", userAuthVo);
	}

	public void updateWebConfigMstr(WebConfigMasterVO webConfigVo) {
		super.getSqlSession().update("Config.updateWebConfigMstr", webConfigVo);
	}

	public void initGroupUsers(Integer groupId) {
		super.getSqlSession().update("Config.initGroupUsers", groupId);
	}

	public void updateGroupUsers(UserGroupVO userGroupVo) {
		super.getSqlSession().update("Config.updateGroupUsers", userGroupVo);
	}

	public List<UserGroupVO> selectUserAuthDataList() {
		return super.getSqlSession().selectList("Config.selectUserAuthDataList");
	}

	public List<UserGroupVO> selectGroupAuthDataList() {
		return super.getSqlSession().selectList("Config.selectGroupAuthDataList");
	}

	public List<UserGroupVO> selectUserDatasetList() {
		return super.getSqlSession().selectList("Config.selectUserDatasetList");
	}

	public List<UserGroupVO> selectGroupDatasetList() {
		return super.getSqlSession().selectList("Config.selectGroupDatasetList");
	}
	
	public List<DataSourceVO> selectDsList() {
		return super.getSqlSession().selectList("Config.selectDsList");
	}

	public List<DataSourceGRPVO> selectGrpDsAuth(String grpId) {
		return super.getSqlSession().selectList("Config.selectGrpDsAuth", grpId);
	}
	
	public List<DataSourceUserVO> selectUserDsAuth(Integer userNo) {
		return super.getSqlSession().selectList("Config.selectUserDsAuth", userNo);
	}
	
	public void initGrpDsAuth(Integer grpId) {
		super.getSqlSession().delete("Config.initGrpDsAuth", grpId);
	}
	
	public void insertGrpDsAuth(DataSourceGRPVO grpAuthVo) {
		super.getSqlSession().insert("Config.insertGrpDsAuth", grpAuthVo);
	}
	
	public void initUserDsAuth(Integer userNo) {
		super.getSqlSession().delete("Config.initUserDsAuth", userNo);
	}
	
	public void insertUserDsAuth(DataSourceUserVO userAuthVo) {
		super.getSqlSession().insert("Config.insertUserDsAuth", userAuthVo);
	}

	
	public List<UserGroupVO> selectGroupAuthDsList() {
		return super.getSqlSession().selectList("Config.selectGroupAuthDsList");
	}
	
	public List<UserGroupVO> selectUserAuthDsList() {
		return super.getSqlSession().selectList("Config.selectUserAuthDsList");
	}

	public UserConfigVO selectUserConfig(Integer userNo) {
		return super.getSqlSession().selectOne("Config.selectUserConfig", userNo);
	}

	public void insertUserConfig(UserConfigVO userConfig) {
		super.getSqlSession().insert("Config.insertUserConfig", userConfig);
	}

	public void updateUserProfileInfo(User user) {
		super.getSqlSession().update("Config.updateUserProfileInfo", user);
	}

	public void updateUserImage(UserConfigVO userConfig) {
		super.getSqlSession().update("Config.updateUserImage", userConfig);
	}

	public void updateUserDatasetId(UserConfigVO userConfig) {
		super.getSqlSession().update("Config.updateUserDatasetId", userConfig);
	}

	public void updateUserReportInfo(UserConfigVO userConfig) {
		super.getSqlSession().update("Config.updateUserReportInfo", userConfig);
	}
	
	public void updateUserItem(UserConfigVO userConfig) {
		super.getSqlSession().update("Config.updateUserItem", userConfig);
	}
	
	public void updateUserPalette(UserConfigVO userConfig) {
		super.getSqlSession().update("Config.updateUserPalette", userConfig);
	}

	public void updateUserViewerReportInfo(UserConfigVO userConfig) {
		super.getSqlSession().update("Config.updateUserViewerReportInfo", userConfig);
	}

	public void updateUserFontConfig(UserConfigVO userConfig) {
		super.getSqlSession().update("Config.updateUserFontConfig", userConfig);
	}

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public FolderMasterVO getUserFolderWithNameAndParent(FolderMasterVO folder) {
		return super.getSqlSession().selectOne("Config.getUserFolderWithNameAndParent", folder);
	}
	
	public void editUserFolderName(FolderMasterVO folder) {
		super.getSqlSession().update("Config.editUserFolderName", folder);
	}
	
	public int getUserFolderLevel(Integer parentFldId) {
		Integer result = super.getSqlSession().selectOne("Config.getUserFolderLevel", parentFldId);
		if (result == null) {
			result = 0;
		}
		return result;
	}
	
	public int getUserFolderMaxOrdinal(Integer parentFldId) {
		Integer result = super.getSqlSession().selectOne("Config.getUserFolderMaxOrdinal", parentFldId);
		if (result == null) {
			result = 0;
		}
		return result;
	}
	
	public void insertUserFolder(FolderMasterVO folder) {
		super.getSqlSession().insert("Config.insertUserFolder", folder);
	}
	
	public List<HashMap> selectGrpWbAuth(String grpId) {
		return super.getSqlSession().selectList("Config.selectGrpWbAuth", grpId);
	}
	
	public List<HashMap> selectUserWbAuth(Integer userNo) {
		return super.getSqlSession().selectList("Config.selectUserWbAuth", userNo);
	}
	
	public void initGrpWbAuth(Integer grpId) {
		super.getSqlSession().delete("Config.initGrpWbAuth", grpId);
	}
	public void initUserWbAuth(Integer userNo) {
		super.getSqlSession().delete("Config.initUserWbAuth", userNo);
	}
	
	public void insertGrpWbAuth(HashMap grpAuth) {
		super.getSqlSession().insert("Config.insertGrpWbAuth", grpAuth);
	}
	public void insertUserWbAuth(HashMap userAuth) {
		super.getSqlSession().insert("Config.insertUserWbAuth", userAuth);
	}
	
	public List<UserGroupVO> selectUserWbList() {
		return super.getSqlSession().selectList("Config.selectUserWbList");
	}
	
	public List<UserGroupVO> selectGroupWbList() {
		return super.getSqlSession().selectList("Config.selectGroupWbList");
	}
}
