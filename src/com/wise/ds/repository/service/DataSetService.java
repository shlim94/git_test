package com.wise.ds.repository.service;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.wise.authn.User;
import com.wise.common.util.CloseableList;
import com.wise.common.util.FileBackedJSONObjectList;
import com.wise.ds.repository.CubeListMasterVO;
import com.wise.ds.repository.CubeMember;
import com.wise.ds.repository.CubeTableVO;
import com.wise.ds.repository.DSViewColVO;
import com.wise.ds.repository.DataSetInfoMasterVO;
import com.wise.ds.repository.DataSetInfoVO;
import com.wise.ds.repository.DataSetMasterVO;
import com.wise.ds.repository.FolderMasterVO;
import com.wise.ds.repository.ParamScheduleVO;
import com.wise.ds.repository.ReportListMasterVO;
import com.wise.ds.repository.SubjectCubeMasterVO;
import com.wise.ds.repository.SubjectMasterVO;
import com.wise.ds.repository.SubjectViewMasterVO;
import com.wise.ds.repository.TableRelationVO;
import com.wise.ds.repository.TossExeVO;
import com.wise.ds.repository.UndefinedDataTypeForNullValueException;
import com.wise.ds.repository.dataset.DataField;
import com.wise.ds.repository.dataset.EmptyDataSetInformationException;
import com.wise.ds.repository.dataset.NotFoundDataSetTypeException;
import com.wise.ds.repository.dataset.NotFoundDatabaseConnectorException;
import com.wise.ds.sql.CubeTable;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import wise.querygen.dto.Hierarchy;
import wise.querygen.dto.SelectCube;
import wise.querygen.dto.SelectCubeMeasure;
import wise.querygen.dto.SelectCubeOrder;
import wise.querygen.dto.SelectCubeWhere;


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

public interface DataSetService {
    
    public void connect(int dataSourceId, String dataSourceType) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException;
    
//    public Connection getConnection(int dataSourceId);
    public Connection getConnection(int dataSourceId, String dataSourceType) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, SQLException;
    
    // 고운산 - 조회 루틴 변경  20210913
    public CloseableList<JSONObject> querySqlById(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout, String queryParam) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
    //ORIGIN
//    public JSONArray querySqlById(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout, boolean join) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
    
//    public JSONArray querySql(int dataSourceId, String sql, JSONObject params);
    
    // 고운산 - 조회 루틴 변경  20210913
    public CloseableList<JSONObject> querySql(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout, String queryParam) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;

    public CloseableList<JSONObject> sparkSql(ArrayList<Integer> dsid, ArrayList<String> tblnm, String dataSourceType, String sql, JSONObject params, int sqlTimeout, String queryParam) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
    
    // 고운산 - 조회 루틴 변경  20210913
    public CloseableList<JSONObject> queryCountSqlById(int dataSourceId, String dataSourceType, String sqlId, JSONObject params, int sqlTimeout) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
    
    public CloseableList<JSONObject> queryCountSql(int dataSourceId, String dataSourceType, String sqlId, JSONObject params, int sqlTimeout) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
    
    public CloseableList<JSONObject> directQuerySql(int dataSourceId, String dataSourceType, String sql, JSONObject params) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;

    public CloseableList<JSONObject> directSparkSql(ArrayList<Integer> dsid, ArrayList<String> tblnm, String dataSourceType, String sql, JSONObject params) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
	
    public int getDSIDforLog(int dataSourceId,String dataSourceType);
    
    /* DOGFOOT ktkang 주제영역 권한 추가  20200120 */
    public List<SubjectViewMasterVO> selectSubjectUserViewList(String userId);
    
    public List<SubjectViewMasterVO> selectSubjectGrpViewList(String userId);
    
    public List<SubjectMasterVO> selectSubjectList();
    
	public int selectCubeIdByDsId(int ds_id);
	
	public Map<String,List<CubeTableVO>> selectCubeReportTableInfoList(int cubeId , String userId);
	
	public DataSetMasterVO getDataSourceInfo(int dataSourceId,String dataSourceType);
	
	public DataSetInfoMasterVO selectDataSetInfo(int dataSetId);
	
	public List<DataSetInfoMasterVO> selectDataSetInfoList();
	
	public List<DataSetInfoMasterVO> selectDataSetInfoList(List<String> dsType);
	
	public List<FolderMasterVO> selectUserAuthDataSetFolderList(String userId);
	
	public List<FolderMasterVO> selectGrpAuthDataSetFolderList(String userId);

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public FolderMasterVO selectReportFld(String pid, String folderId, String fldType);
	
	public List<FolderMasterVO> selectPrivateUserReportFolderList(String userId);

	public List<FolderMasterVO> selectGrpReportFolderList(String userId);

	public List<FolderMasterVO> selectUserReportFolderList(String userId);
	
	public List<ReportListMasterVO> selectReportList(String user_id);
	
	/* DOGFOOT ktkang KERIS KERIS 주제영역 폴더 형식으로 표현  20200120 */
	public List<CubeListMasterVO> selectCubeFldList(String ds_view_id);

	public List<ReportListMasterVO> selectGrpReportList(String userId);

	public List<ReportListMasterVO> selectUserReportList(String userId);

	public void insertSchData(ParamScheduleVO schParam);

	public String generateCubeQuery(User sessionUser, int dataSourceId, String dataSourceType, JSONObject params,
			JSONArray dimensions, JSONArray measures, JSONArray filters, JSONArray subquery);
	
	public TossExeVO getTossBatch(Map param);
	
	public List<Object> getCubeRelationInfo(User sessionUser, int dataSourceId);
	
	public JSONObject querySql2(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout, boolean drillThru, String onlyQuery) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
	
	public JSONObject queryCubeSql2(User sessionUser, int dataSourceId,
			String dataSourceType, JSONObject params, JSONArray dimensions,
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			JSONArray measures, JSONArray filters, JSONArray subquery, int sqlTimeout, boolean drillThru, String reportType, String onlyQuery) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
	
	public String selectSCHForSkip(String schId, String dataSourceIdStr);

	public JSONObject queryDatasetCubeSql(User sessionUser, int dataSourceId, String dataSourceType, JSONObject params,
			String query, JSONArray filters, String subquery, JSONObject subtarget) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;

	public List<List<DataField>> querySqlForExcel(int dataSourceId, String dataSourceType, String sql, JSONObject params) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;

	public List<List<DataField>> querySqlByIdForExcel(int dataSourceId, String dataSourceType, String sqlId, JSONObject params) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
	
	/* DOGFOOT ktkang 사용자 데이터 업로드 권한 추가  20200716 */
	public List<SubjectMasterVO> selectSubjectList(boolean isUploadEnable, String userId);

	public SubjectMasterVO selectSubjectList(int dsid, String ds_type);

	public List<SubjectMasterVO> selectUserAuthDsList(String userNo);

	public List<SubjectMasterVO> selectGrpAuthDsList(String userNo);
	
	public  Map<String,List<List<DataField>>> queryData(String pidParam, JSONArray dataSources, JSONObject params) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;

	public void saveDataSet(org.json.JSONObject obj);
	
	public  Map<String,List<List<DataField>>> queryData(JSONArray dataSources, JSONObject params) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException;

	public DataSetInfoVO openDataSet(String dataSetID, String dataSrcID, String dataSetType);

	public List<SubjectMasterVO> selectUserAuthDsList(String dataSrcID, String userNo);

	public List<SubjectMasterVO> selectGrpAuthDsList(String dataSrcID, String userNo);

	public void deleteDataSet(String datasetId);

	public List<ReportListMasterVO> selectAllreportList();

	public List<FolderMasterVO> selectAllReportFolderList();

	public List<FolderMasterVO> selectAllMyReportFolderList(String userNo);

	public List<SubjectMasterVO> selectUserAuthDsViewList(String userNo);

	public List<SubjectMasterVO> selectGrpAuthDsViewList(String userNo);

	public List<CubeTable> selectDsViewTableList(int dataSourceId);

	public List<DSViewColVO> getDsViewColumnList(int dataSourceId, String tableName);

	public List<ReportListMasterVO> selectUserSpreadReportList(String user_id);

	public List<ReportListMasterVO> selectNotUserSpreadReportList(String user_id);

	public List<ReportListMasterVO> selectGrpSpreadReportList(String user_id);

	public List<ReportListMasterVO> selectSpreadReportList(String user_id);

	public List<ReportListMasterVO> selectNotSpreadReportList(String user_id);
	
	public JSONObject queryDrillThruSql(User sessionUser, int cubeId, String dataSourceType, int actId, JSONObject params) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;

	public List<SubjectCubeMasterVO> selectUserAuthCubeList(String userNo);

	public List<SubjectCubeMasterVO> selectGrpAuthCubeList(String userNo);
	
	public void cancelQuery() throws SQLException;

	public CubeMember selectCubeInfomationOne(int dataSourceId);
	
	public String getSql(ArrayList<SelectCube> aDtSel, ArrayList<Hierarchy> aDtSelHIe,
			ArrayList<SelectCubeMeasure> aDtSelMea, ArrayList<SelectCubeWhere> arrayList,
			ArrayList<SelectCubeOrder> arrayList2, String string, String string2);

	public CloseableList<JSONObject> querySqlLike(int dataSourceId, String dataSourceType, String sql_query, JSONObject params,
			int sqlTimeout, String queryParam, JSONObject sqlConfig, JSONObject nullDimension, String itemType)  throws Exception ;
	/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
	/* DOGFOOT ajkim 피벗그리드 null 처리 방법 수정 20201207 */
	public CloseableList<JSONObject> querySqlLike(int dataSourceId, String dataSourceType, String sql_query, JSONObject params,
			int sqlTimeout, String queryParam, JSONObject sqlConfig, JSONObject nullDimension, String itemType, boolean withQuery) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException, Exception;

	public CloseableList<JSONObject> sparkSqlLike(ArrayList<Integer> dsid, ArrayList<String> tblnm, String dataSourceType, String sql_query, JSONObject params,
			int sqlTimeout, String queryParam, JSONObject sqlConfig) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException, Exception;

	public CloseableList<JSONObject> sparkJson(JSONArray jsonData, String sql, JSONObject params, String queryParam, JSONObject sqlConfig) throws Exception;

	/* DOGFOOT ktkang 데이터 집합 기본값 USE_SQL 로 되어있을 때 오류 수정  20200701 */
	public CloseableList<JSONObject> queryTableSql(int datasrc_id, String datasrc_type, String sql, JSONObject params, int sqlTimeout,
			boolean join, String sqlType) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;

	public CloseableList<JSONObject> querySparkSql(ArrayList<Integer> dsid, ArrayList<String> tblnm, String datasrc_type, String sql, JSONObject params, int sqlTimeout,
			boolean join, String sqlType) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException;
	
	public SubjectMasterVO getDatasourceInfoById(int id);
	
	public CloseableList<JSONObject> getTableList(int dataSourceId, String dataSourceType, String requestType, String searchWord);
	
	public CloseableList<JSONObject> getColumnList(int dataSourceId, String dataSourceType, String requestType, String tableName);
	
	public CloseableList<JSONObject> getCubeTableColumnList(int cubeId);

	public List<TableRelationVO> selectCubeRelationList(CubeTableVO cubeTableVO);

	SubjectCubeMasterVO getCubeDatasourceInfoById(int id);
	
	/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
	public CloseableList<JSONObject> querySqlLikePaging(int dataSourceId, String dataSourceType, String sql_query, JSONObject params,
			int sqlTimeout, JSONObject sqlConfig, int pagingSize, int pagingStart) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException, Exception;

	public String selectGoyongUserSosok(String iscd);
	
	public CloseableList<JSONObject> executeSqlLike(final String sqlLikeOptionValue, boolean useWithQuery, HttpServletRequest request) throws Exception;
	
}
