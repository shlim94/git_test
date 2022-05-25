package com.wise.ds.repository.service;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;

import com.wise.ds.repository.CubeHieMasterVO;
import com.wise.ds.repository.CubeMember;
import com.wise.ds.repository.CubeTableVO;
import com.wise.ds.repository.DSViewColVO;
import com.wise.ds.repository.DrillThruColumnVO;
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
import com.wise.ds.sql.CubeTableColumn;

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

public interface ReportService {
    
	public ReportMasterVO selectReportBasicInformation(int reportId, String reportType);
	
	public ReportMasterVO selectReportBasicInformation(int intValue, String reportType, String fldType);
	
	public ReportMasterVO selectReportBasicInformationExceptLayout(int reportId, String reportType);
	
	/* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
	public ReportMasterVO selectReportBasicInformationHis(int intValue, String reportType, String fldType, String reportSeq);
	
	public ReportMasterVO selectReportBasicInformationExceptLayoutHis(int reportId, String reportType, String reportSeq);
	
	public ReportMasterVO selectReportForLog(int reportId, String wiseReportType);

	public void enrollReportUseLog(boolean useLog,ReportLogMasterVO logVO);
	
	public void enrollReportQueryLog(boolean logUse, ReportLogMasterVO logVo);
	
	public void enrollReportExportLog(boolean logUse, ReportLogMasterVO logVo);

	public void enrollReportPrintLog(boolean logUse, ReportLogMasterVO logVO);
	
	public List<ReportSubLinkVO> selectReportLink(int reportId);
	
	public List<ReportSubLinkVO> selectReportSubLink(int reportId);
	
	public void insertLinkReport(ReportSubLinkVO reportSubLinkVo);
	
	public void insertSubLinkReport(ReportSubLinkVO reportSubLinkVo);

	public JSONObject callUpReportMstrACT(JSONObject obj, String string) throws UnsupportedEncodingException, JSONException;
	
	public JSONObject callUpSpreadReportMstrACT(JSONObject obj,String remoteAddr) throws UnsupportedEncodingException, JSONException;
	
	public List<ReportScheduleVO> selectReportScheduleList(ReportScheduleVO param);

	public List<ReportScheduleVO> selectReportScheduleAllList();
	
	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
	public List<ReportScheduleVO> selectReportScheduleAllList2();
	
	public void insertReportSchedule(ReportScheduleVO param);
	
	public void deleteReportSchedule(ReportScheduleVO param);

	public void deleteReportScheduleAll(ReportScheduleVO param);

	public void deleteReportScheduleAndData(ReportScheduleVO param);

	public String checkReport(String reportNm, String fld_id);

	public int insertReport(ReportMasterVO reportMaster);

	public JSONObject callUpAdhocReportMstrACT(JSONObject obj, String remoteAddr) throws UnsupportedEncodingException, JSONException;

	public void insertReportDetail(boolean logUse, ReportLogDetailMasterVO logdetail);

	public void updateReportLogDetail(boolean logUse, ReportLogMasterVO vo);

	public int updateReportLogDetailError(int interval);
	
	public int getReportLogCleanHour();

	public void updateReportUseLog(boolean logUse, ReportLogMasterVO vo);

	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public ReportMasterVO selectReportType(String pid);

	public void insertUserUpload(UserUploadMstrVO uploadVo);

	public UploadHisVO selectHisUpload(UploadHisVO getseq);

	public void insertUserUploadHis(UploadHisVO hisVo);

	public List<UserUploadMstrVO> selectUserUpload(int dataSourceId);

	public ReportMasterVO selectReportParam(int reportId);
	
	public List<DrillThruColumnVO> selectDrillThruCategoryList(int cubeId);

	/* DOGFOOT ktkang KERIS 보고서 별 필드 정보 추가기능  20200123 */
	public List<ReportFieldMasterVO> selectReportFieldList(int reportId);

	public void deleteReportFieldList(int reportId);

	/* DOGFOOT ktkang KERIS 보고서 별 필드 정보 추가기능  수정 끝 20200123 */
	public void insertReportField(ReportFieldMasterVO reportField);
	
	/* DOGFOOT ktkang KERIS EDS포탈에서 보여주는 보고서 체크 기능  20200205 */
	public List<ReportParamVO> selectPotalReportList();
	
	/* DOGFOOT ktkang 주제영역 필터 기본값 추가 기능  20200207 */
	public List<CubeTableColumn> selectCubeColumnInfomationList(CubeTableVO cubeTable);
	
	/* DOGFOOT yhkim 시계열분석 가공 데이터 */
	public List<LinkedHashMap<String, Object>> getTimeSeriesForecast(List<LinkedHashMap<String, Object>> list, 
			List<LinkedHashMap<String, Object>> measureInfoList, 
			List<LinkedHashMap<String, Object>> seriesDimensionInfoList, 
			Map<String, Object> params, 
			int dataType);
	/* DOGFOOT syjin 시계열분석 R 가공 데이터 */
	public List<LinkedHashMap<String, Object>> getTimeSeriesRForecast(List<LinkedHashMap<String, Object>> list, 
			List<LinkedHashMap<String, Object>> measureInfoList, 
			List<LinkedHashMap<String, Object>> seriesDimensionInfoList, 
			Map<String, Object> params, 
			int dataType);
	public int executeReportScheduleMaster();
	
	/* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
	public void callUpReportMstrHisACT(JSONObject obj, String string, int seq, String reportId) throws UnsupportedEncodingException, JSONException;
	
	public void callUpReportMstrACT2(JSONObject obj, ReportMasterHisVO reportMstrHis);
	
	public List<ReportMasterHisVO> selectReportMstrHisList(JSONObject obj);
	
	public List<ReportMasterHisVO> selectReportHisList(int reportId);
	
	public ReportMasterHisVO selectReportHis(int reportId, int reportSeq);
	
	public int updateReportMstrHis(String reportId, String reportSeq);
	
	/* DOGFOOT ktkang 동시 작업 제한 기능 구현  20200922 */
	public int selectReportWorks();
	
	// 2021-07-12 yyb export가 아닌 권한 전체로 처리
	public UserGrpAuthReportListVO userAuthByReport(int userNo, String reportId);
	
	public UserGrpAuthReportListVO grpAuthByReport(int grpId, String reportId);
	
	public UserGrpAuthReportListVO userAuthByFolder(int userNo, String fldId);
	
	public UserGrpAuthReportListVO grpAuthByFolder(int grpId, String fldId);
	
	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
	public String selectSchedulePath(int reportId);
	
	/* DOGFOOT ktkang BMT 그룹핑 기능 구현  20201203 */
	public List<DSViewColVO> selectCubeGroupingData(int cubeId);
	
	public List<CubeHieMasterVO> selectCubeGroupingTblList(int cubeId);
	
	public int deleteDsViewColMstr(int dsViewId);
	
	public int deleteDsViewHieMstr(int dsViewId);
	
	public int deleteCubeHieMstr(int cubeId);
	
	public int insertDsViewColMstr(JSONObject groupingDataList, int colNum, int colId, int dsViewId);
	
	public int insertDsViewHieMstr(JSONObject groupingDataList, int colNum, int dsViewId);
	
	public int insertCubeHieMstr(JSONObject groupingDataList, int colNum, int cubeId);
	
	public int selectMaxColId();
	
	public CubeMember selectCubeMasterInformation(int cubeId);
	
	public List<CubeHieMasterVO> selectCubeGroupingDimList(String cubeId, String selectTableName);
	
	public ReportMasterVO selectReportParamXmlList(int reportId);
	
	public void updateReportDatasetParam(ReportMasterVO updateReportXmlVal);
}
