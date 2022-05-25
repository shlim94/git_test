package com.wise.ds.repository.dao;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;
import org.springframework.stereotype.Repository;

import com.wise.common.jdbc.SqlSessionDaoSupport;
import com.wise.ds.repository.CubeHieMasterVO;
import com.wise.ds.repository.CubeListMasterVO;
import com.wise.ds.repository.CubeMember;
import com.wise.ds.repository.CubeTableColumnVO;
import com.wise.ds.repository.CubeTableConstraintVO;
import com.wise.ds.repository.CubeTableVO;
import com.wise.ds.repository.CubeVO;
import com.wise.ds.repository.DSViewColVO;
import com.wise.ds.repository.DataSetInfoMasterVO;
import com.wise.ds.repository.DataSetInfoVO;
import com.wise.ds.repository.DataSetMasterVO;
import com.wise.ds.repository.FolderMasterVO;
import com.wise.ds.repository.FolderParamVO;
import com.wise.ds.repository.ParamScheduleVO;
import com.wise.ds.repository.ReportBackup;
import com.wise.ds.repository.ReportListMasterVO;
import com.wise.ds.repository.ReportMasterVO;
import com.wise.ds.repository.ReportParamVO;
import com.wise.ds.repository.SkipQueryParam;
import com.wise.ds.repository.SubjectCubeMasterVO;
import com.wise.ds.repository.SubjectMasterVO;
import com.wise.ds.repository.SubjectViewMasterVO;
import com.wise.ds.repository.TossExeVO;
import com.wise.ds.repository.UserUploadMstrVO;
import com.wise.ds.sql.CubeTable;
import com.wise.ds.sql.CubeTableColumn;

import wise.querygen.dto.Relation;

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

@Repository("dataSetDAO")
public class DataSetDAO extends SqlSessionDaoSupport {

    public DataSetMasterVO selectDataSetMaster(int dataSetId) {
        DataSetMasterVO result = super.getSqlSession().selectOne("DataSet.selectDataSetMaster", dataSetId);
        return result;
    }
    
    public DataSetMasterVO selectDataSetViewMaster(int dataSetId) {
        DataSetMasterVO result = super.getSqlSession().selectOne("DataSet.selectDataSetViewMaster", dataSetId);
        return result;
    }
    
    public DataSetMasterVO selectCubeMaster(int dataSetId) {
        DataSetMasterVO result = super.getSqlSession().selectOne("DataSet.selectCubeMaster", dataSetId);
        return result;
    }
    
    public List<CubeVO> selectCubeList() {
    	List<CubeVO> result = super.getSqlSession().selectList("DataSet.selectCubeList");
		return result;
	}
    
    public int selectDsViewId(int dsId) {
		int result = super.getSqlSession().selectOne("DataSet.selectDsViewId", dsId);
		return result;
	}
    
//    public int selectCubeId(int dsViewId) {
//		// TODO Auto-generated method stub
//    	
////		int result = super.getSqlSession().selectOne("DataSet.selectCubeViewId", dsViewId);
////		return result;
//    	
//    	
//	}
    public List<CubeVO> selectCubeId(int dsViewId) {
		// TODO Auto-generated method stub
    	
    	List<CubeVO> result = super.getSqlSession().selectList("DataSet.selectCubeViewId", dsViewId);
		return result;
	}
    
    public CubeVO selectCubeCubeNm(String cubeNm) {
    	CubeVO result = super.getSqlSession().selectOne("DataSet.selectCubeCubeNm", cubeNm);
		return result;
	}
    
    /* DOGFOOT ktkang KERIS cube아이디 파라미터로 받아서 주제영역 바로 열도록 하는 부분  20200114 */
    public List<CubeVO> selectCubeMasterInformation(int cubeId) {
    	List<CubeVO> result = super.getSqlSession().selectList("DataSet.selectCubeMasterInformation", cubeId);
        return result;
    }
    
    public List<CubeTable> selectDsViewTableMatser(int cubeId) {
        List<CubeTable> result = super.getSqlSession().selectList("DataSet.selectDsViewTableMatser", cubeId);
        return result;
    }
    
    public List<CubeTableColumn> selectDsViewColumnInformationList(int dsViewId) {
        List<CubeTableColumn> result = super.getSqlSession().selectList("DataSet.selectDsViewColumnInformationList", dsViewId);
        return result;
    }
    
    public List<CubeTableVO> selectCubeReportDimensionTableList(int cubeId) {
        List<CubeTableVO> result = super.getSqlSession().selectList("DataSet.selectCubeReportDimensionTableList", cubeId);
        return result;
    }
    public List<CubeTableVO> selectCubeReportMeasureTableList(int cubeId) {
        List<CubeTableVO> result = super.getSqlSession().selectList("DataSet.selectCubeReportMeasureTableList", cubeId);
        return result;
    }
    
    public List<CubeTableColumnVO> selectCubeReportDimensionTableColumnList(CubeTableVO cubeTable) {
        List<CubeTableColumnVO> result = super.getSqlSession().selectList("DataSet.selectCubeReportDimensionTableColumnList", cubeTable);
        return result;
    }
    public List<CubeTableColumnVO> selectCubeReportMeasureTableColumnList(CubeTableVO cubeTable) {
        List<CubeTableColumnVO> result = super.getSqlSession().selectList("DataSet.selectCubeReportMeasureTableColumnList", cubeTable);
        return result;
    }
    
    public List<CubeTableColumn> selectCubeColumnLevelInfomations(CubeTableVO cubeTable) {
        List<CubeTableColumn> result = super.getSqlSession().selectList("DataSet.selectCubeColumnLevelInfomations", cubeTable);
        return result;
    }
    
    public List<CubeTableConstraintVO> selectCubeReportTableConstraints(CubeTableVO cubeTable) {
        List<CubeTableConstraintVO> result = super.getSqlSession().selectList("DataSet.selectCubeReportTableConstraints", cubeTable);
        return result;
    }
    public List<CubeTableConstraintVO> selectViewReportTableConstraints(CubeTableVO cubeTable) {
        List<CubeTableConstraintVO> result = super.getSqlSession().selectList("DataSet.selectViewReportTableConstraints", cubeTable);
        return result;
    }
    public List<Object> selectCubeReportTableConstraints2(CubeTableVO cubeTable) {
        List<Object> result = super.getSqlSession().selectList("DataSet.selectCubeReportTableConstraints2", cubeTable);
        return result;
    }
    public List<Object> selectViewReportTableConstraints2(CubeTableVO cubeTable) {
        List<Object> result = super.getSqlSession().selectList("DataSet.selectViewReportTableConstraints2", cubeTable);
        return result;
    }
    
    /* DOGFOOT ktkang 주제영역 권한 추가  20200120 */
    public List<SubjectViewMasterVO> selectSubjectUserViewList(String userId) {
    	List<SubjectViewMasterVO> result = super.getSqlSession().selectList("DataSet.selectSubjectUserViewList",userId);
        return result;
    }
    
    /* DOGFOOT ktkang 주제영역 권한 추가  20200120 */
    public List<SubjectViewMasterVO> selectSubjectGrpViewList(String userId) {
    	List<SubjectViewMasterVO> result = super.getSqlSession().selectList("DataSet.selectSubjectGrpViewList",userId);
        return result;
    }
    
    public List<SubjectMasterVO> selectSubjectList() {
    	List<SubjectMasterVO> result = super.getSqlSession().selectList("DataSet.selectSubjectList");
        return result;
    }
    
    public DataSetInfoMasterVO selectDataSetInfo(int dataSetId) {
		DataSetInfoMasterVO result = super.getSqlSession().selectOne("DataSet.selectDataSetInfo", dataSetId);
        return result;
	}
    
    public List<DataSetInfoMasterVO> selectDataSetInfoList() {
		List<DataSetInfoMasterVO> result = super.getSqlSession().selectList("DataSet.selectDataSetInfoList");
        return result;
	}
    
    public List<DataSetInfoMasterVO> selectDataSetInfoList(List<String> dsTypeList) {
    	HashMap<String, Object> dsType = new HashMap<String, Object>();
    	dsType.put("dsType", dsTypeList);
		List<DataSetInfoMasterVO> result = super.getSqlSession().selectList("DataSet.selectDataSetInfoListDsType", dsType);
        return result;
	}

	public List<FolderMasterVO> selectGrpAuthDataSetFolderList(String userId) {
		List<FolderMasterVO> result = super.getSqlSession().selectList("DataSet.selectGrpAuthDataSetFolderList", userId);
        return result;
	}
	
	public List<FolderMasterVO> selectUserAuthDataSetFolderList(String userId) {
		List<FolderMasterVO> result = super.getSqlSession().selectList("DataSet.selectUserAuthDataSetFolderList", userId);
        return result;
	}

	public FolderMasterVO selectPUBReportList(Map<String, Comparable> param) {
		// TODO Auto-generated method stub
		FolderMasterVO pubFld = super.getSqlSession().selectOne("DataSet.selectReportFLDInfo",param);
		return pubFld;
	}
	
	public FolderMasterVO selectPUBReportList(FolderParamVO param) {
		// TODO Auto-generated method stub
		FolderMasterVO pubFld = super.getSqlSession().selectOne("DataSet.selectReportFLDInfo",param);
		if(pubFld == null) {
			List tt = param.getP_result();
			pubFld = (FolderMasterVO)tt.get(0);
//			System.out.println("I think it's oracle.\n");
//			System.out.println(pubFld.toString());
		}
		return pubFld;
	}
	
	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public FolderMasterVO selectUSERReportList(FolderParamVO param) {
		// TODO Auto-generated method stub
		FolderMasterVO userFld = super.getSqlSession().selectOne("DataSet.selectReportUserFLDInfo",param);
		return userFld;
	}
	
	public List<FolderMasterVO> selectPrivateUserReportFolderList(String userId) {
		// TODO Auto-generated method stub
		List<FolderMasterVO> result = super.getSqlSession().selectList("DataSet.selectPrivateUserReportFolderList",userId);
		return result;
	}

	public List<FolderMasterVO> selectGrpReportFolderList(String userId) {
		// TODO Auto-generated method stub
		List<FolderMasterVO> result = super.getSqlSession().selectList("DataSet.selectGrpReportFolderList", userId);
		return result;
	}

	public List<FolderMasterVO> selectUserReportFolderList(String userId) {
		// TODO Auto-generated method stub
		List<FolderMasterVO> result = super.getSqlSession().selectList("DataSet.selectUserReportFolderList",userId);
		return result;
	}
	
	/* DOGFOOT ktkang 보고서 정렬 순서 다른 오류 수정  20200707 */
	public List<ReportListMasterVO> selectReportList(String userId, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", userId);
		param.put("reportOrdinal", reportOrdinal);
		
		List<ReportListMasterVO> result = super.getSqlSession().selectList("DataSet.selectReportList", param);
		return result;
	}
	/* DOGFOOT ktkang 보고서 및 폴더 권한 체크 추가  20200717 */
	public List<ReportListMasterVO> selectUserAuthReportList(String userId, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", userId);
		param.put("reportOrdinal", reportOrdinal);
		
		List<ReportListMasterVO> result = super.getSqlSession().selectList("DataSet.selectUserAuthReportList", param);
		return result;
	}
	
	public List<ReportListMasterVO> selectGrpAuthReportList(String userId, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", userId);
		param.put("reportOrdinal", reportOrdinal);
		
		List<ReportListMasterVO> result = super.getSqlSession().selectList("DataSet.selectGrpAuthReportList", param);
		return result;
	}
	
	public List<ReportListMasterVO> selectGrpAuthReportDetailList(String userId, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", userId);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectGrpAuthReportDetailList", param);
	}
	
	public List<ReportListMasterVO> selectNotSpreadGrpAuthReportDetailList(String userId, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", userId);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectNotSpreadGrpAuthReportDetailList", param);
	}
	
	/* DOGFOOT ktkang 보고서별 권한 USER 부분 추가  20200721  */
	public List<ReportListMasterVO> selectUserAuthReportDetailList(String userId, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", userId);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectUserAuthReportDetailList", param);
	}
	
	public List<ReportListMasterVO> selectNotSpreadUserAuthReportDetailList(String userId, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", userId);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectNotSpreadUserAuthReportDetailList", param);
	}
	
	public ReportListMasterVO selectPubFldMstrInfo(int fldId) {
		return super.getSqlSession().selectOne("DataSet.selectPubFldMstrInfo",fldId);
	}
	
	/* DOGFOOT ktkang KERIS 주제영역 폴더 형식으로 표현  20200120 */
	public List<CubeListMasterVO> selectCubeFldList(String ds_view_id) {
		return super.getSqlSession().selectList("DataSet.selectCubeFldList", ds_view_id);
	}

	public List<ReportListMasterVO> selectGrpReportList(String userId) {
		return super.getSqlSession().selectList("DataSet.selectGrpReportList", userId);	
	}

	/* DOGFOOT ktkang 보고서 정렬 순서 다른 오류 수정  20200707 */
	public List<ReportListMasterVO> selectUserReportList(String userId, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", userId);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectUserReportList",param);
	}

	public void insertSchData(ParamScheduleVO schParam) {
		super.getSqlSession().update("Report.insertReportSchData", schParam);
	}

	public TossExeVO getTossBatch(Map param) {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectOne("DataSet.getTossBatch",param);
	}
    
	public String selectSCHForSkip(String schId, String dataSourceIdStr) {
		// TODO Auto-generated method stub
		SkipQueryParam param = new SkipQueryParam();
		param.setSchId(schId);
		param.setDataSourceIdStr(dataSourceIdStr);
		String result = super.getSqlSession().selectOne("Report.selectSCHData", param);
		
		return result;
	}

	/* DOGFOOT ktkang 사용자 데이터 업로드 권한 추가  20200716 */
	public List<SubjectMasterVO> selectSubjectList(boolean isUploadEnable, String userId) {
		// TODO Auto-generated method stub
		
		List<SubjectMasterVO> result = super.getSqlSession().selectList("DataSet.selectUserAreaSubjectList", userId);
        return result;
	}

	public List<UserUploadMstrVO> selectUploadTableList(int ds_id) {
		// TODO Auto-generated method stub
		List<UserUploadMstrVO> result = super.getSqlSession().selectList("DataSet.selectUploadTableList",ds_id);
		return result;
	}

	public SubjectMasterVO selectSubjectList(int dsid, String ds_type) {
		// TODO Auto-generated method stub
		SubjectMasterVO result = new SubjectMasterVO();
		if(ds_type.equalsIgnoreCase("DS"))
			result = super.getSqlSession().selectOne("DataSet.selectSubjectListForOpen",dsid);
		else if(ds_type.equalsIgnoreCase("DS_VIEW"))
			result = super.getSqlSession().selectOne("DataSet.selectSubjectListViewForOpen",dsid);
		return result;
	}

	public List<SubjectMasterVO> selectUserAuthDsList(String userNo) {
		// TODO Auto-generated method stub
		List<SubjectMasterVO> result = super.getSqlSession().selectList("DataSet.selectUserAuthDsList",userNo);
		return result;
	}

	public List<SubjectMasterVO> selectGrpAuthDsList(String userNo) {
		// TODO Auto-generated method stub
		List<SubjectMasterVO> result = super.getSqlSession().selectList("DataSet.selectGrpAuthDsList",userNo);
		return result;
	}

	public void saveDataset(DataSetInfoVO param) {
		// TODO Auto-generated method stub
		
		DataSetInfoVO ret = new DataSetInfoVO();
		ret = super.getSqlSession().selectOne("DataSet.UP_DATASET_MSTR_ACT", param);
		if(ret == null) {
			List tt = param.getP_result();
//			System.out.println(tt.get(0));
			ret = (DataSetInfoVO)tt.get(0);
//			System.out.println("I think it's oracle.\n");
//			System.out.println(result.toString());
		}
//		return ret;
	}

	public DataSetInfoVO openDataSet(DataSetInfoVO param) {
		// TODO Auto-generated method stub
		DataSetInfoVO ret = new DataSetInfoVO();
		
		ret = super.getSqlSession().selectOne("DataSet.openDataSet", param);
		return ret;
	}

	public List<SubjectMasterVO> selectUserAuthDsList(String dataSrcID, String userNo) {
		// TODO Auto-generated method stub
		Map<String, Comparable> param = new HashMap<String, Comparable>();
		param.put("USER_NO", userNo);
		param.put("DS_ID", dataSrcID);
		List<SubjectMasterVO> result = super.getSqlSession().selectList("DataSet.selectUserAuthDsListByDsId",param);
		return result;
	}

	public List<SubjectMasterVO> selectGrpAuthDsList(String dataSrcID, String userNo) {
		// TODO Auto-generated method stub
		Map<String, Comparable> param = new HashMap<String, Comparable>();
		param.put("USER_NO", userNo);
		param.put("DS_ID", dataSrcID);
		List<SubjectMasterVO> result = super.getSqlSession().selectList("DataSet.selectGrpAuthDsListByDsId",param);
		return result;
	}

	public void deleteDataSet(String datasetId) {
		// TODO Auto-generated method stub
		super.getSqlSession().delete("DataSet.deleteDataSet", datasetId);
	}

	public List<ReportListMasterVO> selectAllreportList() {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectList("DataSet.selectAllReportList");	
	}

	public List<FolderMasterVO> selectAllReportFolderList() {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectList("DataSet.selectAllReportFolderList");
	}

	public List<FolderMasterVO> selectAllMyReportFolderList(String userNo) {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectList("DataSet.selectAllMyReportFolderList",userNo);
	}

	public List<SubjectMasterVO> selectUserAuthDsViewList(String userNo) {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectList("DataSet.selectUserAuthDsViewList",userNo);
	}

	public List<SubjectMasterVO> selectGrpAuthDsViewList(String userNo) {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectList("DataSet.selectGrpAuthDsViewList",userNo);
	}

	public List<CubeTable> selectDsViewTableList(int dataSourceId) {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectList("DataSet.selectDsViewTableList",dataSourceId);
	}

	public List<DSViewColVO> getDsViewColumnList(int dataSourceId, String tableName) {
		// TODO Auto-generated method stub
		Map<String, Comparable> param = new HashMap<String, Comparable>();
		param.put("ds_view_id", dataSourceId);
		param.put("tbl_nm", tableName);
		return super.getSqlSession().selectList("DataSet.selectDsViewColumnList",param);
	}
	
	/* DOGFOOT ktkang 보고서 정렬 순서 다른 오류 수정 시작  20200707 */
	public List<ReportListMasterVO> selectUserSpreadReportList(String user_id, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", user_id);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectUserSpreadReportList", param);
	}

	public List<ReportListMasterVO> selectNotUserSpreadReportList(String user_id, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", user_id);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectNotUserSpreadReportList", param);
	}
	
	public List<ReportListMasterVO> selectGrpSpreadReportList(String user_id, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", user_id);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectGrpSpreadReportList", param);	
	}

	public List<ReportListMasterVO> selectSpreadReportList(String user_id, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", user_id);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectSpreadReportList", param);
	}

	public List<ReportListMasterVO> selectNotSpreadReportList(String user_id, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", user_id);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectNotSpreadReportList", param);
	}
	/* DOGFOOT ktkang 보고서 및 폴더 권한 체크 추가  20200717 */
	public List<ReportListMasterVO> selectNotSpreadGrpReportList(String user_id, String reportOrdinal) {
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("userId", user_id);
		param.put("reportOrdinal", reportOrdinal);
		
		return super.getSqlSession().selectList("DataSet.selectNotSpreadGrpReportList", param);
	}
	/* DOGFOOT ktkang 보고서 정렬 순서 다른 오류 수정 끝  20200707 */

	public List<SubjectCubeMasterVO> selectUserAuthCubeList(String userNo) {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectList("DataSet.selectUserAuthCubeList",userNo);
	}

	public List<SubjectCubeMasterVO> selectGrpAuthCubeList(String userNo) {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectList("DataSet.selectGrpAuthCubeList",userNo);
	}
	
	/* DOGFOOT ktkang KERIS 보고서 백업 기능  20200205 */
	public List<ReportBackup> sidoToChong() {
		return super.getSqlSession().selectList("DataSet.sidoToChong");
	}
	
	public List<ReportBackup> chong() {
		return super.getSqlSession().selectList("DataSet.chong");
	}
//    public int insert(FavoriteVO fav) {
//        int count = super.getSqlSession().insert("Favorite.insert", fav);
//        return count;
//    }
//
//    public int delete(FavoriteVO fav) {
//        int count = super.getSqlSession().delete("Favorite.delete", fav);
//        return count;
//    }

	/* DOGFOOT ktkang 주제영역 연결되어있는 차원 필터로 올릴 때 오류 수정  20200207 */
	public CubeHieMasterVO selectHieHieUniNm(int cubeId, String uniNm) {
		Map<String, Comparable> param = new HashMap<String, Comparable>();
		param.put("cube_id", cubeId);
		param.put("uni_nm", uniNm);
		CubeHieMasterVO result = super.getSqlSession().selectOne("DataSet.selectHieHieUniNm", param);
	    
		return result;
	}

	/* DOGFOOT ktkang 주제영역 연계되어있는 차원 및 측정값만 보이는 기능   20200212 */
	public List<Relation> selectCubeRelationList(Relation cubeRel) {
		return super.getSqlSession().selectList("DataSet.selectCubeRelationList", cubeRel);
	}
	/*dogfoot shlim  본사적용 필요 뷰 relation 테스트 작업중 20210701*/
	public List<Relation> selectDsViewCubeRelationList(Relation cubeRel) {
		return super.getSqlSession().selectList("DataSet.selectDsViewCubeRelationList", cubeRel);
	}

	public SubjectMasterVO getDatasourceInfoById(int id) {
		Map<String, Comparable> param = new HashMap<String, Comparable>();
		param.put("id", id);
		return super.getSqlSession().selectOne("DataSet.getDatasourceInfoById", param);
	}
	
	public SubjectCubeMasterVO getCubeDatasourceInfoById(int id) {
		Map<String, Comparable> param = new HashMap<String, Comparable>();
		param.put("id", id);
		return super.getSqlSession().selectOne("DataSet.getCubeDatasourceInfoById", param);
	}
}
