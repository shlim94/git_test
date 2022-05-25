package com.wise.ds.repository.dao;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Repository;

import com.wise.authn.User;
import com.wise.authn.WebConfigMasterVO;
import com.wise.common.jdbc.SqlSessionDaoSupport;
import com.wise.authn.ConfigMasterVO;
import com.wise.ds.repository.CubeHieMasterVO;
import com.wise.ds.repository.CubeMember;
import com.wise.ds.repository.CubeTableVO;
import com.wise.ds.repository.DSViewColVO;
import com.wise.ds.repository.DSViewHieVO;
import com.wise.ds.repository.DrillThruColumnVO;
import com.wise.ds.repository.ReportFieldMasterVO;
import com.wise.ds.repository.ReportLogDetailMasterVO;
import com.wise.ds.repository.ReportLogMasterVO;
import com.wise.ds.repository.ReportMasterHisVO;
import com.wise.ds.repository.ReportMasterVO;
import com.wise.ds.repository.ReportParamVO;
import com.wise.ds.repository.ReportScheduleVO;
import com.wise.ds.repository.ReportSubLinkVO;
import com.wise.ds.repository.TableRelationVO;
import com.wise.ds.repository.UploadHisVO;
import com.wise.ds.repository.UserGrpAuthReportListVO;
import com.wise.authn.UserGroupVO;
import com.wise.ds.repository.UserUploadMstrVO;
import com.wise.ds.sql.CubeTableColumn;

import net.sf.json.JSONArray;

/**
 * @author WISE iTech R&D DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 *      <pre>
 * << 개정이력(Modification Information) >>
 *     수정일                 수정자             수정내용   
 *  ----------    --------    ---------------------------
 *  2015.06.08      DOGFOOT             최초 생성
 *      </pre>
 */

@Repository("reportDAO")
public class ReportDAO extends SqlSessionDaoSupport {
	private int ordinalLoop = 1;
//	public ReportMasterVO select(ReportMasterVO param) {
//		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportBasicInformation", param);
//		return result;
//	}
	
	public ReportMasterVO select(Map<String, Comparable> param) {
		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportBasicInformation", param);
//		System.out.println(result.toString());
		return result;
	}
	
	public ReportMasterVO select(ReportMasterVO param) {
		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportBasicInformation", param);
//		System.out.println(result.toString());
		return result;
	}
	
	public ReportMasterVO select(ReportParamVO param) {
		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportBasicInformation", param);
//		System.out.println(result.toString());
		if(result == null) {
			List tt = param.getP_result();
//			System.out.println(tt.get(0));
			if(tt.size() > 0)
				result = (ReportMasterVO)tt.get(0);
//			System.out.println("I think it's oracle.\n");
//			System.out.println(result.toString());
		}
		return result;
	}
	/* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
	public ReportMasterVO selectHis(ReportMasterHisVO param) {
		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportBasicInformationHis", param);
		return result;
	}
	
	public List<CubeTableColumn> selectDsViewColumnInformationList(int dsViewId) {
        List<CubeTableColumn> result = super.getSqlSession().selectList("Report.selectDsViewColumnInformationList", dsViewId);
        return result;
    }
	
	public CubeMember selectCubeMasterInformation(int cubeId) {
        CubeMember result = super.getSqlSession().selectOne("Report.selectCubeMasterInformation", cubeId);
        return result;
    }
	
	public List<CubeTableColumn> selectCubeColumnInfomationList(CubeTableVO cubeTable) {
        List<CubeTableColumn> result = super.getSqlSession().selectList("Report.selectCubeColumnInfomationList", cubeTable);
        return result;
    }
	/* DOGFOOT ktkang KERIS 주제영역 속도 개선 루틴 추가  20200306 */
	public List<CubeTableColumn> selectCubeColumnInfomationList2(Map<String, Object> colInfoParam) {
        List<CubeTableColumn> result = super.getSqlSession().selectList("Report.selectCubeColumnInfomationList2", colInfoParam);
        return result;
    }
	
	public List<Object> selectCubeReportTableConstraints2(CubeTableVO cubeTable) {
        List<Object> result = super.getSqlSession().selectList("Report.selectCubeReportTableConstraints2", cubeTable);
        return result;
    }
	
    public List<Object> selectViewReportTableConstraints2(CubeTableVO cubeTable) {
        List<Object> result = super.getSqlSession().selectList("Report.selectViewReportTableConstraints2", cubeTable);
        return result;
    }
    /* DOGFOOT ktkang KERIS 주제영역 속도 개선 루틴 추가  20200306 */
    public List<Object> selectViewReportTableConstraints3(Map<String, Object> viewRelParam) {
        List<Object> result = super.getSqlSession().selectList("Report.selectViewReportTableConstraints3", viewRelParam);
        return result;
    }
	
	public ReportMasterVO selectExceptLayout(ReportMasterVO param) {
		// TODO Auto-generated method stub
		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportBasicInformationExceptLayout", param);
		return result;
	}
	/* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
	public ReportMasterVO selectExceptLayoutHis(ReportMasterHisVO param) {
		// TODO Auto-generated method stub
		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportBasicInformationExceptLayoutHis", param);
		return result;
	}
	
	public ReportMasterVO selectReportParam(ReportMasterVO param) {
		// TODO Auto-generated method stub
		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportParam", param);
		return result;
	}

	public ReportMasterVO selectReportForLog(ReportMasterVO param) {
		// TODO Auto-generated method stub
		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportForLog", param);
		return result;
	}

	public int insertReportUseLog(ReportLogMasterVO logVO) {
		// TODO Auto-generated method stub
		int result = super.getSqlSession().insert("Report.InsertReportUse",logVO);
		return result;
	}
	
	public int insertReportQueryLog(ReportLogMasterVO logVo) {
		int result = super.getSqlSession().insert("Report.InsertReportQuery",logVo);
		return result;
	}

	public int insertReportExportLog(ReportLogMasterVO logVo) {
		// TODO Auto-generated method stub
		int result = super.getSqlSession().insert("Report.InsertReportExport",logVo);
		return result;
	}

	public int insertReportPrintLog(ReportLogMasterVO logVo) {
		// TODO Auto-generated method stub
		int result = super.getSqlSession().insert("Report.InsertReportPrint",logVo);
		return result;
	}

	public List<ReportSubLinkVO>  selectReportSubLink(int reportId) {
		// TODO Auto-generated method stub
		List<ReportSubLinkVO> result = super.getSqlSession().selectList("Report.selectSubLinkReport",reportId);
		return result;
	}
	
	public List<ReportSubLinkVO>  selectReportLink(int reportId) {
		List<ReportSubLinkVO> result = super.getSqlSession().selectList("Report.selectLinkReport",reportId);
		return result;
	}
	
	public int insertLinkReport(ReportSubLinkVO reportSubLinkVo) {
		// TODO Auto-generated method stub
		int result = super.getSqlSession().insert("Report.insertLinkReport",reportSubLinkVo);
		return result;
	}
	
	public int insertSubLinkReport(ReportSubLinkVO reportSubLinkVo) {
		// TODO Auto-generated method stub
		int result = super.getSqlSession().insert("Report.insertSubLinkReport",reportSubLinkVo);
		return result;
	}

	public int insertReport(ReportMasterVO reportMaster) {
		// TODO Auto-generated method stub
		User user = super.getSqlSession().selectOne("Authn.selectRepositoryUserByUserId", reportMaster.getREG_USER_ID());

//		System.out.println(reportMaster.toString());
		int result = super.getSqlSession().update("Report.updateReport",reportMaster);
//		System.out.println("UpdateReport > "+result);
		if(result == 0) {
			result = super.getSqlSession().insert("Report.insertNewReport",reportMaster);
//			System.out.println("insertReport > "+reportMaster.getREPORT_ID());
			result = Integer.parseInt(reportMaster.getREPORT_ID());
		}else {
			
		}
		
		return result;
	}
	
	public ReportMasterVO callUpReportMstrACT(Map<String, Comparable> param) {
		// TODO Auto-generated method stub
		ReportMasterVO ret = new ReportMasterVO();
//		ReportMasterVO ret = null;
		
		//call Stored procedure using mybatis
//		try {
//			System.out.println("현재 접속한 DBMS 이름 : "+super.getSqlSession().getConfiguration().getEnvironment().getDataSource().getConnection().getMetaData().getDatabaseProductName());
//		} catch (SQLException e) {
//			e.printStackTrace();
//		}
		ret = super.getSqlSession().selectOne("Report.UP_REPORT_MSTR_ACT", param);
		
		
		//update-insert using mybatis
//		int result = super.getSqlSession().update("Report.updateReport",param);
//		System.out.println("UpdateReport > "+result+"\t report_id : "+param.get("REPORT_ID")+"\n report_ordinal"+param.get("REPORT_ORDINAL"));
//		if(result == 0) {
//			param.put("REPORT_ORDINAL", 
//					super.getSqlSession().selectOne("Report.getReportOrdinal",param.get("FLD_ID")).toString()
//					);
//			result = super.getSqlSession().insert("Report.insertNewReport",param);
//			System.out.println("insertReport > "+result+"\t report_id : "+param.get("REPORT_ID"));
//			ret = super.getSqlSession().selectOne("Report.InsertAfterReport",param.get("REPORT_I	D"));
////			result = insertReport.getReport_id();
//		}else {
//			ret = new ReportMasterVO();
//			ret.setId(Integer.parseInt(param.get("REPORT_ID").toString()));
//			ret.setREPORT_ORDINAL(Integer.parseInt(param.get("REPORT_ORDINAL").toString()));
//		}
		
		//direct-query(procedure)
//		try {
//			String DBMSName = super.getSqlSession().getConfiguration().getEnvironment().getDataSource().getConnection().getMetaData().getDatabaseProductName();
//			System.out.println("현재 접속한 DBMS 이름 : "+DBMSName);
//			if(DBMSName.contains("Microsoft")) {
//				Connection conn = super.getSqlSession().getConfiguration().getEnvironment().getDataSource().getConnection();
//				CallableStatement cstmt = conn.prepareCall(
//						"{call UP_REPORT_MSTR_ACT("
//						+ "?," //P_PARAM
//						+ "?," //REPORT_ID
//						+ "?," //REPORT_NM
//						+ "?," //FLD_ID
//						+ "?," //FLD_TYPE
//						+ "?," //REPORT_ORDINAL
//						+ "?," //REPORT_TYPE
//						+ "?," //REPORT_TAG
//						+ "?," //REPORT_DESC
//						+ "?," //REPORT_LAYOUT
//						+ "?," //GRID_INFO
//						+ "?," //DATASRC_ID
//						+ "?," //DATASRC_TYPE
//						+ "?," //DATASET_TYPE
//						+ "?," //REPORT_XML
//						+ "?," //CHART_XML
//						+ "?," //LAYOUT_XML
//						+ "?," //DATASET_XML
//						+ "?," //PARAM_XML
//						+ "?," //DATASET_QUERY
//						+ "?," //REG_USER_NO
//						+ "?," //DEL_YN
//						+ "?," //PROMPT_YN
//						+ "?," //REPORT_SUB_TITLE
//						+ "?," //MOD_USER_NO
//						+ "?," //PRIVACY_YN
//						+ "?" //out_RtnVal
//						+") }");
//				cstmt.setString(1, "0");
//				if(param.get("REPORT_ID").toString().equalsIgnoreCase("0"))
//					cstmt.setString(2, "");
//				else
//					cstmt.setString(2, param.get("REPORT_ID").toString());
//				cstmt.setString(3, param.get("REPORT_NM").toString());
//				cstmt.setString(4, param.get("FLD_ID").toString());
//				cstmt.setString(5, param.get("FLD_TYPE").toString());
//				cstmt.setString(6, param.get("REPORT_ORDINAL").toString());
//				cstmt.setString(7, param.get("REPORT_TYPE").toString());
//				cstmt.setString(8, param.get("REPORT_TAG").toString());
//				cstmt.setString(9, param.get("REPORT_DESC").toString());
//				cstmt.setString(10, "");
//				cstmt.setString(11, "");
//				cstmt.setString(12, "");
//				cstmt.setString(13, "");
//				cstmt.setString(14, "");
//				cstmt.setString(15, param.get("REPORT_XML").toString());
//				cstmt.setString(16, param.get("CHART_XML").toString());
//				cstmt.setString(17, param.get("LAYOUT_XML").toString());
//				cstmt.setString(18, param.get("DATASET_XML").toString());
//				cstmt.setString(19, param.get("PARAM_XML").toString());
//				cstmt.setString(20, "");
//				cstmt.setString(21, param.get("REG_USER_NO").toString());
//				cstmt.setString(22, param.get("DEL_YN").toString());
//				cstmt.setString(23, param.get("PROMPT_YN").toString());
//				cstmt.setString(24, param.get("REPORT_SUB_TITLE").toString());
//				cstmt.setString(25, param.get("MOD_USER_NO").toString());
//				cstmt.setString(26, param.get("PRIVACY_YN").toString());
//				cstmt.registerOutParameter(27, java.sql.Types.VARCHAR);
//				
////				cstmt.executeUpdate();
////				cstmt.executeQuery();
//				
//				ResultSet rs = cstmt.executeQuery();
//				ResultSetMetaData rsmd = rs.getMetaData();
//				while(rs.next()) {
//					for(int i=1;i<=rsmd.getColumnCount();i++) {
//						if(rsmd.getColumnLabel(i).equalsIgnoreCase("ACT_NM")) {
//							System.out.println(rsmd.getColumnLabel(i));
//							System.out.println(rs.getString(rsmd.getColumnLabel(i)));
//							ret.setId(rs.getInt("REPORT_ID"));
////							ret.setREPORT_ORDINAL(rs.getInt("REPORT_ORDINAL"));
//						}else if(rsmd.getColumnLabel(i).equalsIgnoreCase("ACTION_NM")) {
//							System.out.println(rsmd.getColumnLabel(i));
//							System.out.println(rs.getString(rsmd.getColumnLabel(i)));
//							ret.setId(rs.getInt("REPORT_ID"));
//							ret.setREPORT_ORDINAL(rs.getInt("REPORT_ORDINAL"));
//						}
//						
////						System.out.println(rs.getObject(i));
//					}
//				}
//				
////				System.out.println(rs.get);
////				ret.setId(rs.get);
////				ret.setREPORT_ORDINAL(cstmt.getInt(2));
////				rs.close();
//				cstmt.close();
//				conn.close();
//			}
//		} catch (SQLException e) {
//			e.printStackTrace();
//		}
		
		//direct-query(sql)
//		String DBMSName;
//		try {
////			DBMSName = super.getSqlSession().getConfiguration().getEnvironment().getDataSource().getConnection().getMetaData().getDatabaseProductName();
////			System.out.println("현재 접속한 DBMS 이름 : "+DBMSName);
////			if(DBMSName.contains("Microsoft")) {
////				Connection conn = super.getSqlSession().getConfiguration().getEnvironment().getDataSource().getConnection();
////				super.getSqlSession().getConnection();
//				SqlSession session = sqlSessionTemplate.getSqlSessionFactory().openSession();
//			    Connection conn = session.getConnection();
//			    
//				Statement stmt = conn.createStatement();
////				if(param.get("REPORT_ID").toString().equalsIgnoreCase("0"))
////					stmt.setString(2, "");
////				else
////					cstmt.setString(2, param.get("REPORT_ID").toString());
//				StringBuilder sb;
//				if(param.get("REPORT_ID").toString().equalsIgnoreCase("0") || param.get("REPORT_ID").toString().equalsIgnoreCase("")) {
//					sb = new StringBuilder();
////					sb.append("SELECT (ISNULL(MAX(REPORT_ORDINAL),0) + 1) AS REPORT_ORDINAL FROM REPORT_MSTR WHERE FLD_ID = "+param.get("FLD_ID")+" AND REPORT_ORDINAL <> 999");
//					
////					ResultSet ordinalrs = stmt.executeQuery(sb.toString());
//					int report_ordinal = 0;
////					while(ordinalrs.next()){
////						report_ordinal = ordinalrs.getInt("REPORT_ORDINAL");
////	                }
//					
//					sb = new StringBuilder();
//					sb.append("INSERT INTO REPORT_MSTR (");
//					sb.append("			REPORT_NM" + 
//							"			,FLD_ID" + 
//							"			,FLD_TYPE" + 
//							"			,REPORT_ORDINAL" + 
//							"			,REPORT_TYPE" + 
//							"			,REPORT_TAG" + 
//							"			,REPORT_DESC" + 
//							"			,REPORT_LAYOUT" + 
//							"			,DATASRC_ID" + 
//							"			,DATASRC_TYPE" + 
//							"			,DATASET_TYPE" + 
//							"			,REPORT_XML" + 
//							"			,CHART_XML" + 
//							"			,LAYOUT_XML" + 
//							"			,DATASET_XML" + 
//							"			,PARAM_XML" + 
//							"			,DATASET_QUERY" + 
//							"			,REG_USER_NO" + 
//							"			,REG_DT" + 
//							"			,DEL_YN" + 
//							"			,PROMPT_YN" + 
//							"			,REPORT_SUB_TITLE" + 
//							"			,MOD_USER_NO" + 
//							"			,MOD_DT" + 
//							"			,PRIVACY_YN"+
//							"			)" + 
//							" 		values ("+
//							"'" + param.get("REPORT_NM")+"' , "+
//							param.get("FLD_ID").toString()+" , "+
//							"'" + param.get("FLD_TYPE").toString()+"' , "+
//							report_ordinal+" , "+
//							"'" + param.get("REPORT_TYPE").toString()+"' , "+
//							"'" + param.get("REPORT_TAG").toString()+"' , "+
//							"'" +param.get("REPORT_DESC").toString()+"' , "+
//							"''"+" , "+ //REPORT_LAYOUT
//							"''"+" , "+ //DATASRC_ID
//							"''"+" , "+ //DATASRC_TYPE
//							"''"+" , "+ //DATASET_TYPE
//							"'" +param.get("REPORT_XML").toString()+"' , "+
//							"'" +param.get("CHART_XML").toString().replaceAll("\n", "")+"' , "+
//							"'" +param.get("LAYOUT_XML").toString().replaceAll("\n", "")+"' , "+
//							"'" +param.get("DATASET_XML").toString().replaceAll("\n", "")+"' , "+
//							"'" +param.get("PARAM_XML").toString().replaceAll("\n", "")+"' , "+
//							"''"+" , "+ //DATASET_QUERY
//							param.get("REG_USER_NO").toString()+" , "+
////							"GETDATE() , "+ //REG_DT
//							"CURRENT TIMESTAMP , "+ //REG_DT
//							"'" +param.get("DEL_YN").toString()+"' , "+
//							"'" +param.get("PROMPT_YN").toString()+"' , "+
//							"'" +param.get("REPORT_SUB_TITLE").toString()+"' , "+
//							param.get("MOD_USER_NO").toString()+" , "+
////							"GETDATE() , "+
//							"CURRENT TIMESTAMP , "+
//							"'" +param.get("PRIVACY_YN").toString()+"'"+
//							"		)"
//					);
//					System.out.println("insert query : \n"+sb.toString());
//					stmt.executeUpdate(sb.toString());
//					sb = new StringBuilder();
////					sb.append("SELECT '추가' AS ACTION_NM, ISNULL(MAX(REPORT_ID), '0') AS REPORT_ID FROM REPORT_MSTR WHERE REPORT_TYPE= 'DashAny'");
//					sb.append("SELECT '추가' AS ACTION_NM, NVL(MAX(REPORT_ID) AS REPORT_ID FROM REPORT_MSTR WHERE REPORT_TYPE= 'DashAny'");
//					
//					ResultSet rs = stmt.executeQuery(sb.toString());
//					int report_id =0;
//					while(rs.next()){
//						report_id = rs.getInt("REPORT_ID");
//	                }
//					sb = new StringBuilder();
//					sb.append("SELECT NVL(MAX(REPORT_ID) AS REPORT_ID FROM REPORT_MSTR WHERE REPORT_TYPE= 'DashAny'");
//					ret.setId(report_id);
//					ret.setREPORT_ORDINAL(report_ordinal);
//					System.out.println(report_id+"\t"+report_ordinal);
//					conn.commit();
//					stmt.close();
//					conn.close();
//					session.close();
//				}
//				else {
//						sb = new StringBuilder();
//						sb.append("UPDATE REPORT_MSTR " +
//							"SET   REPORT_NM = '"+ param.get("REPORT_NM") + "' , "+
//							"FLD_ID = " + param.get("FLD_ID") + " , " +
//							"FLD_TYPE = '" + param.get("FLD_TYPE") + "' , "+
//							"REPORT_ORDINAL = " + param.get("REPORT_ORDINAL") + " , "+
//							"REPORT_TYPE = '" + param.get("REPORT_TYPE") + "' , "+
//							"REPORT_TAG = '" + param.get("REPORT_TAG") + "' , "+
//							"REPORT_DESC = '" + param.get("REPORT_DESC") + " ', "+
//							"REPORT_LAYOUT = '" + param.get("REPORT_LAYOUT") + "' , "+
//	//						"DATASRC_ID = '" + param.get("DATASRC_ID") + "' , "+
//							"DATASRC_TYPE = '" + param.get("DATASRC_TYPE") + "' , "+
//							"DATASET_TYPE = '" + param.get("DATASET_TYPE") + "' , "+
//							"REPORT_XML = '" + param.get("REPORT_XML").toString().replaceAll("\n", "") + "' , "+
//							"CHART_XML = '" + param.get("CHART_XML").toString().replaceAll("\n", "") + "' , "+
//							"LAYOUT_XML = '" + param.get("LAYOUT_XML").toString().replaceAll("\n", "") + "' , "+
//							"DATASET_XML = '" + param.get("DATASET_XML").toString().replaceAll("\n", "") + "' , "+
//							"PARAM_XML = '" + param.get("PARAM_XML").toString().replaceAll("\n", "") + "' , "+
//							"DATASET_QUERY = '" + param.get("DATASET_QUERY") + "' , "+
//	//						"REG_USER_NO = " + param.get("REG_USER_NO") + " , "+
//							"DEL_YN = '" + param.get("DEL_YN") + "' , "+
//							"PROMPT_YN = '" + param.get("PROMPT_YN") + "' , "+
//							"REPORT_SUB_TITLE = '" + param.get("REPORT_SUB_TITLE") + "' , "+
//							"MOD_USER_NO = " + param.get("MOD_USER_NO") + " , "+
//	//						"MOD_DT = GETDATE() , "+
//							"MOD_DT = CURRENT TIMESTAMP "+
//	//						"PRIVACY_YN = '" + param.get("PRIVACY_YN")+"'  "+
//				            "WHERE	REPORT_ID = " + param.get("REPORT_ID")
//			            );
//					
//						System.out.println("update query : \n"+sb.toString());
//						stmt.executeUpdate(sb.toString());
//						conn.commit();
//					
//					stmt.close();
//					conn.close();
//					session.close();
//					ret.setId(Integer.parseInt(param.get("REPORT_ID").toString()));
//					ret.setREPORT_ORDINAL(Integer.parseInt(param.get("REPORT_ORDINAL").toString()));
//				}
////			}
//		} catch (SQLException e) {
			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
		//native-sql
//		String driver4 = "com.ibm.db2.jcc.DB2Driver",
//	    	    _url = "jdbc:db2://169.56.81.30:60000/WISEMETA",
//	    	    _user = "WISEBIR5",
//	    	    _password = "wisebir51012";
//		
//		
//		try {
//			Class.forName(driver4);
//			Connection conn = DriverManager.getConnection(_url,_user,_password);
//			Statement stmt = conn.createStatement();
//			int ordinal = 1;
//			String sql = "UPDATE report_mstr \r\n" + 
//					"SET    report_nm = '웹대시보드저장1', \r\n" + 
//					"       fld_id = 2000, \r\n" + 
//					"       fld_type = 'PUBLIC', \r\n" + 
//					"       report_ordinal = "+(ordinalLoop++)+", \r\n" + 
//					"       report_type = 'DashAny', \r\n" + 
//					"       report_tag = '', \r\n" + 
//					"       report_desc = ' ', \r\n" + 
//					"       report_layout = '', \r\n" + 
//					"       datasrc_type = '', \r\n" + 
//					"       dataset_type = '', \r\n" + 
//					"       report_xml = \r\n" + 
//					"'PFJFUE9SVF9YTUw+PFJFQUxUSU1FX0VMRU1FTlQ+MDwvUkVBTFRJTUVfRUxFTUVOVD48L1JFUE9SVF9YTUw+' \r\n" + 
//					"       , \r\n" + 
//					"chart_xml = \r\n" + 
//					"'PERBU0hCT0FSRF9YTUw+PE1BSU5fRUxFTUVOVD48Q0FOVkFTX0hFSUdIVD4wPC9DQU5WQVNfSEVJR0hUPjxDQU5WQVNfQVVUTz50cnVlPC9DQU5WQVNfQVVUTz48Q0FOVkFTX1dJRFRIPjA8L0NBTlZBU19XSURUSD48L01BSU5fRUxFTUVOVD48REFUQV9FTEVNRU5UPjxQQUxFVFRFX05NPk1hdGVyaWFsPC9QQUxFVFRFX05NPjxDVFJMX05NPmNoYXJ0RGFzaGJvYXJkSXRlbTE8L0NUUkxfTk0+PC9EQVRBX0VMRU1FTlQ+PC9EQVNIQk9BUkRfWE1MPg=='\r\n" + 
//					"       , \r\n" + 
//					"layout_xml = \r\n" + 
//					"'IDw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04Ij8+CjxEYXNoYm9hcmQgQ3VycmVuY3lDdWx0dXJlPSJrby1LUiI+CiAgPFRpdGxlIFRleHQ9IuybueuMgOyLnOuztOuTnOyggOyepTEiIEFsaWdubWVudD0iTGVmdCIvPgogIDxEYXRhU291cmNlcz4KICAgIDxEYXRhU291cmNlIENvbXBvbmVudE5hbWU9ImRhdGFTb3VyY2UxIiBOYW1lPSLrjbDsnbTthLDsp5HtlakxIi8+CiAgPC9EYXRhU291cmNlcz4KICA8SXRlbXM+CiAgICA8Q2hhcnQgQ29tcG9uZW50TmFtZT0iY2hhcnREYXNoYm9hcmRJdGVtMSIgTmFtZT0i7LCo7Yq4IDEiIERhdGFTb3VyY2U9ImRhdGFTb3VyY2UxIj4KICAgICAgPERhdGFJdGVtcz4KICAgICAgICA8TWVhc3VyZSBEYXRhTWVtYmVyPSLshozqs4QiIFVuaXF1ZU5hbWU9IkRhdGFJdGVtMCI+CiAgICAgICAgICA8TnVtZXJpY0Zvcm1hdCBQcmVjaXNpb249IjAiIFVuaXQ9Ik9uZXMiIEluY2x1ZGVHcm91cFNlcGFyYXRvcj0idHJ1ZSIvPgogICAgICAgIDwvTWVhc3VyZT4KICAgICAgICA8RGltZW5zaW9uIERhdGFNZW1iZXI9IuyekOuPmeywqCIgVW5pcXVlTmFtZT0iRGF0YUl0ZW0xIi8+CiAgICAgIDwvRGF0YUl0ZW1zPgogICAgICA8QXJndW1lbnRzPgogICAgICAgIDxBcmd1bWVudCBVbmlxdWVOYW1lPSJEYXRhSXRlbTEiLz4KICAgICAgPC9Bcmd1bWVudHM+CiAgICAgIDxTZXJpZXNEaW1lbnNpb25zLz4KICAgICAgPFBhbmVzPgogICAgICAgIDxQYW5lIE5hbWU9IuywvSAxIj4KICAgICAgICAgIDxBeGlzWSBUaXRsZT0i7IaM6rOEIi8+CiAgICAgICAgICA8U2VyaWVzPgogICAgICAgICAgICA8U2ltcGxlPgogICAgICAgICAgICAgIDxWYWx1ZSBVbmlxdWVOYW1lPSJEYXRhSXRlbTAiLz4KICAgICAgICAgICAgPC9TaW1wbGU+CiAgICAgICAgICA8L1Nlcmllcz4KICAgICAgICA8L1BhbmU+CiAgICAgIDwvUGFuZXM+CiAgICAgIDxDaGFydExlZ2VuZCBWaXNpYmxlPSJ0cnVlIi8+CiAgICA8L0NoYXJ0PgogIDwvSXRlbXM+CiAgPExheW91dFRyZWU+CiAgICA8TGF5b3V0R3JvdXA+CiAgICAgIDxMYXlvdXRJdGVtIERhc2hib2FyZEl0ZW09ImNoYXJ0RGFzaGJvYXJkSXRlbTEiIFdlaWdodD0iMTAwIi8+CiAgICA8L0xheW91dEdyb3VwPgogIDwvTGF5b3V0VHJlZT4KPC9EYXNoYm9hcmQ+Cg=='\r\n" + 
//					"       , \r\n" + 
//					"dataset_xml = \r\n" + 
//					"'PERBVEFTRVRfWE1MPjxEQVRBU0VUX0VMRU1FTlQ+PERBVEFTRVQ+PERBVEFTRVRfU0VRPjc0ZGJmNjkzLTQ4YTgtNDM4Yi05OTA3LWZlZDliNzhlNjA4YzwvREFUQVNFVF9TRVE+PERBVEFTRVRfTk0+642w7J207YSw7KeR7ZWpMTwvREFUQVNFVF9OTT48REFUQVNSQ19JRD4xMDAwPC9EQVRBU1JDX0lEPjxEQVRBU1JDX1RZUEU+RFNfU1FMPC9EQVRBU1JDX1RZUEU+PERBVEFTRVRfVFlQRT5EYXRhU2V0U1FMPC9EQVRBU0VUX1RZUEU+PERBVEFTRVRfWE1MPiZsdDtEQVRBX1NFVCZndDsmbHQ7U1FMX1FVRVJZJmd0O1UwVk1SVU5VSUNCVGRXMG9Ja1pmN0o2UTY0K1o3TENvWCt5ZWtleVhoZXlkdk95bmdDSXVJdXlHak9xemhDSXBJRUZUSUNMc2hvenEKczRRaUxBb2dJQ0FnSUNBZ0lGTjFiU2dpUmwvc25wRHJqNW5zc0toZjdKNlI3SmVGN0oyODdLZUFJaTRpNnJpSTdKV2hJaWtnUVZNZwpJdXE0aU95Vm9TSXNDaUFnSUNBZ0lDQWdJa1pmN0o2UTY0K1o3TENvWCt5ZWtleVhoZXlkdk95bmdDSXVJdXlla091UG1leXdxQ0lnClFWTWdJdXlla091UG1leXdxQ0lzQ2lBZ0lDQWdJQ0FnSWtaZjdKNlE2NCtaN0xDb1greWVrZXlYaGV5ZHZPeW5nQ0l1SXV5ZWtleVgKaGV5ZWtDSWdRVk1nSXV5ZWtleVhoZXlla0NJZ0NrWlNUMDBnSUNBZ1JsL3NucERyajVuc3NLaGY3SjZSN0plRjdKMjg3S2VBSUFwSApVazlWVUNCQ1dRbEdYK3lla091UG1leXdxRi9zbnBIc2w0WHNuYnpzcDRBdUl1eWVrT3VQbWV5d3FDSXNDZ2tKUmwvc25wRHJqNW5zCnNLaGY3SjZSN0plRjdKMjg3S2VBTGlMc25wSHNsNFhzbnBBaSZsdDsvU1FMX1FVRVJZJmd0OyZsdDtQQVJBTV9FTEVNRU5ULyZndDsmbHQ7REFUQVNFVF9OTSZndDvrjbDsnbTthLDsp5HtlakxJmx0Oy9EQVRBU0VUX05NJmd0OyZsdDsvREFUQV9TRVQmZ3Q7PC9EQVRBU0VUX1hNTD48REFUQVNFVF9RVUVSWT5TRUxFQ1QgIFN1bSgiRl/snpDrj5nssKhf7J6R7JeF7J287KeAIi4i7IaM6rOEIikgQVMgIuyGjOqzhCIsCiAgICAgICAgU3VtKCJGX+yekOuPmeywqF/snpHsl4Xsnbzsp4AiLiLquIjslaEiKSBBUyAi6riI7JWhIiwKICAgICAgICAiRl/snpDrj5nssKhf7J6R7JeF7J287KeAIi4i7J6Q64+Z7LCoIiBBUyAi7J6Q64+Z7LCoIiwKICAgICAgICAiRl/snpDrj5nssKhf7J6R7JeF7J287KeAIi4i7J6R7JeF7J6QIiBBUyAi7J6R7JeF7J6QIiAKRlJPTSAgICBGX+yekOuPmeywqF/snpHsl4Xsnbzsp4AgCkdST1VQIEJZCUZf7J6Q64+Z7LCoX+yekeyXheydvOyngC4i7J6Q64+Z7LCoIiwKCQlGX+yekOuPmeywqF/snpHsl4Xsnbzsp4AuIuyekeyXheyekCI8L0RBVEFTRVRfUVVFUlk+PFNIRUVUX0lELz48U0hFRVRfTk0vPjwvREFUQVNFVD48L0RBVEFTRVRfRUxFTUVOVD48L0RBVEFTRVRfWE1MPg=='\r\n" + 
//					"       , \r\n" + 
//					"param_xml = 'PFBBUkFNX1hNTC8+', \r\n" + 
//					"dataset_query = '', \r\n" + 
//					"reg_user_no = 2087, \r\n" + 
//					"del_yn = 'N', \r\n" + 
//					"prompt_yn = 'N', \r\n" + 
//					"report_sub_title = '', \r\n" + 
//					"mod_user_no = 2087, \r\n" + 
//					"mod_dt = CURRENT TIMESTAMP, \r\n" + 
//					"privacy_yn = 'N' \r\n" + 
//					"WHERE  report_id = 1012 ";
//			System.out.println("sql : "+sql+"\n");
//			stmt.executeUpdate(sql);
//			stmt.close();
//			conn.close();
//		} catch (SQLException | ClassNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
		
		return ret;
	}
	
	
	public ReportMasterVO callUpReportMstrACT(ReportParamVO param) {
		// TODO Auto-generated method stub
		ReportMasterVO ret = new ReportMasterVO();
		ret = super.getSqlSession().selectOne("Report.UP_REPORT_MSTR_ACT", param);
		if(ret == null) {
			List tt = param.getP_result();
//			System.out.println(tt.get(0));
			ret = (ReportMasterVO)tt.get(0);
//			System.out.println("I think it's oracle.\n");
//			System.out.println(result.toString());
		}
		return ret;
	}
	/* DOGFOOT ktkang 보고서 형상관리 기능 오류 수정  20200909 */
	public ReportMasterVO callUpReportMstrHisACT(ReportParamVO param) {
		// TODO Auto-generated method stub
		ReportMasterVO ret = new ReportMasterVO();
		ret = super.getSqlSession().selectOne("Report.UP_REPORT_MSTR_HIS_ACT", param);
		if(ret == null) {
			List tt = param.getP_result();
//			System.out.println(tt.get(0));
			ret = (ReportMasterVO)tt.get(0);
//			System.out.println("I think it's oracle.\n");
//			System.out.println(result.toString());
		}
		return ret;
	}
	
	public List<ReportMasterHisVO> selectReportMstrHisList(int reportId) {
		List<ReportMasterHisVO> result = super.getSqlSession().selectList("Report.selectReportMstrHisList", reportId);
        return result;
	}
	
	public List<ReportScheduleVO> selectReportScheduleList(ReportScheduleVO param) {
        List<ReportScheduleVO> result = super.getSqlSession().selectList("Report.selectReportScheduleList", param);
        return result;
    }

	public List<ReportScheduleVO> selectReportScheduleAllList() {
        List<ReportScheduleVO> result = super.getSqlSession().selectList("Report.selectReportScheduleAllList");
        return result;
    }
	
	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
	public List<ReportScheduleVO> selectReportScheduleAllList2() {
        List<ReportScheduleVO> result = super.getSqlSession().selectList("Report.selectReportScheduleAllList2");
        return result;
    }
	
	public int insertReportSchedule(ReportScheduleVO param) {
		int result = super.getSqlSession().insert("Report.insertReportSchedule",param);
		return result;
	}
	
	public int deleteReportSchedule(ReportScheduleVO param) {
		int result = super.getSqlSession().insert("Report.deleteReportSchedule",param);
		return result;
	}

	public int deleteReportScheduleAll(ReportScheduleVO param) {
		int result = super.getSqlSession().insert("Report.deleteReportScheduleAll",param);
		return result;
	}

	public int deleteReportScheduleAndData(ReportScheduleVO param) {
		int result = super.getSqlSession().insert("Report.deleteReportScheduleAndData", param);
		return result;
	}

	public String selectReportName(ReportMasterVO param) {
		List<ReportMasterVO> result = super.getSqlSession().selectList("Report.getReportName",param);
		String resultName = "";
		if(result.size() != 0)
			resultName = result.get(0).getREPORT_NM();
		return resultName;
	}

	public int insertReportDetail(ReportLogDetailMasterVO logdetail) {
		// TODO Auto-generated method stub
		int result = super.getSqlSession().insert("Report.InsertReportLogDetail",logdetail);
		return result;
	}

	public int updateReportLogDetail(ReportLogMasterVO vo) {
		// TODO Auto-generated method stub
		int result = super.getSqlSession().update("Report.UpdateReportLogDetail",vo);
		return result;
	}
	
	public int updateReportLogDetailError(int interval) {
		HashMap<String, Integer> map = new HashMap<String, Integer>();
		map.put("interval", interval);
		int result = super.getSqlSession().update("Report.UpdateReportLogDetailError", map);
		return result;
	}
	
	public int getReportLogCleanHour() {
		return super.getSqlSession().selectOne("Report.getReportLogCleanHour");
	}

	public int updateReportUseLog(ReportLogMasterVO vo) {
		// TODO Auto-generated method stub
		int result = super.getSqlSession().update("Report.UpdateReportUseLog",vo);
		return result;
	}

/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	public ReportMasterVO selectReportType(String pid) {
		// TODO Auto-generated method stub
		return super.getSqlSession().selectOne("Report.getReportType",pid);
	}

	public void insertUserUpload(UserUploadMstrVO uploadVo) {
		// TODO Auto-generated method stub
		super.getSqlSession().insert("Report.insertUserUpload",uploadVo); 
	}

	public UploadHisVO selectHisUpload(UploadHisVO getseq) {
		// TODO Auto-generated method stub
		return (UploadHisVO) super.getSqlSession().selectOne("Report.selectHisUpload",getseq); 
	}

	public void insertUserUploadHis(UploadHisVO hisVo) {
		// TODO Auto-generated method stub
		super.getSqlSession().insert("Report.insertUserUploadHis",hisVo); 
	}

	public List<UserUploadMstrVO> selectUserUpload(int dataSourceId) {
		// TODO Auto-generated method stub
		List<UserUploadMstrVO> result = super.getSqlSession().selectList("Report.selectUserUpload",dataSourceId);
		return result;
	}
	
	public ReportSubLinkVO selectLinkSubReportYn(ReportSubLinkVO reportSubLinkVo) {
		ReportSubLinkVO result = super.getSqlSession().selectOne("Report.selectLinkSubReportYn",reportSubLinkVo);
		return result;
	}
	
	//2019.01.17 mksong 서브연결보고서 처음 저장을 위한 추가 dogfoot
	public int selectLinkSubReportSeq() {
		int result = super.getSqlSession().selectOne("Report.selectLinkSubReportSeq");
		return result;
	}
	
	public int deleteReportLink(String report_id) {
		int result = super.getSqlSession().insert("Report.deleteReportLink",report_id);
		return result;
	}
	
	public int updateSubLinkReport(ReportSubLinkVO reportSubLinkVo) {
		int result = super.getSqlSession().update("Report.updateSubLinkReport", reportSubLinkVo);
		return result;
	}

	public int deleteReportSubLink(String report_id) {
		int result = super.getSqlSession().insert("Report.deleteReportSubLink",report_id);
		return result;
	}
	
	public List<DrillThruColumnVO> selectDrillThruColumns(int cubeId, int actId) {
        Map<String, Integer> params = new HashMap<String, Integer>();
        params.put("cubeId", cubeId);
        params.put("actId", actId);
        
        List<DrillThruColumnVO> result = super.getSqlSession().selectList("Report.selectDrillThruColumns", params);
        return result;
    }
	
	public List<DrillThruColumnVO> selectDrillThruCategoryList(int cubeId) {
        List<DrillThruColumnVO> result = super.getSqlSession().selectList("Report.selectDrillThruCategoryList", cubeId);
        return result;
    }
	
	/* DOGFOOT ktkang KERIS 보고서 별 필드 정보 추가기능  20200123 */
	public List<ReportFieldMasterVO> selectReportFieldList(int reportId) {
		List<ReportFieldMasterVO> result = super.getSqlSession().selectList("Report.selectReportFieldList", reportId);
        return result;
    }
	
	public int deleteReportFieldList(int reportId) {
		int result = super.getSqlSession().insert("Report.deleteReportFieldList", reportId);
        return result;
    }
	
	public int insertReportField(ReportFieldMasterVO reportField) {
		int result = super.getSqlSession().insert("Report.insertReportField", reportField);
        return result;
    }
	
	/* DOGFOOT ktkang KERIS EDS포탈에서 보여주는 보고서 체크 기능  20200205 */
	public List<ReportParamVO> selectPotalReportList() {
		return super.getSqlSession().selectList("Report.selectPotalReportList");
	}
	
	public List<TableRelationVO> selectCubeRelationList(CubeTableVO cubeTableVO) {
		return super.getSqlSession().selectList("Report.selectCubeRelationList", cubeTableVO);
	}
	/* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
	public List<ReportMasterHisVO> selectReportHisList(int reportId) {
		return super.getSqlSession().selectList("Report.selectReportHisList", reportId);
	}
	
	public ReportMasterHisVO selectReportHis(int reportId, int reportSeq) {
		Map<String, Integer> params = new HashMap<String, Integer>();
        params.put("reportId", reportId);
        params.put("reportSeq", reportSeq);
        
		return super.getSqlSession().selectOne("Report.selectReportHis", params);
	}
	
	public int updateReportMstrHis(ReportMasterHisVO vo) {
		int result = super.getSqlSession().update("Report.updateReportMstrHis",vo);
		return result;
	}
	
	/* DOGFOOT ktkang 동시 작업 제한 기능 구현  20200922 */
	public int selectReportWorks() {
		int result = super.getSqlSession().selectOne("Report.selectReportWorks");
		return result;
	}
	
	/* DOGFOOT ktkang 리포트 다운로드 권한 구현  20201109 */
	public UserGrpAuthReportListVO userAuthByReport(int userNo, String reportId) {
		Map<String, Integer> params = new HashMap<String, Integer>();
        params.put("userNo", userNo);
        params.put("reportId", Integer.parseInt(reportId));
        
        UserGrpAuthReportListVO result = super.getSqlSession().selectOne("Report.userAuthByReport", params);
		return result;
	}
	
	public UserGrpAuthReportListVO grpAuthByReport(int grpId, String reportId) {
		Map<String, Integer> params = new HashMap<String, Integer>();
        params.put("grpId", grpId);
        params.put("reportId", Integer.parseInt(reportId));
        
        UserGrpAuthReportListVO result = super.getSqlSession().selectOne("Report.grpAuthByReport", params);
		return result;
	}
	
	public UserGrpAuthReportListVO userAuthByFolder(int userNo, String fldId) {
		Map<String, Integer> params = new HashMap<String, Integer>();
        params.put("userNo", userNo);
        params.put("fldId", Integer.parseInt(fldId));
        
        UserGrpAuthReportListVO result = super.getSqlSession().selectOne("Report.userAuthByFolder", params);
		return result;
	}
	
	public UserGrpAuthReportListVO grpAuthByFolder(int grpId, String fldId) {
		Map<String, Integer> params = new HashMap<String, Integer>();
        params.put("grpId", grpId);
        params.put("fldId", Integer.parseInt(fldId));
        
        UserGrpAuthReportListVO result = super.getSqlSession().selectOne("Report.grpAuthByFolder", params);
		return result;
	}
	
	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
	public String selectSchedulePath(int reportId) {
        String result = super.getSqlSession().selectOne("Report.selectSchedulePath", reportId);
		return result;
	}
	
	/* DOGFOOT ktkang BMT 그룹핑 기능 구현  20201203 */
	public List<DSViewColVO> selectCubeGroupingData(int cubeId) {
		List<DSViewColVO> result = super.getSqlSession().selectList("Report.selectCubeGroupingData", cubeId);
		return result;
	}
	
	public List<CubeHieMasterVO> selectCubeGroupingTblList(int cubeId) {
		List<CubeHieMasterVO> result = super.getSqlSession().selectList("Report.selectCubeGroupingTblList", cubeId);
		return result;
	}
	
	public int deleteDsViewColMstr(int dsViewId) {
		int result = super.getSqlSession().insert("Report.deleteDsViewColMstr", dsViewId);
		return result;
	}
	
	public int deleteDsViewHieMstr(int dsViewId) {
		int result = super.getSqlSession().insert("Report.deleteDsViewHieMstr", dsViewId);
		return result;
	}
	
	public int deleteCubeHieMstr(int cubeId) {
		int result = super.getSqlSession().insert("Report.deleteCubeHieMstr", cubeId);
		return result;
	}
	
	public int insertDsViewColMstr(DSViewColVO param) {
		int result = super.getSqlSession().insert("Report.insertDsViewColMstr", param);
		return result;
	}
	
	public int insertDsViewHieMstr(DSViewHieVO param) {
		int result = super.getSqlSession().insert("Report.insertDsViewHieMstr", param);
		return result;
	}
	
	public int insertCubeHieMstr(CubeHieMasterVO param) {
		int result = super.getSqlSession().insert("Report.insertCubeHieMstr", param);
		return result;
	}
	
	public int selectMaxColId() {
		int result = super.getSqlSession().selectOne("Report.selectMaxColId");
		return result;
	}
	
	public List<CubeHieMasterVO> selectCubeGroupingDimList(Map<String, String> param) {
		List<CubeHieMasterVO> result = super.getSqlSession().selectList("Report.selectCubeGroupingDimList", param);
		return result;
	}
	
	/* DOGFOOT shlim reportmstr dsid 변경  20200309 */
	public ReportMasterVO selectReportParamXmlList(int reportId) {
		// TODO Auto-generated method stub
		
		ReportMasterVO result = super.getSqlSession().selectOne("Report.selectReportParamXmlList", reportId);
		return result;
	}
	
	public void updateReportDatasetParam(ReportMasterVO param) {
		// TODO Auto-generated method stub
		
		super.getSqlSession().update("Report.updateReportDatasetParam", param);
	}
	
	public List<ReportMasterVO> selectReportIdGoyongList() {
		List<ReportMasterVO> result = super.getSqlSession().selectList("Report.selectReportIdGoyongList");
		return result;
	}
	
	public String selectGoyongUserSosok(String iscd) {
		String result = super.getSqlSession().selectOne("Report.selectGoyongUserSosok", iscd);
		return result;
	}
	
}
