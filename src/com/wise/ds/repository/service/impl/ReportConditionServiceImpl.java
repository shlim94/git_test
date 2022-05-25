package com.wise.ds.repository.service.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
// DOGFOOT hsshim 1220 데이터 집합 에러 처리 오류 수정
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.wise.authn.DataAuthentication;
import com.wise.authn.ReportDataPermission;
import com.wise.authn.User;
import com.wise.authn.dao.AuthenticationDAO;
import com.wise.common.secure.SecureUtils;
import com.wise.common.util.CoreUtils;
import com.wise.context.config.Base64Coder;
import com.wise.context.config.Configurator;
import com.wise.ds.query.util.SqlConvertor;
import com.wise.ds.query.util.SqlMapper;
import com.wise.ds.repository.CubeHieMasterVO;
import com.wise.ds.repository.CubeMember;
// DOGFOOT hsshim 1220 데이터 집합 에러 처리 오류 수정
import com.wise.ds.repository.UndefinedDataTypeForNullValueException;
import com.wise.ds.repository.dao.ReportDAO;
import com.wise.ds.repository.dataset.DataField;
import com.wise.ds.repository.dataset.DataSetConst;
// DOGFOOT hsshim 1220 데이터 집합 에러 처리 오류 수정
import com.wise.ds.repository.dataset.EmptyDataSetInformationException;
import com.wise.ds.repository.dataset.JavaxtUtils;
// DOGFOOT hsshim 1220 데이터 집합 에러 처리 오류 수정
import com.wise.ds.repository.dataset.NotFoundDataSetTypeException;
import com.wise.ds.repository.dataset.NotFoundDatabaseConnectorException;
// DOGFOOT hsshim 1220 데이터 집합 에러 처리 오류 수정 끝
import com.wise.ds.repository.service.DataSetService;
import com.wise.ds.repository.service.ReportConditionService;
import com.wise.ds.sql.CubeTableColumn;

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

@Service("reportConditionService")
public class ReportConditionServiceImpl implements ReportConditionService {
	final static private Logger logger = LoggerFactory.getLogger(ReportConditionServiceImpl.class);

	@Resource(name = "dataSetService")
	private DataSetService dataSetService;
	/* DOGFOOT ktkang 주제영역 필터 데이터 권한 추가  20200806 */
    @Resource(name = "authenticationDAO")
    private AuthenticationDAO authenticationDAO;
    
    @Resource(name = "reportDAO")
    private ReportDAO reportDAO;
 
	@Resource(name = "sqlMapper")
	private SqlMapper sqlMapper;

	@Resource(name = "sqlConvertor")
	private SqlConvertor sqlConvertor;
	@Override
	public List selectDataList(int dataSourceId, String dataSourceType, String columnName, String tableName) throws Exception {
		Connection connection = null;
		PreparedStatement pstmt = null;
		ResultSet resultSet = null;

		List ret = new ArrayList<>();
		try {
			String sql;

			sql = "SELECT ";
            sql +=  columnName + " ";
            sql += " FROM " + tableName + " ";
            sql += " GROUP BY " + columnName +" ";
            sql += " ORDER BY " + columnName;

			connection = this.dataSetService.getConnection(dataSourceId, DataSetConst.DataSetType.DS);
			pstmt = connection.prepareStatement(sql);

			logger.debug("connection is closed? " + connection.isClosed());

			resultSet = pstmt.executeQuery();

			ResultSetMetaData md = resultSet.getMetaData();
			while (resultSet.next()) {
				for (int i = 1; i <= md.getColumnCount(); i++) {
					DataField field = new DataField(i, md, resultSet.getObject(i));
					ret.add(JavaxtUtils.getValue(field));
				}
			}
			
		} catch (Exception e) {
			logger.error("ReportConditionServiceImpl#queryComboCondition", e);
			throw e;
		} finally {
			if (resultSet != null)
				resultSet.close();
			if (pstmt != null)
				pstmt.close();
			if (connection != null && !connection.isClosed()) {
				logger.debug("");
				logger.debug("");
				logger.debug("connection close - condition");
				logger.debug("");
				logger.debug("");
				connection.close();
			} 
		}

		return ret;
	}
	
	@Override
	public JSONArray queryComboCondition(int dataSourceId, String dataSourceType, String dataSource, String textColumn,
			String valueColumn, String parameterValues, String sortType, String whereClause, String sortColumn, User user, int cubeId, String orderByKeyColumn, String closYm) 
			throws SQLException, NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException {
		Connection connection = null;
		PreparedStatement pstmt = null;
		ResultSet resultSet = null;

		JSONArray ret = null;
		if(sortColumn == null || sortColumn.equals("")) {
        	sortColumn = valueColumn;
        }
		try {
			String sql;
			String keyStr = "KEY_VALUE";
			String captionStr = "CAPTION_VALUE";
			String where = "";
			String uniName = "";
			
			

			if ("QUERY".equalsIgnoreCase(dataSourceType) || "LVL".equalsIgnoreCase(dataSourceType)) {
				sql = dataSource;
				dataSourceType = "DS_SQL";
				keyStr = valueColumn;
				captionStr = textColumn;
			} else {
				String sort = (CoreUtils.ifNull(sortType).equalsIgnoreCase("desc")) ? "desc" : "asc";
				/* DOGFOOT ktkang 주제영역 필터 데이터 권한 추가  20200806 */
				if(cubeId != 0) {
					CubeMember cubeInfo = this.reportDAO.selectCubeMasterInformation(cubeId);
					List<DataAuthentication> userDataAuthentications = new ArrayList<DataAuthentication>();

					Map<String, Object> colInfoParam = new HashMap<String, Object>();
					colInfoParam.put("cubeId", cubeId);
					
					Map<String,List<String>> usedWhere0 = new HashMap<String,List<String>>();
					uniName = dataSource + "." + valueColumn;
					if (userDataAuthentications.size() > 0) {
						for (DataAuthentication da : userDataAuthentications) {
							if(uniName.equals(da.getUniqueName().replace("[", "").replace("]", ""))) 
							{
								if (usedWhere0.containsKey(da.getUniqueName())) {
									((List<String>)usedWhere0.get(da.getUniqueName())).add(da.getMemberName());
								}
								else {
									List<String> memberValues = new ArrayList<String>();
									memberValues.add(da.getMemberName());
									usedWhere0.put(da.getUniqueName(), memberValues);
								}
							}
						}
					}
					for (Object un : usedWhere0.keySet().toArray()) {
						where = "";
						for (String memberValue : (List<String>)usedWhere0.get(un)) {
							where += "'" + memberValue + "'";
							where += ",";
						}
						if (where.length() > 0) where = where.substring(0, where.length() - 1);
						logger.debug("DataAuthentications 510 : "+where);
					}
				}
				sql = "SELECT ";
                sql += textColumn + " AS CAPTION_VALUE, ";
                sql += valueColumn + " AS  KEY_VALUE ";
                sql += " FROM " + dataSource + " ";
                if(where.length() != 0) {
                	sql += " WHERE " + uniName + " IN (" + where + ")";
                }
                /* DOGFOOT ktkang 고용정보원10 사용자컬럼 필터 오류 수정 */
//                sql += " GROUP BY CAPTION_VALUE, KEY_VALUE";
                sql += " GROUP BY " + textColumn +" , "+ valueColumn;
                /*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
                if(orderByKeyColumn != null && !(orderByKeyColumn.equalsIgnoreCase("")) && !orderByKeyColumn.contains("WISE_")) {
                	sql += " , " + orderByKeyColumn +" ";
                	sql += " ORDER BY " + orderByKeyColumn + " " + sort;
                }else {
                	if(sortColumn != null && sortColumn.equalsIgnoreCase("key column")) {
                    	sql += " ORDER BY KEY_VALUE " + sort + ", CAPTION_VALUE " + sort;
                    } else if(sortColumn != null && sortColumn.equalsIgnoreCase("name column")){
                    	sql += " ORDER BY CAPTION_VALUE " + sort + ", KEY_VALUE " + sort;
                    }else if(sortColumn != null && !sortColumn.contains("WISE_")){
                    	sql += " , " + sortColumn +" ";
                    	sql += " ORDER BY "+ sortColumn + " " + sort;
                    }else {
                    	sql += " ORDER BY CAPTION_VALUE " + sort + ", KEY_VALUE " + sort;
                    }
                }
               
			}

			logger.debug("parameter sql : " + sql);

			sql = this.sqlConvertor.convert(sql);
			logger.debug("(converted) parameter sql : " + sql);

			if (parameterValues != null) {
				parameterValues = this.sqlConvertor.convert(parameterValues);

				JSONObject jsonParameterValues = JSONObject.fromObject(parameterValues);
				logger.debug("param Val : "+jsonParameterValues.toString());
				/*dogfoot shlim 20210414*/
				sql = this.sqlMapper.mapParameter(sql, jsonParameterValues, whereClause,user);
				logger.debug("parameter sql(param) : " + sql);
			}
			
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

    		sql = sql.replaceAll("#CLOSYM", closYm);
            sql = sql.replaceAll("#ISCD", iscd);
     		sql = sql.replaceAll("#AUTHCD", auth_cd);
     		sql = sql.replaceAll("#WAUTHCD", wnet_cd);
     		sql = sql.replaceAll("#TAUTHCD", octr_cd);
     		
			//치환되지 않은 스칼라변수 제거
            //sql = sql.replaceAll("@([a-zA-Z0-9_-]+)","''");

			connection = this.dataSetService.getConnection(dataSourceId, dataSourceType);
			pstmt = connection.prepareStatement(sql);

			logger.debug("connection is closed? " + connection.isClosed());

			resultSet = pstmt.executeQuery();

			//HashMap<String, String> keyValueMap = new HashMap<String, String>();
            //keyValueMap.put("KEY_VALUE", valueColumn);
            //keyValueMap.put("CAPTION_VALUE",textColumn);
            
            
			ResultSetMetaData md = resultSet.getMetaData();
			List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
			while (resultSet.next()) {
				Map<String, Object> row = new HashMap<String, Object>();

				for (int i = 1; i <= md.getColumnCount(); i++) {
					DataField field = new DataField(i, md, resultSet.getObject(i));
					row.put(md.getColumnLabel(i).toUpperCase(), JavaxtUtils.getValue(field));
					/*
					//KEY_VALUE, CAPTION_VALUE 바꿔야하는 이유 알아내기~ hjkim
					if (keyStr.equals(md.getColumnLabel(i)) && keyStr.equals(captionStr)) {
						row.put("KEY_VALUE", JavaxtUtils.getValue(field));
						row.put("CAPTION_VALUE", JavaxtUtils.getValue(field));
						break;
					} else if (keyStr.equals(md.getColumnLabel(i))) {
						row.put("KEY_VALUE", JavaxtUtils.getValue(field));
					} else if (captionStr.equals(md.getColumnLabel(i))) {
						row.put("CAPTION_VALUE", JavaxtUtils.getValue(field));
					}
					*/
				}

				result.add(row);
			}
			
			ret = JSONArray.fromObject(result);
		} catch (SQLException | NotFoundDatabaseConnectorException | EmptyDataSetInformationException | NotFoundDataSetTypeException | UndefinedDataTypeForNullValueException e) {
			logger.error("ReportConditionServiceImpl#queryComboCondition", e);
			throw e;
		} finally {
			if (resultSet != null) {
				try {
					resultSet.close();
				} catch (SQLException se) {
					se.printStackTrace();
				}
			}
			if (pstmt != null) {
				try {
					pstmt.close();
				} catch (SQLException se) {
					se.printStackTrace();
				}
			}
			if (connection != null) {
				try {
					if (!connection.isClosed()) {
						connection.close();
					}
				} catch (SQLException se) {
					se.printStackTrace();
				}
			}
		}

		return ret;
	}

	@Override
	public JSONArray queryParamCondition(int dataSourceId, String Caption_Value, String Key_Value, String dataTable,
			String queryOption,String queryType, String queryValue) throws Exception {
		Connection connection = null;
		PreparedStatement pstmt = null;
		ResultSet resultSet = null;
		JSONArray ret = null;
		// TODO Auto-generated method stub
		String whereCluse;
		if(queryType.equals("코드")) {
			whereCluse = Key_Value;
		}
		else {
			whereCluse = Caption_Value;
		}
		String[] temp = queryValue.split(",");
		String sql;
		sql = "SELECT distinct ";
		sql += Caption_Value + ", ";
		sql += Key_Value + " ";
		sql += "FROM " + dataTable + " ";
		sql += "WHERE " + whereCluse + " IN ('" + temp[0].trim() + "')";
		for (int i = 1; i < temp.length; i++) {
			sql += " " + queryOption + " " + whereCluse + " IN ('" + temp[i].trim() + "')";
		}
		sql += "ORDER BY 1 ";
		if(queryValue.equals("") && queryOption.equals("")) {
			sql = "SELECT distinct ";
			sql += Caption_Value + ", ";
			sql += Key_Value + " ";
			sql += "FROM " + dataTable + " ";
		}
		logger.debug(sql);
		try {
			connection = this.dataSetService.getConnection(dataSourceId, DataSetConst.DataSetType.DS);
			pstmt = connection.prepareStatement(sql);
			resultSet = pstmt.executeQuery();
			ResultSetMetaData md = resultSet.getMetaData();
			List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
			while (resultSet.next()) {
				Map<String, Object> row = new HashMap<String, Object>();

				for (int i = 1; i <= md.getColumnCount(); i++) {
					DataField field = new DataField(i, md, resultSet.getObject(i));
					// System.out.println(md.getColumnName(i));
					// System.out.println(md.getColumnLabel(i));
					// row.put(md.getColumnName(i), JavaxtUtils.getValue(field));
					row.put(md.getColumnLabel(i), JavaxtUtils.getValue(field));
				}
				result.add(row);
			}
			ret = JSONArray.fromObject(result);
		} catch (Exception e) {
			logger.error("ReportConditionServiceImpl#queryParamCondition", e);
			throw e;
		} finally {
			if (resultSet != null)
				resultSet.close();
			if (pstmt != null)
				pstmt.close();
			if (connection != null && !connection.isClosed()) {
				logger.debug("");
				logger.debug("");
				logger.debug("connection close - ParamCondition");
				logger.debug("");
				logger.debug("");
				connection.close();
			}
		}

		return ret;
	}

}
