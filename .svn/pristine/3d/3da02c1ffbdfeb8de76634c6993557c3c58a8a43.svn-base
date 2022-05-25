package com.wise.ds.repository.service;
// DOGFOOT hsshim 1220 데이터 집합 에러 처리 오류 수정
import java.sql.SQLException;
import java.util.List;

import com.wise.authn.User;
import com.wise.common.secure.SecureUtils;
// DOGFOOT hsshim 1220 데이터 집합 에러 처리 오류 수정
import com.wise.ds.repository.UndefinedDataTypeForNullValueException;
import com.wise.ds.repository.dataset.EmptyDataSetInformationException;
import com.wise.ds.repository.dataset.NotFoundDataSetTypeException;
import com.wise.ds.repository.dataset.NotFoundDatabaseConnectorException;
// DOGFOOT hsshim 1220 데이터 집합 에러 처리 오류 수정 끝

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

public interface ReportConditionService {
    /* DOGFOOT ktkang 주제영역 필터 데이터 권한 추가  20200806 */
	/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
    public JSONArray queryComboCondition(int dataSourceId, String dataSourceType, String dataSource, String textColumn, String valueColumn, String parameterValues, String sortType,String whereClause, String sortColumn, User user, int cubeId, String orderByKeyColumn, String closYm) throws SQLException, NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException;
     
    public JSONArray queryParamCondition(int dataSourceId, String Caption_Value, String Key_Value, String dataTable, String queryOption, String queryType, String queryValue) throws Exception;

	public List selectDataList(int dataSourceId, String dataSourceType, String columnName, String tableName) throws Exception;
}