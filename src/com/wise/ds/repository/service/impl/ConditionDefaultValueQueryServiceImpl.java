package com.wise.ds.repository.service.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Map;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.wise.ds.query.util.SqlConvertor;
import com.wise.ds.repository.dataset.DataSetConst;
import com.wise.ds.repository.service.ConditionDefaultValueQueryService;
import com.wise.ds.repository.service.DataSetService;

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

@Service("conditionDefaultValueQueryService")
public class ConditionDefaultValueQueryServiceImpl implements ConditionDefaultValueQueryService {
    final static private Logger logger = LoggerFactory.getLogger(ConditionDefaultValueQueryServiceImpl.class);
    
    @Resource(name = "dataSetService")
    private DataSetService dataSetService;
    
    @Resource(name = "sqlConvertor")
    private SqlConvertor sqlConvertor;
    
    @Override
    public ArrayList<Object> queryDefaultSql(int dataSourceId, String dataSource, String closYm, Map<String, String> relCodeMap) throws Exception {
        Connection connection = null;
        PreparedStatement pstmt = null;
        ResultSet resultSet = null;
        
        ArrayList<Object> defaultValue = new ArrayList<Object>();
        
        try {
            String sql = dataSource;
            //치환되지 않은 스칼라변수 제거
            sql = sql.replaceAll("#CLOSYM", closYm);
            sql = sql.replaceAll("#ISCD", relCodeMap.get("iscd"));
    		sql = sql.replaceAll("#AUTHCD", relCodeMap.get("auth_cd"));
    		sql = sql.replaceAll("#WAUTHCD", relCodeMap.get("wnet_cd"));
    		sql = sql.replaceAll("#TAUTHCD", relCodeMap.get("octr_cd"));
            
            sql = sql.replaceAll("@([a-zA-Z0-9_-]+)","''");
            logger.debug("Condition parameter sql : " + sql);
            
            sql = this.sqlConvertor.convert(sql);
            logger.debug("Condition parameter sql(converted) : " + sql);
            
            connection = this.dataSetService.getConnection(dataSourceId, DataSetConst.DataSetType.DS);
            pstmt = connection.prepareCall(sql);
            
            resultSet = pstmt.executeQuery();
            
            while (resultSet.next()) {
            	 defaultValue.add(resultSet.getObject(1));
            }
        }
        catch(Exception e) {
            logger.error("ReportConditionServiceImpl#queryComboCondition", e);
            throw e;
        }
        finally {
            if (resultSet != null) resultSet.close();
            if (pstmt != null) pstmt.close();
            if (connection != null && !connection.isClosed()) { 
                logger.debug("");
                logger.debug("");
                logger.debug("connection close - condition");
                logger.debug("");
                logger.debug("");
                connection.close();
            }
        }
        
        return defaultValue;
    }
    
    public ArrayList<Object> queryDefaultSql(int dataSourceId, String dataSources[], String closYm, Map<String, String> relCodeMap) throws Exception {
        Connection connection = null;
        PreparedStatement pstmt = null;
        ResultSet resultSet = null;
        
        ArrayList<Object> defaultValue = new ArrayList<Object>();
        
        try {
        	connection = this.dataSetService.getConnection(dataSourceId, DataSetConst.DataSetType.DS);
        	
        	for(String dataSource : dataSources)
        	{
        		String sql = dataSource;
                
        		sql = sql.replaceAll("#CLOSYM", closYm);
        		sql = sql.replaceAll("#ISCD", relCodeMap.get("iscd"));
        		sql = sql.replaceAll("#AUTHCD", relCodeMap.get("auth_cd"));
        		sql = sql.replaceAll("#WAUTHCD", relCodeMap.get("wnet_cd"));
        		sql = sql.replaceAll("#TAUTHCD", relCodeMap.get("octr_cd"));
                logger.debug("parameter sql : " + sql);
                
                pstmt = connection.prepareCall(sql);
                
                resultSet = pstmt.executeQuery();
                
                while (resultSet.next()) {
                	 defaultValue.add(resultSet.getObject(1));
                }
        	}
            
        }
        catch(Exception e) {
            logger.error("ReportConditionServiceImpl#queryComboCondition", e);
            throw e;
        }
        finally {
            if (resultSet != null) resultSet.close();
            if (pstmt != null) pstmt.close();
            if (connection != null && !connection.isClosed()) { 
                logger.debug("");
                logger.debug("");
                logger.debug("connection close - condition");
                logger.debug("");
                logger.debug("");
                connection.close();
            }
        }
        
        return defaultValue;
    }
}
