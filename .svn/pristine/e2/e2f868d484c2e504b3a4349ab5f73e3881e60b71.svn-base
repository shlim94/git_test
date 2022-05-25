package com.wise.ds.repository.service.impl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.spark.SparkContext;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Encoders;
import org.apache.spark.sql.SQLContext;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.types.DataTypes;
import org.apache.spark.sql.types.Metadata;
import org.apache.spark.sql.types.StructField;
import org.apache.spark.sql.types.StructType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import com.wise.authn.ConfigMasterVO;
import com.wise.authn.DataAuthentication;
import com.wise.authn.ReportDataPermission;
import com.wise.authn.User;
import com.wise.authn.WebConfigMasterVO;
import com.wise.authn.dao.AuthenticationDAO;
import com.wise.authn.service.AuthenticationService;
import com.wise.common.diagnos.WDC;
import com.wise.common.diagnos.WdcTask;
import com.wise.common.file.CacheFileWritingTaskExecutorService;
import com.wise.common.file.KeyedFileLockService;
import com.wise.common.secure.SecureUtils;
import com.wise.common.util.CloseableList;
import com.wise.common.util.CoreUtils;
import com.wise.common.util.FileBackedJSONObjectList;
import com.wise.common.util.ServiceTimeoutUtils;
import com.wise.common.util.Timer;
import com.wise.common.util.WINumberUtils;
import com.wise.context.config.Configurator;
import com.wise.ds.query.util.SqlConvertor;
import com.wise.ds.query.util.SqlForEachMartDbType;
import com.wise.ds.query.util.SqlMapper;
import com.wise.ds.query.util.SqlStorage;
import com.wise.ds.repository.CubeListMasterVO;
import com.wise.ds.repository.CubeMember;
import com.wise.ds.repository.CubeTableColumnVO;
import com.wise.ds.repository.CubeTableVO;
import com.wise.ds.repository.DSViewColVO;
import com.wise.ds.repository.DataSetInfoMasterVO;
import com.wise.ds.repository.DataSetInfoVO;
import com.wise.ds.repository.DataSetMasterVO;
import com.wise.ds.repository.DrillThruColumnVO;
import com.wise.ds.repository.FolderMasterVO;
import com.wise.ds.repository.FolderParamVO;
import com.wise.ds.repository.ParamScheduleVO;
import com.wise.ds.repository.ReportListMasterVO;
import com.wise.ds.repository.ReportLogMasterVO;
import com.wise.ds.repository.ReportMasterVO;
import com.wise.ds.repository.SubjectCubeMasterVO;
import com.wise.ds.repository.SubjectMasterVO;
import com.wise.ds.repository.SubjectViewMasterVO;
import com.wise.ds.repository.TableRelationVO;
import com.wise.ds.repository.TossExeVO;
import com.wise.ds.repository.UndefinedDataTypeForNullValueException;
import com.wise.ds.repository.dao.DataSetDAO;
import com.wise.ds.repository.dao.ReportDAO;
import com.wise.ds.repository.dataset.DataField;
import com.wise.ds.repository.dataset.DataSetConst;
import com.wise.ds.repository.dataset.DataSourceFactory;
import com.wise.ds.repository.dataset.EmptyDataSetInformationException;
import com.wise.ds.repository.dataset.JavaxtUtils;
import com.wise.ds.repository.dataset.NotFoundDataSetTypeException;
import com.wise.ds.repository.dataset.NotFoundDatabaseConnectorException;
import com.wise.ds.repository.service.DataSetService;
import com.wise.ds.repository.service.ReportService;
import com.wise.ds.sql.CubeTable;
import com.wise.ds.sql.CubeTableColumn;
import com.wise.ds.util.Json2Xml;
import com.wise.ds.util.ResultSetMetaDataUtils;
import com.wise.ds.util.SparkLoad;
import com.wise.ds.util.WebFileUtils;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import wise.querygen.dto.Hierarchy;
import wise.querygen.dto.Relation;
import wise.querygen.dto.SelectCube;
import wise.querygen.dto.SelectCubeEtc;
import wise.querygen.dto.SelectCubeMeasure;
import wise.querygen.dto.SelectCubeOrder;
import wise.querygen.dto.SelectCubeWhere;
import wise.querygen.service.QuerySettingEx;

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

@Service("dataSetService")
public class DataSetServiceImpl implements DataSetService {
    final static private Logger logger = LoggerFactory.getLogger(DataSetServiceImpl.class);
    private PreparedStatement pstmt = null;
    private Connection connection = null;
    /* DOGFOOT ktkang 작업 취소 기능 구현  20200923 */
	String os = System.getProperty("os.name").toLowerCase();

    @Autowired
    private SparkLoad sparkLoad;

    @Resource(name = "dataSetDAO")
    private DataSetDAO dataSetDAO;

    @Resource(name = "authenticationDAO")
    private AuthenticationDAO authenticationDAO;

    @Resource(name = "dataSourceFactory")
    private DataSourceFactory dataSourceFactory;

    @Resource(name = "sqlMapper")
    private SqlMapper sqlMapper;

    @Resource(name = "sqlConvertor")
    private SqlConvertor sqlConvertor;

    @Resource(name = "sqlStorage")
    private SqlStorage sqlStorage;

    @Resource(name = "reportDAO")
    private ReportDAO reportDAO;

    @Resource(name = "reportService")
    private ReportService reportService;

	@Resource(name = "authenticationService")
	private AuthenticationService authenticationService;

    /* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
	ResultSet massRS = null;
	Connection massConnection = null;

	@Autowired
	private KeyedFileLockService keyedFileLockService;
	
	@Autowired
	private QueryResultCacheManager queryResultCacheManager;
	
	@Autowired
	private CacheFileWritingTaskExecutorService cacheFileWritingTaskExecutorService;
	
    @Override
    public void connect(int dataSourceId, String dataSourceType)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException {
		this.dataSourceFactory.getDataSource(dataSourceId, dataSourceType);
    }

    @Override
    public Connection getConnection(int dataSourceId, String dataSourceType)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, SQLException {
        DataSource dataSource = this.dataSourceFactory.getDataSource(dataSourceId, dataSourceType);
        Connection connection = dataSource.getConnection();

        if (connection == null || connection.isClosed()) {
            String dataSetType = this.dataSourceFactory.getDataSourceType(dataSourceId);

            // dataset type을 가져온 후에 제거시켜야 한다.
//            this.dataSourceFactory.removeDataSource(dataSourceId);

            dataSource = this.dataSourceFactory.getDataSource(dataSourceId, dataSetType);

            connection = dataSource.getConnection();
        }

        return connection;
    }

    /* DOGFOOT ktkang KERIS 상세현황 탭일 때 결과 값 자르기  20200123 */
    //KERIS
    @Override
    public CloseableList<JSONObject> querySqlById(int dataSourceId, String dataSourceType, String sqlId, JSONObject params, int sqlTimeout, String queryParam)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        String sql = this.sqlStorage.getSql(sqlId);
        logger.debug("sql(raw) : " + sql);
        return this.querySql(dataSourceId, dataSourceType, sql, params, sqlTimeout, queryParam);
    }

    //ORIGIN
//    @Override
//    public JSONArray querySqlById(int dataSourceId, String dataSourceType, String sqlId, JSONObject params, int sqlTimeout, boolean join)
//    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
//        String sql = this.sqlStorage.getSql(sqlId);
//        logger.debug("sql(raw) : " + sql);
//        return this.querySql(dataSourceId, dataSourceType, sql, params, sqlTimeout, join);
//    }

    @Override
    public CloseableList<JSONObject> queryCountSqlById(int dataSourceId, String dataSourceType, String sqlId, JSONObject params, int sqlTimeout)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        String sql = this.sqlStorage.getSql(sqlId);
        String oriSql = sql;
        sql = sql.toUpperCase();
        /* DOGFOOT ktkang order by 있는 쿼리 오류 수정  20200110 */
        String line = System.getProperty("line.separator");
        oriSql = "SELECT COUNT (*) AS ROW_COUNT FROM (\n"+oriSql+"\n) ABBCCD";
        oriSql = oriSql.replace("\n", line);
        logger.debug("sql(raw) : " + sql);

        /* DOGFOOT ktkang KERIS 상세현황 탭일 때 결과 값 자르기  20200123 */
        //KERIS
        return this.querySql(dataSourceId, dataSourceType, oriSql, params, sqlTimeout, null);
//        ORIGIN
//        return this.querySql(dataSourceId, dataSourceType, oriSql, params, sqlTimeout, false);
    }

    @Override
    public CloseableList<JSONObject> queryCountSql(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        String countSql = sql;
        String oriSql = sql;
        countSql = countSql.toUpperCase();
        String line = System.getProperty("line.separator");
        oriSql = "SELECT COUNT (*) AS ROW_COUNT FROM (\n"+oriSql+"\n) ABBCCD";
        oriSql = oriSql.replace("\n", line);

        logger.debug("sql(raw) : " + oriSql);
        /* DOGFOOT ktkang KERIS 상세현황 탭일 때 결과 값 자르기  20200123 */
//      KERIS
        return this.querySql(dataSourceId, dataSourceType, oriSql, params, sqlTimeout, null);
//      ORIGIN
//        return this.querySql(dataSourceId, dataSourceType, oriSql, params, sqlTimeout, false);

    }

    public JSONObject queryCubeSql2(User sessionUser, int dataSourceId, String dataSourceType,
    		JSONObject params, JSONArray dimensions, JSONArray measures, JSONArray filters,
    		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
    		JSONArray subquery,int sqlTimeout, boolean drillThru, String reportType , String onlyQuery)
    				throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        CubeTableVO vo = new CubeTableVO();
        vo.setCubeId(dataSourceId);
        /* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
        JSONObject ret = null;

        CubeMember cubeInfo = this.reportDAO.selectCubeMasterInformation(dataSourceId);

        List<DataAuthentication> userGroupDataAuthentications = new ArrayList<DataAuthentication>();
        List<DataAuthentication> userDataAuthentications = new ArrayList<DataAuthentication>();

        Map<String, Object> viewRelParam = new HashMap<String, Object>();
        Map<String, Object> colInfoParam = new HashMap<String, Object>();
        viewRelParam.put("cubeId", vo.getCubeId());
        colInfoParam.put("cubeId", vo.getCubeId());

        List<String> meaList = new ArrayList<String>();
        List<String> colList = new ArrayList<String>();

        for (int i = 0; i < dimensions.size(); i++) {
        	JSONObject dim = dimensions.getJSONObject(i);
        	/* DOGFOOT ktkang 주제영역 오류 수정  20200707 */
        	if(dim.has("uid")) {
        		String dimString = dim.get("uid").toString();
        		dimString = dimString.split("\\.")[0];
        		String dimStringReple = dimString.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll("[0-9]", "");
        		if(!meaList.contains(dimStringReple)) {
        			meaList.add(dimStringReple);
        		}

        		if(!colList.contains(dimString)) {
        			colList.add(dimString);
        		}
        	}
        }

        for (int i = 0; i < measures.size(); i++) {
        	JSONObject mea = measures.getJSONObject(i);
        	/* DOGFOOT ktkang 주제영역 오류 수정  20200707 */
        	if(mea.has("uid")) {
        		String meaString = mea.get("uid").toString();
        		meaString = meaString.split("\\.")[0];
        		String meaStringReple = meaString.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll("[0-9]", "");

        		if(!meaList.contains(meaStringReple)) {
        			meaList.add(meaStringReple);
        		}

        		if(!colList.contains(meaString)) {
        			colList.add(meaString);
        		}
        	}
        }
        for (Object key : params.keySet().toArray()) {
        	JSONObject param = params.getJSONObject((String) key);
        	String paramString = null;
        	String paramStringReple = null;
        	if(param.has("cubeUniqueName")) {
        		paramString = param.get("cubeUniqueName").toString();
        		paramString = paramString.split("\\.")[0];
        		paramStringReple = paramString.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll("[0-9]", "");
            	if(!meaList.contains(paramStringReple)) {
            		meaList.add(paramStringReple);
            	}

            	if(!colList.contains(paramString)) {
            		colList.add(paramString);
            	}
        	}
        	if(param.has("uniqueName")) {
        		paramString = param.get("uniqueName").toString();
        		paramString = paramString.split("\\.")[0];
        		paramStringReple = paramString.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll("[0-9]", "");
        		if(!meaList.contains(paramStringReple)) {
            		meaList.add(paramStringReple);
            	}

            	if(!colList.contains(paramString)) {
            		colList.add(paramString);
            	}
        	}
        }

        viewRelParam.put("measures", meaList);
        colInfoParam.put("columns", colList);

        List<CubeTableColumn> columnInfoList = this.reportDAO.selectCubeColumnInfomationList2(colInfoParam);

        QuerySettingEx sqlQenQuery = new QuerySettingEx();
        ArrayList<SelectCube> aDtSel = new ArrayList<SelectCube>();
        ArrayList<Hierarchy> aDtSelHIe = new ArrayList<Hierarchy>();
        ArrayList<SelectCubeMeasure> aDtSelMea = new ArrayList<SelectCubeMeasure>();
        ArrayList<Relation> aDtCubeRel = new ArrayList<Relation>();
        ArrayList<Relation> aDtDsViewRel = new ArrayList<Relation>();
        ArrayList<SelectCubeWhere> aDtWhere = new ArrayList<SelectCubeWhere>();
        List<Object> cubeRelation =this.reportDAO.selectCubeReportTableConstraints2(vo);
        List<Object> dsViewRelation =this.reportDAO.selectViewReportTableConstraints3(viewRelParam);
        /* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
        ArrayList<CubeTableColumn> aDtOrder = new ArrayList<CubeTableColumn>();
        logger.debug("######### dimensions ######### ");

        JSONObject col;
        for (int index = 0; index < dimensions.size(); index++) {
            col = dimensions.getJSONObject(index);

            for(CubeTableColumn column : columnInfoList)
            {

            	if(column.getLogicalColumnName() != null)
            	{
            		/* DOGFOOT ktkang 주제영역 오류 수정  20200707 */
            		/* DOGFOOT ajkim 주제영역 측정값 집계함수 없을 경우 차원으로 처리 20200921*/
            		/*dogfoot 측정값 차원 변경 오라클 오류 수정 shlim 20210329 */
            		if((col.has("uid") 
            				&& col.get("uid").toString().contains(column.getLogicalColumnName().toString()) 
            				&& column.getColumnType().equalsIgnoreCase("dimension"))
            				|| (col.has("uid") 
            				&& col.get("uid").toString().contains(column.getLogicalColumnName().toString()) 
            				&& column.getColumnType().equalsIgnoreCase("measure")
            				&& 
            				(column.getAggregationType() == null 
            				||column.getAggregationType().replaceAll(" ", "").equals(""))
//            				column.getAggregationType().replaceAll(" ", "").equals("")
            				))
                	{
                		SelectCube selCube = new SelectCube();
                		selCube.setUNI_NM(column.getLogicalColumnName());
                		selCube.setCAPTION(column.getColumnCaption());
                		selCube.setDATA_TYPE(column.getDataType());
                		selCube.setORDER(Integer.toString(index));
                		selCube.setTYPE("DIM");
                		boolean duple4 = true;
                		for(SelectCube selectCube : aDtSel) {
                			if(selectCube.getUNI_NM().equals(column.getLogicalColumnName())) {
                				duple4 = false;
                			}
                		}
                		if(duple4) {
                			aDtSel.add(selCube);
                		}

                		Hierarchy selHie = new Hierarchy();

                		selHie.setDIM_UNI_NM(column.getLogicalTableName());
                		selHie.setHIE_UNI_NM(column.getLogicalColumnName());
                		selHie.setHIE_CAPTION(column.getColumnCaption());
                		selHie.setTBL_NM(column.getPhysicalTableName().trim());
                		selHie.setCOL_NM(column.getPhysicalColumnName().trim());
                		if(selHie.getCOL_NM().equals(""))
                			selHie.setCOL_NM(column.getPhysicalColumnKey());
                		selHie.setCOL_EXPRESS(column.getExpression());
                		boolean duple5 = true;
                		for(Hierarchy selectHie : aDtSelHIe) {
                			if(selectHie.getHIE_UNI_NM().equals(column.getLogicalColumnName()) && selectHie.getDIM_UNI_NM().equals(column.getLogicalTableName())) {
                				duple5 = false;
                			}
                		}
                		if(duple5) {
                			aDtSelHIe.add(selHie);
                		}
                		
                		if(column.getOrderBy().trim().equalsIgnoreCase("Key Column"))
                		{
                			if(!column.getPhysicalColumnName().contains(column.getPhysicalColumnKey()))
                			{
                				selHie = new Hierarchy();

                        		selHie.setDIM_UNI_NM(column.getLogicalTableName());
                        		selHie.setHIE_UNI_NM(column.getLogicalColumnName());
                        		selHie.setHIE_CAPTION(column.getColumnCaption());
//                        		selHie.setHIE_CAPTION(column.getColumnCaption() + "_K");
                        		selHie.setTBL_NM(column.getPhysicalTableName());
                        		selHie.setCOL_NM(column.getPhysicalColumnKey());
                        		selHie.setCOL_EXPRESS(column.getExpression());
                        		aDtSelHIe.add(selHie);
                			}
                		/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
                		} else if(!column.getOrderBy().trim().equalsIgnoreCase("Name Column") && !column.getOrderBy().trim().equalsIgnoreCase("")) {
                			for(CubeTableColumn orderColumn : columnInfoList) {
                				if(column.getOrderBy().trim().equalsIgnoreCase(orderColumn.getPhysicalColumnName().trim()) && column.getLogicalTableName().equalsIgnoreCase(orderColumn.getLogicalTableName())) {
                					SelectCube selCubeOrder = new SelectCube();
                					selCubeOrder.setUNI_NM(orderColumn.getLogicalColumnName());
                					selCubeOrder.setCAPTION(orderColumn.getColumnCaption());
                            		selCubeOrder.setDATA_TYPE(orderColumn.getDataType());
                            		selCubeOrder.setORDER(Integer.toString(index));
                            		selCubeOrder.setTYPE("DIM");
                            		boolean duple = true;
                            		for(SelectCube selectCube : aDtSel) {
                            			if(selectCube.getUNI_NM().equals(orderColumn.getLogicalColumnName())) {
                            				duple = false;
                            			}
                            		}
                            		if(duple) {
                            			aDtSel.add(selCubeOrder);
                            		}
                            		
                            		if(col.has("uniqueName")) {
                            			column.setUniqueName(col.get("uniqueName").toString());
                            		}
                            		column.setOrderByCaption(orderColumn.getColumnCaption());
                            		
                            		boolean duple2 = true;
                            		for(CubeTableColumn selectOrder : aDtOrder) {
                            			if(selectOrder.getLogicalColumnName().equals(orderColumn.getLogicalColumnName()) && selectOrder.getLogicalTableName().equals(orderColumn.getLogicalTableName())) {
                            				duple2 = false;
                            			}
                            		}
                            		if(duple2) {
                            			aDtOrder.add(column);
                            		}
                            		
                            		selHie = new Hierarchy();
                            		selHie.setDIM_UNI_NM(orderColumn.getLogicalTableName());
                            		selHie.setHIE_UNI_NM(orderColumn.getLogicalColumnName());
                            		selHie.setHIE_CAPTION(orderColumn.getColumnCaption());
//                            		selHie.setHIE_CAPTION(column.getColumnCaption() + "_K");
                            		selHie.setTBL_NM(orderColumn.getPhysicalTableName());
                            		selHie.setCOL_NM(orderColumn.getPhysicalColumnKey());
                            		selHie.setCOL_EXPRESS(orderColumn.getExpression());
                            		
                            		boolean duple3 = true;
                            		for(Hierarchy selectHie : aDtSelHIe) {
                            			if(selectHie.getHIE_UNI_NM().equals(orderColumn.getLogicalColumnName()) && selectHie.getDIM_UNI_NM().equals(orderColumn.getLogicalTableName())) {
                            				duple3 = false;
                            			}
                            		}
                            		if(duple3) {
                            			aDtSelHIe.add(selHie);
                            		}
                				}
                			}
                		}
                		break;
                	}
            	}

            }
        }

        logger.debug("######### measures ######### ");
        for (int index = 0; index < measures.size(); index++) {
            col = measures.getJSONObject(index);

            for(CubeTableColumn column : columnInfoList)
            {
            	if(column.getLogicalColumnName() != null)
            	{
            		/* DOGFOOT ktkang 주제영역 오류 수정  20200707 */
            		if(col.has("uid") && col.get("uid").toString().contains(column.getLogicalColumnName()) && column.getColumnType().equalsIgnoreCase("measure"))
	            	{
	            		SelectCube selCube = new SelectCube();
	            		selCube.setUNI_NM(column.getLogicalColumnName());
	            		selCube.setCAPTION(column.getColumnCaption());
	            		selCube.setDATA_TYPE(column.getDataType());
	            		selCube.setORDER(Integer.toString(index));
	            		selCube.setTYPE("MEA");
	            		aDtSel.add(selCube);

	            		SelectCubeMeasure selMea = new SelectCubeMeasure();

	            		selMea.setMEA_GRP_UNI_NM(column.getLogicalTableName());
	            		selMea.setMEA_UNI_NM(column.getLogicalColumnName());
	            		selMea.setMEA_CAPTION(column.getColumnCaption());
	            		selMea.setMEA_TBL_NM(column.getPhysicalTableName());
	            		selMea.setMEA_COL_NM(column.getPhysicalColumnKey());
	            		selMea.setMEA_AGG(column.getAggregationType());
	            		selMea.setCOL_EXPRESS(column.getExpression());
	            		aDtSelMea.add(selMea);
	            	}
            	}
            }

        }

        /*ReportMasterVO param = new ReportMasterVO();
        param.setId(dataSourceId);
        param.setType("AdHoc");

        ReportMasterVO ret;
        try {
            ret = this.reportDAO.select(param);
        }
        catch (Exception e) {
            if (e.getMessage().indexOf("Could not set property 'layoutXmlBase64'") > -1) {
                logger.error("COULD NOT FIND REPORT META XML FROM DATABASE",e);
                throw new NotFoundReportXmlException();
            }
            else {
                throw e;
            }
        }

        if (ret == null) {
            throw new UnRegisterdReportException();
        }

        this.xml2Json.setReportMasterVo(ret);
        JSONObject reportMeta = this.xml2Json.parseJSON();

        JSONArray parameterInfos = reportMeta.getJSONObject("ReportMasterInfo").getJSONObject("dataSource").getJSONArray("parameters");
        */
        JSONObject subqueryMeta;
        logger.debug("######### subqueryMeta ######### ");
        if(subquery == null) {
        } else if(subquery.getJSONObject(0).size() > 0)
        {
        	subqueryMeta = (JSONObject) subquery.getJSONObject(0).get("SUB_QUERY");

            String query = (String) subqueryMeta.get("QUERY");
            String subHieUniNm = (String) subqueryMeta.get("HIE_UNI_NM");

            if (!query.equals(""))
            {
            	 ArrayList<String> chkParamList = new ArrayList<String>();

            	for(CubeTableColumn column : columnInfoList)
                {
                	if(column.getLogicalColumnName() != null)
                	{
                		if(subHieUniNm.contains(column.getLogicalColumnName()))
    	            	{

                			if(!chkParamList.contains(subHieUniNm))
                			{
                				SelectCubeWhere whereCube = new SelectCubeWhere();
        	            		whereCube.setPARENT_UNI_NM(column.getLogicalTableName());
        	            		whereCube.setUNI_NM(subHieUniNm);
        	            		whereCube.setCAPTION(column.getColumnCaption());
        	            		whereCube.setOPER("In");
        	            		whereCube.setVALUES("#SUB_QUERY#");
        	            		whereCube.setVALUES_CAPTION(query);
        	            		whereCube.setAGG("");
        	            		whereCube.setDATA_TYPE(column.getDataType());
        	            		whereCube.setPARAM_YN("False");
        	            		whereCube.setPARAM_NM("");
        	            		whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
        	            		whereCube.setORDER("0");
        	            		whereCube.setTBL_NM(column.getPhysicalTableName());
        	            		whereCube.setCOL_NM(column.getPhysicalColumnKey());
        	            		whereCube.setLOGIC("");
        	            		whereCube.setCOL_EXPRESS("");
        	            		whereCube.setWHERE_CLAUSE("");
        	            		whereCube.setCOND_ID("");

        	            		aDtWhere.add(whereCube);
                			}

    	            	}
                	}
                }
            }
        }

        ArrayList<String> chkParamList = new ArrayList<String>();
        JSONObject filter;
        if (filters == null) filters = new JSONArray();
        logger.debug("######### params ######### ");
        for (Object key : params.keySet().toArray()) {
        	filter = params.getJSONObject((String) key);
        	logger.debug(filter.toString());
        	for(CubeTableColumn column : columnInfoList)
            {
            	if(column.getLogicalColumnName() != null)
            	{
            		/* DOGFOOT ktkang 주제영역 필터 오류 수정  20201201 */
            		if(reportType.equals("AdHoc")) {
            			if(filter.get("cubeUniqueName") != null && filter.get("cubeUniqueName").toString().contains(column.getLogicalColumnName())
            					|| (filter.get("cubeUniqueName") != null && filter.get("cubeUniqueName").toString().contains("[" + column.getLogicalTableName() + "].[" + column.getPhysicalColumnKey() + "]"))) {
            				if(!chkParamList.contains(filter.get("uniqueName").toString()))
            				{
            					SelectCubeWhere whereCube = new SelectCubeWhere();
            					whereCube.setPARENT_UNI_NM(column.getLogicalTableName());
            					whereCube.setUNI_NM(filter.get("cubeUniqueName").toString());
            					whereCube.setCAPTION(filter.get("name").toString());
            					whereCube.setOPER(filter.get("parameterType").toString());
            					whereCube.setOPERATION(filter.get("operation").toString());
            					whereCube.setVALUES(filter.get("value").toString().replaceAll("\"", ""));
            					whereCube.setVALUES_CAPTION("");
            					whereCube.setAGG("");
            					whereCube.setDATA_TYPE(column.getDataType());
            					//    	            		whereCube.setDATA_TYPE(filter.get("type").toString());
            					//    	            		whereCube.setOPERATON(filter.getString("oper").toString());
            					whereCube.setPARAM_YN("False");
            					whereCube.setPARAM_NM("");
            					whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
            					whereCube.setORDER("0");
            					/* DOGFOOT ktkang 주제영역 속도개선 오류 수정  20200310 */
            					String cubeUniqueName = filter.get("cubeUniqueName").toString();
            					cubeUniqueName = cubeUniqueName.split("\\.")[0];
            					/*dogfoot 주제영역 테이블 복사후 필터 올릴시 join 오류 수정 shlim 20210408*/
            					whereCube.setTBL_NM(column.getPhysicalTableName());
//            					whereCube.setTBL_NM(cubeUniqueName.replaceAll("\\[", "").replaceAll("\\]", ""));
            					if(drillThru) {
            						String uniName = filter.get("cubeUniqueName").toString();
            						String[] colName = uniName.split("\\.");
            						whereCube.setCOL_NM(colName[1]);
            					} else {
            						whereCube.setCOL_NM(column.getPhysicalColumnKey());
            					}
            					whereCube.setLOGIC("");
            					whereCube.setCOL_EXPRESS("");
            					whereCube.setWHERE_CLAUSE(filter.get("whereClause").toString() + "");
            					whereCube.setCOND_ID("");
            					/*dogfoot 주제영역 계산된 컬럼 필터 추가시 치환 기능 추가 shlim 20210408*/
            					if(column.getExpression() != null) {
            						whereCube.setCOL_EXPRESS(column.getExpression());
            					}
            					aDtWhere.add(whereCube);

            				}

            				chkParamList.add(filter.get("uniqueName").toString());
            			}
            			else if(filter.get("uniqueName").toString().contains(column.getLogicalColumnName()))
            			{
            				if(!chkParamList.contains(filter.get("uniqueName").toString()))
            				{
            					SelectCubeWhere whereCube = new SelectCubeWhere();
            					whereCube.setPARENT_UNI_NM("[" + column.getPhysicalTableName() + "]");
            					whereCube.setUNI_NM(filter.get("cubeUniqueName").toString());
            					whereCube.setCAPTION(filter.get("name").toString());
            					whereCube.setOPER(filter.get("parameterType").toString());
            					whereCube.setOPERATION(filter.get("operation").toString());
            					whereCube.setVALUES(filter.get("value").toString().replaceAll("\"", ""));
            					whereCube.setVALUES_CAPTION("");
            					whereCube.setAGG("");
            					whereCube.setDATA_TYPE(column.getDataType());
            					//    	            		whereCube.setDATA_TYPE(filter.get("type").toString());
            					//    	            		whereCube.setOPERATON(filter.getString("oper").toString());
            					whereCube.setPARAM_YN("False");
            					whereCube.setPARAM_NM("");
            					whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
            					whereCube.setORDER("0");
            					whereCube.setTBL_NM(column.getPhysicalTableName());
            					if(drillThru) {
            						String uniName = filter.get("cubeUniqueName").toString();
            						String[] colName = uniName.split("\\.");
            						whereCube.setCOL_NM(colName[1]);
            					} else {
            						whereCube.setCOL_NM(column.getPhysicalColumnKey());
            					}
            					whereCube.setLOGIC("");
            					whereCube.setCOL_EXPRESS("");
            					whereCube.setWHERE_CLAUSE(filter.get("whereClause").toString() + "");
            					whereCube.setCOND_ID("");
            					aDtWhere.add(whereCube);

            				}

            				chkParamList.add(filter.get("uniqueName").toString());

            			}
            			/* DOGFOOT ktkang 주제영역 필터 오류 수정  20201201 */
            		} else if(reportType.equals("DashAny")) {
            			if(filter.get("cubeUniqueName") != null && filter.get("cubeUniqueName").toString().contains(column.getLogicalColumnName())
            					|| (filter.get("cubeUniqueName") != null && filter.get("cubeUniqueName").toString().contains("[" + column.getPhysicalTableName() + "].[" + column.getPhysicalColumnKey() + "]"))) {
            				if(!chkParamList.contains(filter.get("uniqueName").toString()))
            				{
            					SelectCubeWhere whereCube = new SelectCubeWhere();
            					/* DOGFOOT ktkang 주제영역 스노우플레이크 오류 수정  20200714 */
            					String tblNm = "";
            					if(column.getDisplayType() != null && column.getDisplayType().equals("SF")) {
            						tblNm = column.getPhysicalTableName();
            					} else {
            						/*dogfoot 주제영역 테이블복사후 필터 올릴시 물리적 테이블 명으로 입력되는 쿼리 오류 수정 shlim 20210325*/
            						if(!(filter.get("cubeUniqueName") != null && filter.get("cubeUniqueName").toString().contains("[" + column.getPhysicalTableName() + "].[" + column.getPhysicalColumnKey() + "]"))) {
            							tblNm = column.getPhysicalTableName();
            						}else {
            							tblNm = column.getLogicalTableName();
            						}
	
            					}
            					whereCube.setPARENT_UNI_NM(column.getLogicalTableName());
            					whereCube.setUNI_NM(filter.get("cubeUniqueName")+"");
            					whereCube.setCAPTION(filter.get("name").toString());
            					whereCube.setOPER(filter.get("parameterType").toString());
            					whereCube.setOPERATION(filter.get("operation").toString());
            					/* DOGFOOT ktkang 대시보드 주제영역 필터 오류 수정  20200708 */
            					whereCube.setVALUES(filter.get("value").toString().replaceAll("\"", ""));
            					whereCube.setVALUES_CAPTION("전체");
            					whereCube.setAGG("");
            					whereCube.setDATA_TYPE(column.getDataType());
            					//    	            		whereCube.setDATA_TYPE(filter.get("type").toString());
            					//    	            		whereCube.setOPERATON(filter.getString("oper").toString());
            					whereCube.setPARAM_YN("False");
            					whereCube.setPARAM_NM("");
            					whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
            					whereCube.setORDER("0");
            					/* DOGFOOT ktkang 주제영역 속도개선 오류 수정  20200310 */
//            					String cubeUniqueName = filter.get("cubeUniqueName").toString();
//            					cubeUniqueName = cubeUniqueName.split("\\.")[0];
            					/*dogfoot shlim 20210419*/
            					whereCube.setTBL_NM(column.getPhysicalTableName());
//            					whereCube.setTBL_NM(tblNm.replaceAll("\\[", "").replaceAll("\\]", ""));
            					if(drillThru) {
            						String uniName = filter.get("cubeUniqueName").toString();
            						String[] colName = uniName.split("\\.");
            						whereCube.setCOL_NM(colName[1]);
            					} else {
            						whereCube.setCOL_NM(column.getPhysicalColumnKey());
            					}
            					whereCube.setLOGIC("");
            					whereCube.setCOL_EXPRESS("");
            					/* DOGFOOT ktkang 대시보드 주제영역 필터 오류 수정  20200708 */
            					whereCube.setWHERE_CLAUSE(filter.get("whereClause").toString() + "");
            					whereCube.setCOND_ID("");
            					aDtWhere.add(whereCube);
            					/*dogfoot 주제영역 테이블복사후 필터 올릴시 물리적 테이블 명으로 입력되는 쿼리 오류 수정 shlim 20210325*/
            					chkParamList.add(filter.get("uniqueName").toString());
            				}
            			}
            			else if(filter.get("uniqueName").toString().contains(column.getLogicalColumnName()))
            			{
            				if(!chkParamList.contains(filter.get("uniqueName").toString()))
            				{
            					SelectCubeWhere whereCube = new SelectCubeWhere();
            					whereCube.setPARENT_UNI_NM("[" + column.getPhysicalTableName() + "]");
            					whereCube.setUNI_NM(filter.get("uniqueName")+"");
            					whereCube.setCAPTION(filter.get("name").toString());
            					whereCube.setOPER(filter.get("parameterType").toString());
            					whereCube.setOPERATION(filter.get("operation").toString());
            					/* DOGFOOT ktkang 대시보드 주제영역 필터 오류 수정  20200708 */
            					whereCube.setVALUES(filter.get("value").toString().replaceAll("\"", ""));
            					whereCube.setVALUES_CAPTION("전체");
            					whereCube.setAGG("");
            					whereCube.setDATA_TYPE(column.getDataType());
            					//    	            		whereCube.setDATA_TYPE(filter.get("type").toString());
            					//    	            		whereCube.setOPERATON(filter.getString("oper").toString());
            					whereCube.setPARAM_YN("False");
            					whereCube.setPARAM_NM("");
            					whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
            					whereCube.setORDER("0");
            					whereCube.setTBL_NM(column.getPhysicalTableName());
            					if(drillThru) {
            						String uniName = filter.get("cubeUniqueName").toString();
            						String[] colName = uniName.split("\\.");
            						whereCube.setCOL_NM(colName[1]);
            					} else {
            						whereCube.setCOL_NM(column.getPhysicalColumnKey());
            					}
            					whereCube.setLOGIC("");
            					whereCube.setCOL_EXPRESS("");
            					/* DOGFOOT ktkang 대시보드 주제영역 필터 오류 수정  20200708 */
            					whereCube.setWHERE_CLAUSE(filter.get("whereClause").toString() + "");
            					whereCube.setCOND_ID("");
            					aDtWhere.add(whereCube);

            				}
            			}
            		}
            	}
            }
        }
        String where="";
    	Map<String,List<String>> usedWhere0 = new HashMap<String,List<String>>();

    	if (userDataAuthentications.size() > 0) {
    		for (DataAuthentication da : userDataAuthentications) {
    			for(CubeTableColumn column : columnInfoList) {
					if(column.getLogicalColumnName() != null) {
						// 2021-03-11 yyb 주제영역 권한처리 수정
    					String strUniqueNm = getUniqNm(da.getLogicalTablenName(), da.getUniqueName());

    					if(column.getLogicalColumnName().equals(strUniqueNm))
        				{
        					if (usedWhere0.containsKey(strUniqueNm)) {
        						((List<String>)usedWhere0.get(strUniqueNm)).add(da.getMemberName());
        					}
        					else {
        						List<String> memberValues = new ArrayList<String>();
                                memberValues.add(da.getMemberName());
                                usedWhere0.put(strUniqueNm, memberValues);
        					}
        				}
					}
    			}
    		}
    	}
    	else {
    		for (DataAuthentication da : userGroupDataAuthentications) {
    			for(CubeTableColumn column : columnInfoList) {
    				if(column.getLogicalColumnName() != null) {
    					// 2021-03-11 yyb 주제영역 권한처리 수정
    					String strUniqueNm = getUniqNm(da.getLogicalTablenName(), da.getUniqueName());

    					if(column.getLogicalColumnName().equals(strUniqueNm))
	    				{
	    					if (usedWhere0.containsKey(strUniqueNm)) {
	    						((List<String>)usedWhere0.get(strUniqueNm)).add(da.getMemberName());
	    					}
	    					else {
	    						List<String> memberValues = new ArrayList<String>();
	                            memberValues.add(da.getMemberName());
	                            usedWhere0.put(strUniqueNm, memberValues);
	    					}
	    				}
    				}
    			}
    		}
    	}


//        ArrayList<JSONObject> groupParamList = new  ArrayList<JSONObject>();
    	if (userDataAuthentications.size() > 0) {
    		for(CubeTableColumn column : columnInfoList)
            {
            	if(column.getLogicalColumnName() != null)
            	{
            		/* DOGFOOT ktkang 주제영역 권한 오류 수정  20200810 */
            		ArrayList<String> uniqueNameList = new ArrayList<String>();
            		for(DataAuthentication da:userDataAuthentications)
            		{
            			// 2021-03-11 yyb 주제영역 권한처리 수정
    					String strUniqueNm = getUniqNm(da.getLogicalTablenName(), da.getUniqueName());

            			if(column.getLogicalColumnName().equals(strUniqueNm) && uniqueNameList.indexOf(strUniqueNm) == -1) {
            				logger.debug("userGroupDataAuthentications 486 : "+column.toString()+"\t"+strUniqueNm+"\t"+column.getLogicalColumnName().equals(strUniqueNm));
            				/* DOGFOOT ktkang 주제영역 권한 쿼리 오류 수정  20200811 */
            				where = "";
            				for (Object un : usedWhere0.keySet().toArray()) {
            					if(column.getLogicalColumnName().equals(un)) {
            						for (String memberValue : (List<String>)usedWhere0.get(un)) {
            							where += "" + memberValue + "";
            							where += ",";
            						}
            						if (where.length() > 0) where = where.substring(0, where.length() - 1);
            						logger.debug("DataAuthentications 510 : "+where);
            					}
            				}

            				SelectCubeWhere whereCube = new SelectCubeWhere();
            				whereCube.setPARENT_UNI_NM("[" + column.getPhysicalTableName() + "]");
            				whereCube.setUNI_NM(column.getLogicalColumnName());
            				whereCube.setCAPTION(column.getColumnCaption());
            				whereCube.setOPER("");
            				whereCube.setVALUES(where);
            				whereCube.setVALUES_CAPTION("");
            				whereCube.setAGG("");
            				whereCube.setDATA_TYPE(column.getDataType());
            				whereCube.setOPERATION("");
            				whereCube.setPARAM_YN("False");
            				whereCube.setPARAM_NM("");
            				whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
            				whereCube.setORDER("0");
            				whereCube.setTBL_NM(column.getPhysicalTableName());
            				whereCube.setCOL_NM(column.getPhysicalColumnKey());
            				whereCube.setLOGIC("");
            				whereCube.setCOL_EXPRESS("");
            				whereCube.setWHERE_CLAUSE("");
            				whereCube.setCOND_ID("");
            				aDtWhere.add(whereCube);
            				uniqueNameList.add(strUniqueNm);
            			}
            		}
            	}
            }
    	}
    	else {
    		for(CubeTableColumn column : columnInfoList)
    		{
    			if(column.getLogicalColumnName() != null)
    			{
    				ArrayList<String> uniqueNameList = new ArrayList<String>();
    				for(DataAuthentication da:userGroupDataAuthentications)
    				{
    					// 2021-03-11 yyb 주제영역 권한처리 수정
    					String strUniqueNm = getUniqNm(da.getLogicalTablenName(), da.getUniqueName());

    					if(column.getLogicalColumnName().equals(strUniqueNm) && uniqueNameList.indexOf(strUniqueNm) == -1) {
    						logger.debug("userGroupDataAuthentications 486 : "+column.toString()+"\t"+strUniqueNm+"\t"+column.getLogicalColumnName().equals(strUniqueNm));
    						/* DOGFOOT ktkang 주제영역 권한 쿼리 오류 수정  20200811 */
    						where = "";
    						for (Object un : usedWhere0.keySet().toArray()) {
            					if(column.getLogicalColumnName().equals(un)) {
            						for (String memberValue : (List<String>)usedWhere0.get(un)) {
            							where += "" + memberValue + "";
            							where += ",";
            						}
            						if (where.length() > 0) where = where.substring(0, where.length() - 1);
            						logger.debug("DataAuthentications 510 : "+where);
            					}
            				}

    						SelectCubeWhere whereCube = new SelectCubeWhere();
    						whereCube.setPARENT_UNI_NM("[" + column.getPhysicalTableName() + "]");
    						whereCube.setUNI_NM(column.getLogicalColumnName());
    						whereCube.setCAPTION(column.getColumnCaption());
    						whereCube.setOPER("");
    						whereCube.setVALUES(where);
    						whereCube.setVALUES_CAPTION("");
    						whereCube.setAGG("");
    						whereCube.setDATA_TYPE(column.getDataType());
    						whereCube.setOPERATION("");
    						whereCube.setPARAM_YN("False");
    						whereCube.setPARAM_NM("");
    						whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
    						whereCube.setORDER("0");
    						whereCube.setTBL_NM(column.getPhysicalTableName());
    						whereCube.setCOL_NM(column.getPhysicalColumnKey());
    						whereCube.setLOGIC("");
    						whereCube.setCOL_EXPRESS("");
    						whereCube.setWHERE_CLAUSE("");
    						whereCube.setCOND_ID("");
    						aDtWhere.add(whereCube);
    						uniqueNameList.add(strUniqueNm);
    					}
    				}
    			}
    		}
    	}


        logger.debug("######### filters #########");
//        System.out.println(filters.toString());
        for (int index = 0; index < filters.size(); index++) {
            filter = filters.getJSONObject(index);

//            System.out.println(filter.toString());
            if(!filter.toString().equals("{}")) {
            	for(CubeTableColumn column : columnInfoList)
                {
                	if(column.getLogicalColumnName() != null)
                	{
                		if(filter.get("UNI_NM").toString().contains(column.getLogicalColumnName()))
    	            	{
                			if(!chkParamList.contains(filter.get("UNI_NM").toString()))
                			{
                				SelectCubeWhere whereCube = new SelectCubeWhere();
        	            		whereCube.setPARENT_UNI_NM("[" + column.getPhysicalTableName() + "]");
        	            		whereCube.setUNI_NM(filter.get("UNI_NM").toString());
        	            		whereCube.setVALUES(filter.get("VALUE").toString().replaceAll("\"", ""));
        	            		whereCube.setAGG(filter.get("AGG").toString());
        	            		whereCube.setDATA_TYPE(column.getDataType());
//        	            		whereCube.setOPER("");
        	            		whereCube.setOPER(filter.getString("COND"));
//        	            		whereCube.setDATA_TYPE(filter.get("type").toString());
        	            		whereCube.setOPERATION(filter.getString("COND"));
        	            		whereCube.setPARAM_NM(filter.getString("FLD_NM"));
        	            		whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
        	            		whereCube.setORDER("0");
        	            		whereCube.setTBL_NM(column.getPhysicalTableName());
        	            		whereCube.setCOL_NM(column.getPhysicalColumnKey());
        	            		aDtWhere.add(whereCube);
                			}
    	            		chkParamList.add(filter.get("UNI_NM").toString());

    	            	}
                	}
                }
            }
        }

        logger.debug("######### cubeRelation ######### ");
        for(int i =0; i<cubeRelation.size();i++){
        	/*dogfoot shlim 20210430*/
        	Relation cuberel = (Relation) cubeRelation.get(i);
        	if(cuberel.getJOIN_TYPE() == null) {
        		cuberel.setJOIN_TYPE("INNER JOIN");
        	}
//			HashMap map = (HashMap)cubeRelation.get(i);
//			Relation cuberel = new Relation();
//			
//			cuberel.setDS_ID(Integer.parseInt(map.get("DS_ID").toString()));
//			cuberel.setDS_VIEW_ID(Integer.parseInt(map.get("DS_VIEW_ID").toString()));
//			cuberel.setCUBE_ID(Integer.parseInt(map.get("CUBE_ID").toString()));
//			cuberel.setCONST_NM(map.get("CONST_NM").toString());
//			cuberel.setFK_TBL_NM(map.get("FK_TBL_NM").toString());
//			cuberel.setFK_COL_NM(map.get("FK_COL_NM").toString());
//			cuberel.setPK_TBL_NM(map.get("PK_TBL_NM").toString());
//			cuberel.setPK_COL_NM(map.get("PK_COL_NM").toString());
//			/* DOGFOOT ktkang 주제영역 조인 타입 기본값 INNER JOIN 으로 수정  20200312 */
//			if(map.get("JOIN_TYPE") == null) {
//				cuberel.setJOIN_TYPE("INNER JOIN");
//			} else {
//				cuberel.setJOIN_TYPE(map.get("JOIN_TYPE").toString());
//			}
//			if(map.get("FK_EXPRESS") == null) {
//				cuberel.setFK_EXPRESS("");
//			}else {	
//				cuberel.setFK_EXPRESS(map.get("FK_EXPRESS").toString());
//			}
//			if(map.get("PK_EXPRESS") == null) {
//				cuberel.setPK_EXPRESS("");
//			}else {
//				cuberel.setPK_EXPRESS(map.get("PK_EXPRESS").toString());
//			}
//			cuberel.setJOIN_SET_OWNER(map.get("JOIN_SET_OWNER").toString());
//			cuberel.setREL_CONST_NM(map.get("REL_CONST_NM").toString());
//			cuberel.setDIM_UNI_NM(map.get("DIM_UNI_NM").toString());
//			cuberel.setMEA_GRP_UNI_NM(map.get("MEA_GRP_UNI_NM").toString());
//			cuberel.setMODIFY_TAG("");

			aDtCubeRel.add(cuberel);
		}
        for(Relation cuberel : aDtCubeRel) {
        	for(CubeTableColumn column : columnInfoList) {
        		if(column.getPhysicalColumnName()!=null) {
        			if(column.getPhysicalColumnName().contains("WISE_")) {
        				if(cuberel.getFK_COL_NM().toString().equals(column.getPhysicalColumnName().trim())) {
            				cuberel.setEXPRESSION(column.getExpression());
            				break;
            			}
            			else if(cuberel.getPK_COL_NM().toString().equals(column.getPhysicalColumnName().trim())) {
            				cuberel.setEXPRESSION(column.getExpression());
            				break;
            			}
        			}
        		}
        	}
        }
        logger.debug("######### dsViewRelation ######### ");
        for(int i =0; i<dsViewRelation.size();i++){
			HashMap map = (HashMap)dsViewRelation.get(i);
			Relation cuberel = new Relation();

			cuberel.setDS_ID(Integer.parseInt(map.get("DS_ID").toString()));
			cuberel.setDS_VIEW_ID(Integer.parseInt(map.get("DS_VIEW_ID").toString()));
			cuberel.setFK_TBL_NM(map.get("FK_TBL_NM").toString());
			cuberel.setFK_COL_NM(map.get("FK_COL_NM").toString());
			cuberel.setPK_TBL_NM(map.get("PK_TBL_NM").toString());
			cuberel.setPK_COL_NM(map.get("PK_COL_NM").toString());
			/* DOGFOOT ktkang 주제영역 조인 없을 때 기본 값 추가  20200401 */
			if(map.get("JOIN_TYPE") == null) {
				cuberel.setJOIN_TYPE("INNER JOIN");
			} else {
				cuberel.setJOIN_TYPE(map.get("JOIN_TYPE").toString());
			}
			cuberel.setJOIN_SET_OWNER(map.get("JOIN_SET_OWNER").toString());
			cuberel.setMODIFY_TAG(map.get("MODIFY_TAG").toString());
			cuberel.setCONST_NM(map.get("CONST_NM").toString());
			aDtDsViewRel.add(cuberel);
		}
        String sql2 = null;

        logger.debug("######### CubeQuerySetting ######### ");
        //2020.12.07 MKSONG MARIADB 오류  DOGFOOT
//        sql2 = sqlQenQuery.CubeQuerySetting(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, new ArrayList<SelectCubeOrder> (), "MARIA", aDtCubeRel, aDtDsViewRel, new ArrayList<SelectCubeEtc>());
        sql2 = sqlQenQuery.CubeQuerySetting(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, new ArrayList<SelectCubeOrder> (), "DB2", aDtCubeRel, aDtDsViewRel, new ArrayList<SelectCubeEtc>());
        String sql = null;

        /* validate sql */
     /*   try {
        	sqlGenerator.generate(true);
            sql = sqlGenerator.getSql();
            this.querySql(dataSourceId, dataSourceType, sql, params);
        }
        catch (Exception  e) {
        	logger.error("", e);
        	throw new CubeSqlValidationException(e);
        }
        finally {
            sqlGenerator.initCheckJoin();
        }*/

        if(reportType.equals("StaticAnalysis")) {
        	sql2 = sql2.replaceAll("Sum", "");
        }
        /* excute sql */
       /* sqlGenerator.generate();
        sql = sqlGenerator.getSql();*/
//        logger.debug("sql(raw-cube) : " +sql2);
        ret = this.querySql2(dataSourceId, dataSourceType, sql2, params,sqlTimeout, drillThru, onlyQuery);
        /* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
        ret.put("order_Key", aDtOrder);
		return ret;
    }

    @Override
    public JSONObject queryDatasetCubeSql(User sessionUser, int dataSourceId,
    		String dataSourceType, JSONObject params, String sql,
    		JSONArray filters, String subquery, JSONObject subtarget)
    				throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        Connection connection = null;
        PreparedStatement pstmt = null;
        ResultSet resultSet = null;

        JSONObject ret = null;

        logger.debug("sql(raw in querySql) : " + sql);

        try {
            if (DataSetConst.DataSetType.DS.equals(dataSourceType) || DataSetConst.DataSetType.VIEW.equals(dataSourceType)) {
                List<CubeTableColumn> columnInformations = this.reportDAO.selectDsViewColumnInformationList(dataSourceId);
                sql = this.sqlConvertor.convertColumnToExpression(sql, columnInformations);
            }
            logger.debug("sql(raw converted expression) : " + sql);


            //////////////////////////////////////////////////////////////////////////
            // for DB2BLU
            sql = sql.replaceAll("\\[", "").replaceAll("\\]", "");
            logger.debug("sql(DB2BLU) : " + sql);
            ////////////////////////////////////////////////////////////////////////////


            /**
             * sql mapper 생성 및 활용해야 할 부분
             * - client에서 전달받온 parameter를 name과 type을 이용하여 sql에 value를  mapping
             */
//            System.out.println(params.toString());
            sql = this.sqlMapper.mapParameter(sql, params);
            logger.debug("sql(param) : " + sql);

            sql = this.sqlConvertor.insertSubquery(sql, subquery, subtarget);

            sql = this.sqlConvertor.convert(sql);
            logger.debug("sql(converted) : " + sql);


            connection = this.getConnection(dataSourceId, dataSourceType);
            pstmt = connection.prepareStatement(sql);

            Timer timer1 = new Timer();
            timer1.start();
//            pstmt.setQueryTimeout(sqlTimeout);
            resultSet = pstmt.executeQuery();
            timer1.stop();

            logger.debug("query timeout : "+ pstmt.getQueryTimeout());

            Timer timer2 = new Timer();
            timer2.start();

            boolean checker = true;
            ResultSetMetaData md = resultSet.getMetaData();
            Map<String,Object> meta = new LinkedHashMap<String,Object>();
            FileBackedJSONObjectList result = new FileBackedJSONObjectList();
            while (resultSet.next()) {
                JSONObject row = new JSONObject();

                if (checker) {
                    for (int i = 1; i <= md.getColumnCount(); i++) {
                        Map<String,Object> m0 = new LinkedHashMap<String,Object>();
                        m0.put("name", md.getColumnLabel(i));
                        m0.put("type", md.getColumnTypeName(i));
                        meta.put(md.getColumnLabel(i), m0);
                    }
                }
                checker = false;

                for (int i = 1; i <= md.getColumnCount(); i++) {
                    DataField field =  new DataField(i, md, resultSet.getObject(i));
                    row.put(md.getColumnLabel(i), JavaxtUtils.getValue(field));
                }
//                if(sqlTimeout != 0 && sqlTimeout <= looptimer.getInterval("3"))
//                	throw new SQLTimeoutException();
                result.add(row);
            }
            timer2.stop();

            Timer timer3 = new Timer();
            timer3.start();

            ret = new JSONObject();
            ret.put("meta", meta);
            ret.put("data", result);
            ret.put("sql", sql);
            timer3.stop();

            logger.debug("queried count : " + ret.size());
            logger.debug("sql quering time : " + timer1.getInterval());
            logger.debug("result loop time : " + timer2.getInterval());
            logger.debug("convert result to json time: " + timer3.getInterval());
        } catch (SQLException e) {
        	e.printStackTrace();
        	throw e;
        } finally {
        	if (pstmt != null) {
            	try {
            		pstmt.close();
            	} catch (SQLException e) {
            		e.printStackTrace();
            		pstmt = null;
            	}
            }
            if (resultSet != null) {
            	try {
            		resultSet.close();
            	} catch (SQLException e) {
            		e.printStackTrace();
            		resultSet = null;
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

        return ret;
    }

    @Override
    public JSONObject querySql2(int dataSourceId, String dataSourceType, String sql, JSONObject params,int sqlTimeout, boolean drillThru, String onlyQuery)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        /* DOGFOOT ktkang 작업 취소 기능 구현  20200923 */
    	Connection connection = null;
    	PreparedStatement pstmt = null;
        ResultSet resultSet = null;

        JSONObject ret = null;

        logger.debug("sql(raw in querySql) : " + sql);

        try {
            if (DataSetConst.DataSetType.DS.equals(dataSourceType) || DataSetConst.DataSetType.VIEW.equals(dataSourceType)) {
                List<CubeTableColumn> columnInformations = this.reportDAO.selectDsViewColumnInformationList(dataSourceId);
                sql = this.sqlConvertor.convertColumnToExpression(sql, columnInformations);
            }
            logger.debug("sql(raw converted expression) : " + sql);


            //////////////////////////////////////////////////////////////////////////
            // for DB2BLU
            sql = sql.replaceAll("\\[", "").replaceAll("\\]", "");
            logger.debug("sql(DB2BLU) : " + sql);
            ////////////////////////////////////////////////////////////////////////////


            /**
             * sql mapper 생성 및 활용해야 할 부분
             * - client에서 전달받온 parameter를 name과 type을 이용하여 sql에 value를  mapping
             */
//            System.out.println(params.toString());
            sql = this.sqlMapper.mapParameter(sql, params);
            logger.debug("sql(param) : " + sql);

            sql = this.sqlConvertor.convert(sql);
            logger.debug("sql(converted) : " + sql);


            connection = this.getConnection(dataSourceId, dataSourceType);

            String databaseProductName = connection.getMetaData().getDatabaseProductName();
            if(databaseProductName.equals("Impala")) {
            	sql = sql.replaceAll("\"", "");
            }
            
            /*dogfoot 비정형 주제영역 데이터 안가져오도록 수정 shlim 20210728*/
            DataSetMasterVO dataSetMaster = null;
	        if (DataSetConst.DataSetType.DS.equals(dataSourceType) || DataSetConst.DataSetType.DS_SQL.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetMaster(dataSourceId);
	        }
	        else if (DataSetConst.DataSetType.VIEW.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetViewMaster(dataSourceId);
	        }
	        else if (DataSetConst.DataSetType.CUBE.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectCubeMaster(dataSourceId);
	        }

	        if(drillThru) {
	        	String countSql = this.sqlConvertor.convertTopN(sql, dataSetMaster.getDatabaseType(), 10000);
	            pstmt = connection.prepareStatement(countSql);
	        } else {
//	        	String countSql = this.sqlConvertor.convertTopN(sql, dataSetMaster.getDatabaseType(), 1);
//	            pstmt = connection.prepareStatement(countSql);
	        }
	        
            ret = new JSONObject();
            
	        if(!"true".equalsIgnoreCase(onlyQuery)) {
	        	Timer timer1 = new Timer();
	            timer1.start();
	            if(drillThru) {
	            	pstmt.setQueryTimeout(sqlTimeout);
		            resultSet = pstmt.executeQuery();
		            timer1.stop();

		            logger.debug("query timeout : "+ pstmt.getQueryTimeout());

		            Timer timer2 = new Timer();
		            timer2.start();

		            int rowCount = 0;
		            boolean checker = true;
		            ResultSetMetaData md = resultSet.getMetaData();
		            Map<String,Object> meta = new LinkedHashMap<String,Object>();
		            List<Map<String,Object>> result = null;
		            if(drillThru) {
		            	result = new ArrayList<Map<String,Object>>();
		            }
		            int count = 0;
		            while (resultSet.next()) {
		            	++rowCount;
		            	Map<String,Object> row = null;
		            	if(drillThru) {
		            		row = new LinkedHashMap<String,Object>();
		            	}
	
		                if (checker) {
		                    for (int i = 1; i <= md.getColumnCount(); i++) {
		                        Map<String,Object> m0 = new LinkedHashMap<String,Object>();
		                        m0.put("name", md.getColumnLabel(i));
		                        m0.put("type", md.getColumnTypeName(i));
		                        meta.put(md.getColumnLabel(i), m0);
		                    }
		                }
		                checker = false;
	
		                if(drillThru) {
		                	for (int i = 1; i <= md.getColumnCount(); i++) {
		                		DataField field =  new DataField(i, md, resultSet.getObject(i));
		                		row.put(md.getColumnLabel(i), JavaxtUtils.getValue(field));
		                	}
		                	result.add(row);
		                }
		                
		                if(++count%1000 == 0) {
		                	ServiceTimeoutUtils.checkServiceTimeout();
		                }
		            }
		            timer2.stop();
		            
		            logger.debug("result loop time : " + timer2.getInterval());
		            
		            ret.put("meta", meta);
		            /*dogfoot 비정형 주제영역 데이터 안가져오도록 수정 shlim 20210728*/
		            if(drillThru) {
		            	ret.put("data", result);
		            }
		            ret.put("dataLength", rowCount);
	            }
	            

	            Timer timer3 = new Timer();
	            timer3.start();

	            /* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
	            ret.put("sql", Base64.encode(sql.getBytes()));
	            timer3.stop();

	            logger.debug("queried count : " + ret.size());
	            logger.debug("sql quering time : " + timer1.getInterval());
	            logger.debug("convert result to json time: " + timer3.getInterval());
	        }else {
	        	ret = new JSONObject();
	        	ret.put("sql", Base64.encode(sql.getBytes()));
	            /* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
	            
	        }
            
        } catch (SQLException e) {
        	e.printStackTrace();
        	throw e;
        } finally {
        	if (pstmt != null) {
        		try {
        			pstmt.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		pstmt = null;
             	}
        	}
        	if (resultSet != null) {
        		try {
             		resultSet.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		resultSet = null;
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

        return ret;
    }

    /* DOGFOOT ktkang KERIS 상세현황 탭일 때 결과 값 자르기  20200123 */
//  KERIS
    @Override
    public CloseableList<JSONObject> querySql(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout, String queryParam)
//    ORIGIN
    //    public JSONArray querySql(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout, boolean join)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
    	/* DOGFOOT ktkang 작업 취소 기능 구현  20200923 */
    	Connection connection = null;
    	PreparedStatement pstmt = null;
        ResultSet resultSet = null;

        JSONArray ret = null;
        CloseableList<JSONObject> result = new FileBackedJSONObjectList();

        try {
            /**
             * sql mapper 생성 및 활용해야 할 부분
             * - client에서 전달받온 parameter를 name과 type을 이용하여 sql에 value를  mapping
             */
            sql = this.sqlMapper.mapParameter(sql, params);
            logger.debug("sql(param) : " + sql);

            sql = this.sqlConvertor.convert(sql);
            logger.debug("sql(converted) : " + sql);

            /* DOGFOOT ktkang KERIS 상세현황 탭일 때 결과 값 자르기  20200123 */
            //KERIS
            if(queryParam != null && queryParam.equals("nullData")) {
            	sql = sql.replaceAll("RIGHT OUTER", "INNER");
            } else if(queryParam != null && queryParam.equals("dataCut")) {
//            	 String line = System.getProperty("line.separator");
//            	 sql = "SELECT * FROM (\n"+sql+"\n) WHERE ROWNUM <= 65000";
//            	 sql = sql.replace("\n", line);
            }

            //ORIGIN
//            if(join) {
//            	sql = sql.replaceAll("RIGHT OUTER", "INNER");
//            }

            connection = this.getConnection(dataSourceId, dataSourceType);
            pstmt = connection.prepareStatement(sql);

            Timer timer1 = new Timer();
            timer1.start();

            if(sqlTimeout > 0) {
            	pstmt.setQueryTimeout(sqlTimeout);
            }
            if(pstmt != null) {
            	resultSet = pstmt.executeQuery();
            } else {
            	resultSet = null;
            }
            timer1.stop();

            Timer timer2 = new Timer();
            timer2.start();

            ResultSetMetaData md = resultSet.getMetaData();
            int count = 0;
            while (resultSet.next()) {
            	JSONObject row = new JSONObject();

                for (int i = 1; i <= md.getColumnCount(); i++) {
                    DataField field =  new DataField(i, md, resultSet.getObject(i));

                    row.put(md.getColumnLabel(i), JavaxtUtils.getValue(field));
//                    row.put(md.getColumnName(i), JavaxtUtils.getValue(field));
//                    if (field.getValue().isNull()) {
////                        row.put(md.getColumnName(i), null);
//                    }
//                    else {
//                        row.put(md.getColumnName(i), field.getValue().toObject());
//                    }
                }

                result.add(row);
                
                if(++count%1000 == 0) {
                	ServiceTimeoutUtils.checkServiceTimeout();
                }
            }
            timer2.stop();
        	if(ret != null) {
        	    logger.debug("queried count : " + ret.size());
        	}
           
            logger.debug("sql quering time : " + timer1.getInterval());
            logger.debug("result loop time : " + timer2.getInterval());
        } catch (SQLException e) {
        	e.printStackTrace();
        	throw e;
        } finally {
        	if (pstmt != null) {
        		try {
        			pstmt.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		pstmt = null;
             	}
        	}
        	if (resultSet != null) {
        		try {
             		resultSet.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		resultSet = null;
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

        return result;
    }

    public CloseableList<JSONObject> sparkSql(ArrayList<Integer> dsid, ArrayList<String> tblnm, String dataSourceType, String sql, JSONObject params, int sqlTimeout, String queryParam)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
    	CloseableList<JSONObject> ret = null;

        try {
            sql = this.sqlMapper.mapParameter(sql, params);
            logger.debug("sql(param) : " + sql);

            sql = this.sqlConvertor.convert(sql);
            logger.debug("sql(converted) : " + sql);

            if(queryParam != null && queryParam.equals("nullData")) {
            	sql = sql.replaceAll("RIGHT OUTER", "INNER");
            }

            Dataset<org.apache.spark.sql.Row> dfRes = sparkExec(dsid, tblnm, sql);

			ret = new FileBackedJSONObjectList();
			for(String str:dfRes.toJSON().collectAsList()) {
				ret.add(JSONObject.fromObject(JSONSerializer.toJSON(str)));
			}
        } catch (Exception e) {
        	e.printStackTrace();
        	throw e;
    	}

        return ret;
    }


    @Override
    public CloseableList<JSONObject> directQuerySql(int dataSourceId, String dataSourceType, String sql, JSONObject params)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        Connection connection = null;
        PreparedStatement pstmt = null;
        ResultSet resultSet = null;

        CloseableList<JSONObject> result = new FileBackedJSONObjectList();

        try {
            /**
             * sql mapper 생성 및 활용해야 할 부분
             * - client에서 전달받온 parameter를 name과 type을 이용하여 sql에 value를  mapping
             */

        	sql = this.sqlMapper.mapParameter(sql, params);
            logger.debug("sql(param) : " + sql);
			/* DOGFOOT ktkang 테스트 쿼리보기용 쿼리 수정  20200629 */
            DataSetMasterVO dataSetMaster = null;
	        if (DataSetConst.DataSetType.DS.equals(dataSourceType) || DataSetConst.DataSetType.DS_SQL.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetMaster(dataSourceId);
	        }
	        else if (DataSetConst.DataSetType.VIEW.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetViewMaster(dataSourceId);
	        }
	        else if (DataSetConst.DataSetType.CUBE.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectCubeMaster(dataSourceId);
	        }

	        /* DOGFOOT ktkang DOMO용 주석처리  20210123*/
//	        sql = this.sqlConvertor.convertTopN(sql, dataSetMaster.getDatabaseType(), 100);

            connection = this.getConnection(dataSourceId, dataSourceType);
          //2020.12.07 MKSONG MARIADB 오류  DOGFOOT
            if(dataSetMaster.getDatabaseType().equals("IMPALA") || dataSetMaster.getDatabaseType().equals("MYSQL") || dataSetMaster.getDatabaseType().equals("MARIA")) {
            	sql = sql.replaceAll("\"", "");
            }
            pstmt = connection.prepareStatement(sql);

            Timer timer1 = new Timer();
            timer1.start();

            resultSet = pstmt.executeQuery();
            timer1.stop();

            Timer timer2 = new Timer();
            timer2.start();

            ResultSetMetaData md = resultSet.getMetaData();
            while (resultSet.next()) {
            	JSONObject row = new JSONObject();

                for (int i = 1; i <= md.getColumnCount(); i++) {
                	//컬럼헤더에 빈값이면 오류 표시로
                    if(md.getColumnLabel(i).equals("")) throw new SQLException();

                    DataField field =  new DataField(i, md, resultSet.getObject(i));

                    row.put(md.getColumnLabel(i), JavaxtUtils.getValue(field));
//                    row.put(md.getColumnName(i), JavaxtUtils.getValue(field));
//                    if (field.getValue().isNull()) {
////                        row.put(md.getColumnName(i), null);
//                    }
//                    else {
//                        row.put(md.getColumnName(i), field.getValue().toObject());
//                    }
                }

                result.add(row);
            }
            timer2.stop();

            logger.debug("queried count : " + result.size());
            logger.debug("sql quering time : " + timer1.getInterval());
            logger.debug("result loop time : " + timer2.getInterval());
        } catch (SQLException e) {
        	e.printStackTrace();
        	throw e;
        } finally {
        	if (pstmt != null) {
        		try {
        			pstmt.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		pstmt = null;
             	}
        	}
        	if (resultSet != null) {
        		try {
             		resultSet.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		resultSet = null;
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

        return result;
    }

    public CloseableList<JSONObject> directSparkSql(ArrayList<Integer> dsid, ArrayList<String> tblnm, String dataSourceType, String sql, JSONObject params)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {

    	CloseableList<JSONObject> result = new FileBackedJSONObjectList();

        try {
        	sql = this.sqlMapper.mapParameter(sql, params);

        	Dataset<org.apache.spark.sql.Row> dfRes = sparkExec(dsid, tblnm, sql);

			for(String str:dfRes.toJSON().collectAsList()) {
				result.add(JSONObject.fromObject(JSONSerializer.toJSON(str)));
			}
        } catch (Exception e) {
        	e.printStackTrace();
        	throw e;
    	}

        return result;
    }

    public int getDSIDforLog(int dataSourceId,String dataSourceType){
		return this.dataSourceFactory.getDSInformation(dataSourceId,dataSourceType).getId();
    }

    /* DOGFOOT ktkang 주제영역 권한 추가  20200120 */
    @Override
	public List<SubjectViewMasterVO> selectSubjectUserViewList(String userId) {
		return this.dataSetDAO.selectSubjectUserViewList(userId);
	}

    @Override
	public List<SubjectViewMasterVO> selectSubjectGrpViewList(String userId) {
		return this.dataSetDAO.selectSubjectGrpViewList(userId);
	}

    @Override
	public List<SubjectMasterVO> selectSubjectList() {
		return this.dataSetDAO.selectSubjectList();
	}

    @Override
    public Map<String,List<CubeTableVO>> selectCubeReportTableInfoList(int cubeId,String userId) {

    	long startMili = System.currentTimeMillis();
    	long checkMili = 0;
    	double checkMin = 0;
    	
        Map<String,List<CubeTableVO>> ret = new HashMap<String,List<CubeTableVO>>();

        CubeTableVO param = new CubeTableVO();
        param.setCubeId(cubeId);
        List<CubeTableColumn> levelColumns = this.dataSetDAO.selectCubeColumnLevelInfomations(param);

        /* DOGFOOT ktkang KERIS cube아이디 파라미터로 받아서 주제영역 바로 열도록 하는 부분  20200114 */
        CubeMember cubeInfo = this.reportDAO.selectCubeMasterInformation(cubeId);

        checkMili = System.currentTimeMillis();
        checkMin = (checkMili - (double) startMili) / 1000;
        System.out.println("selectCubeReportTableInfoList user전까지 : " + checkMin + "초");
        startMili = System.currentTimeMillis();
        
        User user = this.authenticationDAO.selectRepositoryUserByUserId(userId);
        
        checkMili = System.currentTimeMillis();
        checkMin = (checkMili - (double) startMili) / 1000;
        System.out.println("selectCubeReportTableInfoList user후 권한체크 : " + checkMin + "초");
        startMili = System.currentTimeMillis();

        List<CubeTableVO> dimensions = this.dataSetDAO.selectCubeReportDimensionTableList(cubeId);
        
        checkMili = System.currentTimeMillis();
        checkMin = (checkMili - (double) startMili) / 1000;
        System.out.println("selectCubeReportTableInfoList 차원 부분1 : " + checkMin + "초");
        startMili = System.currentTimeMillis();
        
        if (dimensions.size() == 0) {
            dimensions = new ArrayList<CubeTableVO>();
        }
        else {
            List<CubeTableColumnVO> cubeTableColumns = this.dataSetDAO.selectCubeReportDimensionTableColumnList(dimensions.get(0));
            for (CubeTableVO cubeTable : dimensions) {
            	/* DOGFOOT hsshim 2020-01-15 주제영역 중복 차원 무시하는 기능 작업 */
            	HashSet<String> uniqueCols = new HashSet<String>();
                for (CubeTableColumnVO cubeTableColumn : cubeTableColumns) {
                    if (cubeTable.getUniqueName().equalsIgnoreCase(cubeTableColumn.getTableName()) && !(uniqueCols.contains(cubeTableColumn.getUniqueName())) ) {
                    	uniqueCols.add(cubeTableColumn.getUniqueName());
                		if (cubeTableColumn.getIsLevelType()) {
                            for (CubeTableColumn levelColumn : levelColumns) {
                        		if (levelColumn.getLogicalColumnName().equals(cubeTableColumn.getUniqueName())) {
                                    cubeTableColumn.addLevelChild(levelColumn.getLevelLogicalColumnName());
                                }
                            }
                        }
                        cubeTable.addColumn(cubeTableColumn);
                    }
                }
                /* DOGFOOT hsshim 2020-01-15 끝 */
            }
        }
        
        checkMili = System.currentTimeMillis();
        checkMin = (checkMili - (double) startMili) / 1000;
        System.out.println("selectCubeReportTableInfoList 차원 부분2 : " + checkMin + "초");
        startMili = System.currentTimeMillis();

        /* DOGFOOT ktkang 주제영역 오류 수정  20201209 */
        List<CubeTableVO> measures = this.dataSetDAO.selectCubeReportMeasureTableList(cubeId);
        
        checkMili = System.currentTimeMillis();
        checkMin = (checkMili - (double) startMili) / 1000;
        System.out.println("selectCubeReportTableInfoList 측정값 부분 : " + checkMin + "초");
        startMili = System.currentTimeMillis();
        if (measures.size() == 0) {
            measures = new ArrayList<CubeTableVO>();
        }
        else {
            List<CubeTableColumnVO> cubeTableColumns = this.dataSetDAO.selectCubeReportMeasureTableColumnList(measures.get(0));
            for (CubeTableVO cubeTable : measures) {
                for (CubeTableColumnVO cubeTableColumn : cubeTableColumns) {
                    if (cubeTable.getUniqueName().equalsIgnoreCase(cubeTableColumn.getTableName())) {
                        cubeTable.addColumn(cubeTableColumn);
                    }
                }
            }
        }
        
        checkMili = System.currentTimeMillis();
        checkMin = (checkMili - (double) startMili) / 1000;
        System.out.println("selectCubeReportTableInfoList 측정값 부분2 : " + checkMin + "초");
        startMili = System.currentTimeMillis();

        ret.put("dimensions", dimensions);
        ret.put("measures", measures);

        return ret;
    }

    @Override
    public int selectCubeIdByDsId(int ds_id) {
    	int dsViewId = this.dataSetDAO.selectDsViewId(ds_id);
//    	return this.dataSetDAO.selectCubeId(dsViewId);
    	return this.dataSetDAO.selectCubeId(dsViewId).get(0).getCUBE_ID();
    }

    public DataSetMasterVO getDataSourceInfo(int dataSourceId,String dataSourceType){
    	return this.dataSourceFactory.getDSInformation(dataSourceId,dataSourceType);
    }

    @Override
	public DataSetInfoMasterVO selectDataSetInfo(int dataSetId) {
		return this.dataSetDAO.selectDataSetInfo(dataSetId);
	}

    @Override
	public List<DataSetInfoMasterVO> selectDataSetInfoList() {
		return this.dataSetDAO.selectDataSetInfoList();
	}

    @Override
	public List<DataSetInfoMasterVO> selectDataSetInfoList(List<String> dsType) {
		return this.dataSetDAO.selectDataSetInfoList(dsType);
	}

	@Override
	public List<FolderMasterVO> selectGrpAuthDataSetFolderList(String userId) {
		return this.dataSetDAO.selectGrpAuthDataSetFolderList(userId);
	}

	@Override
	public List<FolderMasterVO> selectUserAuthDataSetFolderList(String userId) {
		return this.dataSetDAO.selectUserAuthDataSetFolderList(userId);
	}

	@Override
	public FolderMasterVO selectReportFld(String pid, String folderId, String fldType) {
		// TODO Auto-generated method stub
		//나중에 프로시저로 전환하기 위한 메소드
//		Map<String, Comparable> param = new HashMap<String, Comparable>();
		FolderParamVO param = new FolderParamVO();
		param.setP_PARAM(pid);
		param.setFLD_ID(Integer.parseInt(folderId));
//		param.put("P_PARAM", pid);
//		param.put("FLD_ID", folderId);
		/* DOGFOOT ktkang 개인보고서 추가  20200107 */
		if(fldType.equals("MY")) {
			return this.dataSetDAO.selectUSERReportList(param);
		} else {
			return this.dataSetDAO.selectPUBReportList(param);
		}
	}

	@Override
	public List<FolderMasterVO> selectPrivateUserReportFolderList(String userId) {
		return  this.dataSetDAO.selectPrivateUserReportFolderList(userId);
	}

	@Override
	public List<FolderMasterVO> selectGrpReportFolderList(String userId) {
		return this.dataSetDAO.selectGrpReportFolderList(userId);
	}

	@Override
	public List<FolderMasterVO> selectUserReportFolderList(String userId) {
		return  this.dataSetDAO.selectUserReportFolderList(userId);
	}

	@Override
	public List<ReportListMasterVO> selectGrpReportList(String userId) {
		return this.dataSetDAO.selectGrpReportList(userId);
	}

	@Override
	public List<ReportListMasterVO> selectReportList(String userId) {
		ConfigMasterVO configVo = authenticationService.getConfigMstr();
		//보고서별권한
		/* DOGFOOT ktkang 보고서 정렬 순서 다른 오류 수정  20200707 */
		String reportOrdinal = (configVo.getREPORT_ORDINAL().equals("REG_DT"))?"REG_DT":"TEXT";
		if (configVo.getAUTH_REPORT_DETAIL_YN().equals("Y")) {
			//정렬순서

			List<ReportListMasterVO> returnReportList = new ArrayList<ReportListMasterVO>();
			/* DOGFOOT ktkang 보고서별 권한 USER 부분 추가  20200721  */
			List<ReportListMasterVO> reportListMasterVoList = this.dataSetDAO.selectUserAuthReportDetailList(userId, reportOrdinal);
			if(reportListMasterVoList.size() == 0) {
				reportListMasterVoList = this.dataSetDAO.selectGrpAuthReportDetailList(userId, reportOrdinal);
			}

			//폴더 상위 계층 리스트 가져오기
			for(int i=0;i<reportListMasterVoList.size();i++) {
				ReportListMasterVO reportListMasterVO = reportListMasterVoList.get(i);
				if(reportListMasterVO.getTYPE().equals("FOLDER")) {
					returnReportList.add(reportListMasterVO);
					int upperId = reportListMasterVO.getUPPERID();
					while(upperId>0) {
						ReportListMasterVO upper_reportListMasterVO = selectFldInfo(upperId);
						returnReportList.add(upper_reportListMasterVO);
						upperId = upper_reportListMasterVO.getUPPERID();
					}
				}
			}

			//폴더 중복 삭제
			List<ReportListMasterVO> resultList = new ArrayList<ReportListMasterVO>();
            for (int i = 0; i < returnReportList.size(); i++) {
            	ReportListMasterVO fld1 = returnReportList.get(i);
            	boolean keep = false;
            	for (int j = 0; j < resultList.size(); j++) {
            		ReportListMasterVO fld2 = resultList.get(j);
	                if (fld1.getID()==fld2.getID()) {
	                    keep = true;
	                }
            	}
            	if(!keep) resultList.add(returnReportList.get(i));
            }

            //폴더명은 이름순으로 정렬
            Collections.sort(resultList, new Comparator<Object>(){
            	@Override
            	public int compare(Object o1, Object o2) {
            		String vo1 = ((ReportListMasterVO)o1).getTEXT();
            		String vo2 = ((ReportListMasterVO)o2).getTEXT();
            		return vo1.compareTo(vo2);
            	}
            });

			//레포트 리스트
			for(int i=0;i<reportListMasterVoList.size();i++) {
				ReportListMasterVO reportListMasterVO = reportListMasterVoList.get(i);
				if(reportListMasterVO.getTYPE().equals("REPORT")) {
					resultList.add(reportListMasterVO);
				}
			}

			return resultList;
		} else {
			//폴더별권한
			/* DOGFOOT ktkang 보고서 및 폴더 권한 체크 추가  20200717 */
			List<ReportListMasterVO> reportList = new ArrayList<ReportListMasterVO>();
			reportList = this.dataSetDAO.selectUserAuthReportList(userId, reportOrdinal);
			if(reportList.size() == 0) {
				reportList = this.dataSetDAO.selectGrpAuthReportList(userId, reportOrdinal);
			}

			return reportList;
		}
	}

	public ReportListMasterVO selectFldInfo(int fldId) {
		return this.dataSetDAO.selectPubFldMstrInfo(fldId);
	}

	/* DOGFOOT ktkang 주제영역 폴더 형식으로 표현  20200120 */
	@Override
	public List<CubeListMasterVO> selectCubeFldList(String ds_view_id) {
		return this.dataSetDAO.selectCubeFldList(ds_view_id);
	}

	@Override
	public List<ReportListMasterVO> selectUserReportList(String userId) {
		ConfigMasterVO configVo = authenticationService.getConfigMstr();
		String reportOrdinal = (configVo.getREPORT_ORDINAL().equals("REG_DT"))?"REG_DT":"TEXT";
		return this.dataSetDAO.selectUserReportList(userId, reportOrdinal);
	}

	@Override
	public void insertSchData(ParamScheduleVO schParam) {
		this.dataSetDAO.insertSchData(schParam);
	}

	public List<Object> getCubeRelationInfo(User sessionUser, int dataSourceId) {
		CubeTableVO vo = new CubeTableVO();
        vo.setCubeId(dataSourceId);

        List<Object> cubeRelation =this.reportDAO.selectCubeReportTableConstraints2(vo);

		return cubeRelation;
	}

	public String generateCubeQuery(User sessionUser, int dataSourceId, String dataSourceType, JSONObject params, JSONArray dimensions, JSONArray measures, JSONArray filters, JSONArray subquery) {
        CubeTableVO vo = new CubeTableVO();
        vo.setCubeId(dataSourceId);

        CubeMember cubeInfo = this.reportDAO.selectCubeMasterInformation(dataSourceId);

        List<DataAuthentication> userGroupDataAuthentications;
        ReportDataPermission userGroupDataPermission = this.authenticationDAO.selectDataAuthnByUserGroup(0);
        if (userGroupDataPermission == null || userGroupDataPermission.getDataAuthnXml().equals("")) {
            userGroupDataAuthentications = new ArrayList<DataAuthentication>();
        }
        else {
            userGroupDataAuthentications = userGroupDataPermission.getAuthnMember(cubeInfo.getDsViewId());
        }

        List<DataAuthentication> userDataAuthentications;
        ReportDataPermission userDataPermission = this.authenticationDAO.selectDataAuthnByUser(0);
        if (userDataPermission == null || userDataPermission.getDataAuthnXml().equals("")) {
            userDataAuthentications = new ArrayList<DataAuthentication>();
        }
        else {
            userDataAuthentications = userDataPermission.getAuthnMember(cubeInfo.getDsViewId());
        }

        List<CubeTableColumn> columnInfoList = this.reportDAO.selectCubeColumnInfomationList(vo);

        QuerySettingEx sqlQenQuery = new QuerySettingEx();
        ArrayList<SelectCube> aDtSel = new ArrayList<SelectCube>();
        ArrayList<Hierarchy> aDtSelHIe = new ArrayList<Hierarchy>();
        ArrayList<SelectCubeMeasure> aDtSelMea = new ArrayList<SelectCubeMeasure>();
        ArrayList<Relation> aDtCubeRel = new ArrayList<Relation>();
        ArrayList<Relation> aDtDsViewRel = new ArrayList<Relation>();
        ArrayList<SelectCubeWhere> aDtWhere = new ArrayList<SelectCubeWhere>();
        List<Object> cubeRelation =this.reportDAO.selectCubeReportTableConstraints2(vo);
        List<Object> dsViewRelation =this.reportDAO.selectViewReportTableConstraints2(vo);
        logger.debug("######### dimensions ######### ");

        JSONObject col;
        for (int index = 0; index < dimensions.size(); index++) {
            col = dimensions.getJSONObject(index);
            for(CubeTableColumn column : columnInfoList)
            {

            	if(column.getLogicalColumnName() != null)
            	{
            		if(col.get("uid").toString().contains(column.getLogicalColumnName().toString()))
                	{
                		SelectCube selCube = new SelectCube();
                		selCube.setUNI_NM(column.getLogicalColumnName());
                		selCube.setCAPTION(column.getColumnCaption());
                		selCube.setDATA_TYPE(column.getDataType());
                		selCube.setORDER(Integer.toString(index));
                		selCube.setTYPE("DIM");
                		aDtSel.add(selCube);

                		Hierarchy selHie = new Hierarchy();

                		selHie.setDIM_UNI_NM(column.getLogicalTableName());
                		selHie.setHIE_UNI_NM(column.getLogicalColumnName());
                		selHie.setHIE_CAPTION(column.getColumnCaption());
                		selHie.setTBL_NM(column.getPhysicalTableName());
                		selHie.setCOL_NM(column.getPhysicalColumnName());
                		selHie.setCOL_EXPRESS(column.getExpression());
                		aDtSelHIe.add(selHie);

                		if(column.getOrderBy().equalsIgnoreCase("Key Column"))
                		{
                			if(!column.getPhysicalColumnName().contains(column.getPhysicalColumnKey()))
                			{
                				selHie = new Hierarchy();

                        		selHie.setDIM_UNI_NM(column.getLogicalTableName());
                        		selHie.setHIE_UNI_NM(column.getLogicalColumnName());
                        		selHie.setHIE_CAPTION(column.getColumnCaption());
//                        		selHie.setHIE_CAPTION(column.getColumnCaption() + "_K");
                        		selHie.setTBL_NM(column.getPhysicalTableName());
                        		selHie.setCOL_NM(column.getPhysicalColumnKey());
                        		selHie.setCOL_EXPRESS(column.getExpression());
                        		aDtSelHIe.add(selHie);
                			}
                		}
                		break;
                	}
            	}

            }
        }

        logger.debug("######### measures ######### ");
        for (int index = 0; index < measures.size(); index++) {
            col = measures.getJSONObject(index);

            for(CubeTableColumn column : columnInfoList)
            {
            	if(column.getLogicalColumnName() != null)
            	{
            		if(col.get("uid").toString().contains(column.getLogicalColumnName()))
	            	{
	            		SelectCube selCube = new SelectCube();
	            		selCube.setUNI_NM(column.getLogicalColumnName());
	            		selCube.setCAPTION(column.getColumnCaption());
	            		selCube.setDATA_TYPE(column.getDataType());
	            		selCube.setORDER(Integer.toString(index));
	            		selCube.setTYPE("MEA");
	            		aDtSel.add(selCube);

	            		SelectCubeMeasure selMea = new SelectCubeMeasure();

	            		selMea.setMEA_GRP_UNI_NM(column.getLogicalTableName());
	            		selMea.setMEA_UNI_NM(column.getLogicalColumnName());
	            		selMea.setMEA_CAPTION(column.getColumnCaption());
	            		selMea.setMEA_TBL_NM(column.getPhysicalTableName());
	            		selMea.setMEA_COL_NM(column.getPhysicalColumnKey());
	            		selMea.setMEA_AGG(column.getAggregationType());
	            		selMea.setCOL_EXPRESS(column.getExpression());
	            		aDtSelMea.add(selMea);
	            	}
            	}
            }

        }

        /*ReportMasterVO param = new ReportMasterVO();
        param.setId(dataSourceId);
        param.setType("AdHoc");

        ReportMasterVO ret;
        try {
            ret = this.reportDAO.select(param);
        }
        catch (Exception e) {
            if (e.getMessage().indexOf("Could not set property 'layoutXmlBase64'") > -1) {
                logger.error("COULD NOT FIND REPORT META XML FROM DATABASE",e);
                throw new NotFoundReportXmlException();
            }
            else {
                throw e;
            }
        }

        if (ret == null) {
            throw new UnRegisterdReportException();
        }

        this.xml2Json.setReportMasterVo(ret);
        JSONObject reportMeta = this.xml2Json.parseJSON();

        JSONArray parameterInfos = reportMeta.getJSONObject("ReportMasterInfo").getJSONObject("dataSource").getJSONArray("parameters");
        */
        JSONObject subqueryMeta;
        logger.debug("######### subqueryMeta ######### ");
        if(subquery == null) {
        } else if(subquery.getJSONObject(0).size() > 0)
        {
        	subqueryMeta = (JSONObject) subquery.getJSONObject(0).get("SUB_QUERY");

            String query = (String) subqueryMeta.get("QUERY");
            String subHieUniNm = (String) subqueryMeta.get("HIE_UNI_NM");

            if (!query.equals(""))
            {
            	 ArrayList<String> chkParamList = new ArrayList<String>();

            	for(CubeTableColumn column : columnInfoList)
                {
                	if(column.getLogicalColumnName() != null)
                	{
                		if(subHieUniNm.contains(column.getLogicalColumnName()))
    	            	{

                			if(!chkParamList.contains(subHieUniNm))
                			{
                				SelectCubeWhere whereCube = new SelectCubeWhere();
        	            		whereCube.setPARENT_UNI_NM(column.getLogicalTableName());
        	            		whereCube.setUNI_NM(subHieUniNm);
        	            		whereCube.setCAPTION(column.getColumnCaption());
        	            		whereCube.setOPER("In");
        	            		whereCube.setVALUES("#SUB_QUERY#");
        	            		whereCube.setVALUES_CAPTION(query);
        	            		whereCube.setAGG("");
        	            		whereCube.setDATA_TYPE(column.getDataType());
        	            		whereCube.setPARAM_YN("False");
        	            		whereCube.setPARAM_NM("");
        	            		whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
        	            		whereCube.setORDER("0");
        	            		whereCube.setTBL_NM(column.getPhysicalTableName());
        	            		whereCube.setCOL_NM(column.getPhysicalColumnKey());
        	            		whereCube.setLOGIC("");
        	            		whereCube.setCOL_EXPRESS("");
        	            		whereCube.setWHERE_CLAUSE("");
        	            		whereCube.setCOND_ID("");

        	            		aDtWhere.add(whereCube);
                			}

    	            	}
                	}
                }
            }
        }

        ArrayList<String> chkParamList = new ArrayList<String>();
        JSONObject filter;
        if (filters == null) filters = new JSONArray();
        logger.debug("######### params ######### ");
        for (Object key : params.keySet().toArray()) {
        	filter = params.getJSONObject((String) key);

        	for(CubeTableColumn column : columnInfoList)
            {
            	if(column.getLogicalColumnName() != null)
            	{
            		if(filter.get("uniqueName").toString().contains(column.getLogicalColumnName()))
	            	{

            			if(!chkParamList.contains(filter.get("uniqueName").toString()))
            			{
            				SelectCubeWhere whereCube = new SelectCubeWhere();
    	            		whereCube.setPARENT_UNI_NM("[" + column.getPhysicalTableName() + "]");
    	            		whereCube.setUNI_NM(filter.get("uniqueName").toString());
    	            		whereCube.setCAPTION(filter.get("name").toString());
    	            		whereCube.setOPER(filter.get("parameterType").toString());
    	            		whereCube.setVALUES(filter.get("value").toString().replaceAll("\"", ""));
    	            		whereCube.setVALUES_CAPTION("");
    	            		whereCube.setAGG("");
    	            		whereCube.setDATA_TYPE(column.getDataType());
    	            		whereCube.setPARAM_YN("False");
    	            		whereCube.setPARAM_NM("");
    	            		whereCube.setTYPE(column.getColumnType().equalsIgnoreCase("dimension") ? "DIM":"MEA");
    	            		whereCube.setORDER("0");
    	            		whereCube.setTBL_NM(column.getPhysicalTableName());
    	            		whereCube.setCOL_NM(column.getPhysicalColumnKey());
    	            		whereCube.setLOGIC("");
    	            		whereCube.setCOL_EXPRESS("");
    	            		whereCube.setWHERE_CLAUSE(filter.get("whereClause").toString() + "");
    	            		whereCube.setCOND_ID("");

    	            		aDtWhere.add(whereCube);
            			}

	            		chkParamList.add(filter.get("uniqueName").toString());

	            	}
            	}
            }

        }

        logger.debug("######### cubeRelation ######### ");
        for(int i =0; i<cubeRelation.size();i++){
        	/*dogfoot shlim 20210430*/
        	Relation cuberel = (Relation) cubeRelation.get(i);
//			HashMap map = (HashMap)cubeRelation.get(i);
//			Relation cuberel = new Relation();
//
//			cuberel.setDS_ID(Integer.parseInt(map.get("DS_ID").toString()));
//			cuberel.setDS_VIEW_ID(Integer.parseInt(map.get("DS_VIEW_ID").toString()));
//			cuberel.setCUBE_ID(Integer.parseInt(map.get("CUBE_ID").toString()));
//			cuberel.setCONST_NM(map.get("CONST_NM").toString());
//			cuberel.setFK_TBL_NM(map.get("FK_TBL_NM").toString());
//			cuberel.setFK_COL_NM(map.get("FK_COL_NM").toString());
//			cuberel.setPK_TBL_NM(map.get("PK_TBL_NM").toString());
//			cuberel.setPK_COL_NM(map.get("PK_COL_NM").toString());
//			cuberel.setJOIN_TYPE(map.get("JOIN_TYPE").toString());
//			cuberel.setJOIN_SET_OWNER(map.get("JOIN_SET_OWNER").toString());
//			cuberel.setREL_CONST_NM(map.get("REL_CONST_NM").toString());
//			cuberel.setDIM_UNI_NM(map.get("DIM_UNI_NM").toString());
//			cuberel.setMEA_GRP_UNI_NM(map.get("MEA_GRP_UNI_NM").toString());
//			cuberel.setMODIFY_TAG("");

			aDtCubeRel.add(cuberel);
		}
        logger.debug("######### dsViewRelation ######### ");
        for(int i =0; i<dsViewRelation.size();i++){
			HashMap map = (HashMap)dsViewRelation.get(i);
			Relation cuberel = new Relation();

			cuberel.setDS_ID(Integer.parseInt(map.get("DS_ID").toString()));
			cuberel.setDS_VIEW_ID(Integer.parseInt(map.get("DS_VIEW_ID").toString()));
			cuberel.setFK_TBL_NM(map.get("FK_TBL_NM").toString());
			cuberel.setFK_COL_NM(map.get("FK_COL_NM").toString());
			cuberel.setPK_TBL_NM(map.get("PK_TBL_NM").toString());
			cuberel.setPK_COL_NM(map.get("PK_COL_NM").toString());
			cuberel.setJOIN_TYPE(map.get("JOIN_TYPE").toString());
			cuberel.setJOIN_SET_OWNER(map.get("JOIN_SET_OWNER").toString());
			cuberel.setMODIFY_TAG(map.get("MODIFY_TAG").toString());
			cuberel.setCONST_NM(map.get("CONST_NM").toString());
			aDtDsViewRel.add(cuberel);
		}
        String sql2 = null;

        logger.debug("######### CubeQuerySetting ######### ");
      //2020.12.07 MKSONG MARIADB 오류  DOGFOOT
//        sql2 = sqlQenQuery.CubeQuerySetting(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, new ArrayList<SelectCubeOrder> (), "MARIA", aDtCubeRel, aDtDsViewRel, new ArrayList<SelectCubeEtc>());
        sql2 = sqlQenQuery.CubeQuerySetting(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, new ArrayList<SelectCubeOrder> (), "DB2", aDtCubeRel, aDtDsViewRel, new ArrayList<SelectCubeEtc>());

        String sql = null;

        /* validate sql */
     /*   try {
        	sqlGenerator.generate(true);
            sql = sqlGenerator.getSql();
            this.querySql(dataSourceId, dataSourceType, sql, params);
        }
        catch (Exception  e) {
        	logger.error("", e);
        	throw new CubeSqlValidationException(e);
        }
        finally {
            sqlGenerator.initCheckJoin();
        }*/

        /* excute sql */
       /* sqlGenerator.generate();
        sql = sqlGenerator.getSql();*/
        logger.debug("sql(raw-cube) : " +sql2);
        return sql2;
    }

	@Override
	public TossExeVO getTossBatch(Map param) {
		// TODO Auto-generated method stub
		return this.dataSetDAO.getTossBatch(param);
	}

	@Override
	public String selectSCHForSkip(String schId, String dataSourceIdStr) {
		// TODO Auto-generated method stub
		return this.dataSourceFactory.selectSCHForSkip(schId,dataSourceIdStr);
	}

	@Override
    public List<List<DataField>> querySqlByIdForExcel(int dataSourceId, String dataSourceType, String sqlId, JSONObject params)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        String sql = this.sqlStorage.getSql(sqlId);
        logger.debug("sql(raw) : " + sql);
        return this.querySqlForExcel(dataSourceId, dataSourceType, sql, params);
    }

    @Override
    public List<List<DataField>> querySqlForExcel(int dataSourceId, String dataSourceType, String sql, JSONObject params)
    		 throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        Connection connection = null;
        PreparedStatement pstmt = null;
        ResultSet resultSet = null;

        List<List<DataField>> result = new ArrayList<List<DataField>>();

        try {
            /**
             * sql mapper 생성 및 활용해야 할 부분
             * - client에서 전달받온 parameter를 name과 type을 이용하여 sql에 value를  mapping
             */
            sql = this.sqlMapper.mapParameter(sql, params);
            logger.debug("sql(param) : " + sql);

            sql = this.sqlConvertor.convert(sql);
            logger.debug("sql(converted) : " + sql);

            connection = this.getConnection(dataSourceId, dataSourceType);
            pstmt = connection.prepareStatement(sql);

            Timer timer1 = new Timer();
            timer1.start();

            resultSet = pstmt.executeQuery();
            timer1.stop();

            Timer timer2 = new Timer();
            timer2.start();

            ResultSetMetaData md = resultSet.getMetaData();
            while (resultSet.next()) {
                List<DataField> row = new ArrayList<DataField>();

                for (int i = 1; i <= md.getColumnCount(); i++) {

                	row.add(new DataField(i, md, resultSet.getObject(i)));
                }

                result.add(row);
            }
            timer2.stop();

            logger.debug("queried count : " + result.size());
            logger.debug("sql quering time : " + timer1.getInterval());
            logger.debug("result loop time : " + timer2.getInterval());
        } catch (SQLException e) {
        	e.printStackTrace();
        	throw e;
        } finally {
        	if (pstmt != null) {
        		try {
        			pstmt.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		pstmt = null;
             	}
        	}
        	if (resultSet != null) {
        		try {
             		resultSet.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		resultSet = null;
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

        return result;
    }

	/* DOGFOOT ktkang 사용자 데이터 업로드 권한 추가  20200716 */
	@Override
	public List<SubjectMasterVO> selectSubjectList(boolean isUploadEnable, String userId) {
		// TODO Auto-generated method stub
		return this.dataSetDAO.selectSubjectList(isUploadEnable, userId);
	}

	@Override
	public SubjectMasterVO selectSubjectList(int dsid, String ds_type) {
		// TODO Auto-generated method stub
		return this.dataSetDAO.selectSubjectList(dsid,ds_type);
	}

	@Override
	public List<SubjectMasterVO> selectUserAuthDsList(String userNo) {
		// TODO Auto-generated method stub
		return this.dataSetDAO.selectUserAuthDsList(userNo);
	}

	@Override
	public List<SubjectMasterVO> selectGrpAuthDsList(String userNo) {
		// TODO Auto-generated method stub
		return this.dataSetDAO.selectGrpAuthDsList(userNo);
	}

	@Override
    public Map<String,List<List<DataField>>> queryData(String pidParam, JSONArray dataSources, JSONObject params)
    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
        JSONObject dataSource;

        String sheetName;
        String dataSourceIdStr;
        String dataSourceType;
        String sqlId;

        Map<String,List<List<DataField>>> result = new HashMap<String,List<List<DataField>>>();

        int pid = Integer.valueOf(pidParam).intValue();

        for (int index = 0; index < dataSources.size(); index++) {
            dataSource = dataSources.getJSONObject(index);

            sheetName = dataSource.containsKey("sheetNm") ? dataSource.getString("sheetNm") : "UNDEFINED-SHEET-NAME";
            dataSourceIdStr = dataSource.getString("dsid");
            dataSourceType = dataSource.getString("dstype");
            sqlId = dataSource.getString("sqlid");

            int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();

            String sql = this.sqlStorage.getSql(sqlId);
            if (sql == null) {
                ReportMasterVO reportMasterVo = this.reportService.selectReportBasicInformation(pid, Configurator.Constants.WISE_REPORT_TYPE);
                JSONObject info = reportMasterVo.getDataSourceAndParameterJson("");
                JSONObject reportMasterInfo = JSONObject.fromObject(info);
//                    System.out.println(reportMasterVo);
                this.sqlStorage.store(reportMasterInfo); // store sql to sql storage & remove sql[DATASET_QUERY] from reportMasterInfo
            }

            List<List<DataField>> queryData = this.querySqlByIdForExcel(dataSourceId, dataSourceType, sqlId, params);
            result.put(sheetName, queryData);

        } // end of loop

        return result;
    }

	@Override
	public void saveDataSet(org.json.JSONObject obj){
		// TODO Auto-generated method stub
		DataSetInfoVO param = new DataSetInfoVO();
		Json2Xml parser = new Json2Xml();
//		System.out.println(obj);
		if(obj.getString("dataSetType").equalsIgnoreCase("DataSetDs")) {
			try {
				String SQL_XML = parser.sortDataSetXMLForDataSetDS(obj,new org.json.JSONObject(),false);

				param.setP_PARAM("0");
				param.setDATASET_ID(obj.getInt("datasetId"));
				param.setDATASET_NM(obj.getString("dataSetNM"));
				param.setFLD_ID(obj.getInt("fldId"));
				param.setDATASRC_ID(obj.getInt("ds_id"));
				param.setDATASRC_TYPE(obj.getString("dataSrcType"));
				param.setDATASET_TYPE(obj.getString("dataSetType"));
				param.setSQL_XML(Base64.encode(SQL_XML.getBytes()));
				param.setSQL_QUERY(Base64.encode(obj.getString("dataSetQuery").getBytes()));
				param.setDATASET_DESC(obj.getString("dataSetDesc"));
				param.setREG_USER_NO(obj.getInt("userNo"));
				param.setMOD_USER_NO(obj.getInt("userNo"));
				param.setPRIVACY_YN("N");
				this.dataSetDAO.saveDataset(param);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		else if(obj.getString("dataSetType").equalsIgnoreCase("DataSetSingleDs")) {

		}
	}

	@Override
    public Map<String,List<List<DataField>>> queryData(JSONArray dataSources, JSONObject params)
    		 throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException {
    	Timer timer = new Timer();

    	Connection connection = null;
        PreparedStatement pstmt = null;
        ResultSet resultSet = null;

        JSONObject dataSource;

        String sheetName;
        String dataSourceIdStr;
        String dataSourceType;
        String sql;

        Map<String,List<List<DataField>>> result = new HashMap<String,List<List<DataField>>>();
        try {
            for (int index = 0; index < dataSources.size(); index++) {
            	List<List<DataField>> subResult = new ArrayList<List<DataField>>();
            	dataSource = dataSources.getJSONObject(index);
                sheetName = dataSource.containsKey("sheetNm") ? dataSource.getString("sheetNm") : "UNDEFINED-SHEET-NAME";
                dataSourceIdStr = dataSource.getString("dsid");
                dataSourceType = dataSource.getString("dstype");
                sql = dataSource.getString("sql");

                int dataSourceId = Integer.valueOf(dataSourceIdStr).intValue();

                timer.start();

                sql = this.sqlMapper.mapParameter(sql, params);
                logger.debug("sql(param) : " + sql);

                sql = this.sqlConvertor.convert(sql);
                logger.debug("sql(converted) : " + sql);

                connection = this.getConnection(dataSourceId, dataSourceType);
                pstmt = connection.prepareStatement(sql);

                Timer timer1 = new Timer();
                timer1.start();

                resultSet = pstmt.executeQuery();
                timer1.stop();

                Timer timer2 = new Timer();
                timer2.start();

                ResultSetMetaData md = resultSet.getMetaData();
                while (resultSet.next()) {
                    List<DataField> row = new ArrayList<DataField>();

                    for (int i = 1; i <= md.getColumnCount(); i++) {

                    	row.add(new DataField(i, md, resultSet.getObject(i)));
                    }

                    subResult.add(row);
                }
                timer2.stop();

                logger.debug("queried count : " + result.size());
                logger.debug("sql quering time : " + timer1.getInterval());
                logger.debug("result loop time : " + timer2.getInterval());

                result.put(sheetName, subResult);

            } // end of loop
        }
        catch (SQLException e) {
            e.printStackTrace();
        }finally {
        	if (pstmt != null) {
        		try {
        			pstmt.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		pstmt = null;
             	}
        	}
        	if (resultSet != null) {
        		try {
             		resultSet.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		resultSet = null;
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

        return result;
    }

	@Override
	public DataSetInfoVO openDataSet(String dataSetID, String dataSrcID,String dataSetType) {
		// TODO Auto-generated method stub
		DataSetInfoVO param = new DataSetInfoVO();
		param.setDATASET_ID(Integer.parseInt(dataSetID));
		param.setDATASRC_ID(Integer.parseInt(dataSrcID));
		param.setDATASRC_TYPE(dataSetType);
		return this.dataSetDAO.openDataSet(param);
	}

	@Override
	public List<SubjectMasterVO> selectUserAuthDsList(String dataSrcID, String userNo) {
		// TODO Auto-generated method stub
		return this.dataSetDAO.selectUserAuthDsList(dataSrcID,userNo);
	}

	@Override
	public List<SubjectMasterVO> selectGrpAuthDsList(String dataSrcID, String userNo) {
		// TODO Auto-generated method stub
		return this.dataSetDAO.selectGrpAuthDsList(dataSrcID,userNo);
	}

	@Override
	public void deleteDataSet(String datasetId) {
		// TODO Auto-generated method stub
		this.dataSetDAO.deleteDataSet(datasetId);
	}

	@Override
	public List<ReportListMasterVO> selectAllreportList() {
		// TODO Auto-generated method stub
		return dataSetDAO.selectAllreportList();
	}

	@Override
	public List<FolderMasterVO> selectAllReportFolderList() {
		// TODO Auto-generated method stub
		return dataSetDAO.selectAllReportFolderList();
	}

	@Override
	public List<FolderMasterVO> selectAllMyReportFolderList(String userNo) {
		// TODO Auto-generated method stub
		return dataSetDAO.selectAllMyReportFolderList(userNo);
	}

	@Override
	public List<SubjectMasterVO> selectUserAuthDsViewList(String userNo) {
		// TODO Auto-generated method stub
		return dataSetDAO.selectUserAuthDsViewList(userNo);
	}

	@Override
	public List<SubjectMasterVO> selectGrpAuthDsViewList(String userNo) {
		// TODO Auto-generated method stub
		return dataSetDAO.selectGrpAuthDsViewList(userNo);
	}

	@Override
	public List<CubeTable> selectDsViewTableList(int dataSourceId) {
		// TODO Auto-generated method stub
		return dataSetDAO.selectDsViewTableList(dataSourceId);
	}

	@Override
	public List<DSViewColVO> getDsViewColumnList(int dataSourceId, String tableName) {
		// TODO Auto-generated method stub
		return dataSetDAO.getDsViewColumnList(dataSourceId,tableName);
	}

	/* DOGFOOT ktkang 보고서 정렬 순서 다른 오류 수정 시작  20200707 */
	@Override
	public List<ReportListMasterVO> selectUserSpreadReportList(String user_id) {
		ConfigMasterVO configVo = authenticationService.getConfigMstr();
		String reportOrdinal = (configVo.getREPORT_ORDINAL().equals("REG_DT"))?"REG_DT":"TEXT";
		return dataSetDAO.selectUserSpreadReportList(user_id, reportOrdinal);
	}

	@Override
	public List<ReportListMasterVO> selectNotUserSpreadReportList(String user_id) {
		ConfigMasterVO configVo = authenticationService.getConfigMstr();
		String reportOrdinal = (configVo.getREPORT_ORDINAL().equals("REG_DT"))?"REG_DT":"TEXT";
		return dataSetDAO.selectNotUserSpreadReportList(user_id, reportOrdinal);
	}

	@Override
	public List<ReportListMasterVO> selectGrpSpreadReportList(String user_id) {
		ConfigMasterVO configVo = authenticationService.getConfigMstr();
		String reportOrdinal = (configVo.getREPORT_ORDINAL().equals("REG_DT"))?"REG_DT":"TEXT";
		return dataSetDAO.selectGrpSpreadReportList(user_id, reportOrdinal);
	}

	@Override
	public List<ReportListMasterVO> selectSpreadReportList(String user_id) {
		ConfigMasterVO configVo = authenticationService.getConfigMstr();
		String reportOrdinal = (configVo.getREPORT_ORDINAL().equals("REG_DT"))?"REG_DT":"TEXT";
		return dataSetDAO.selectSpreadReportList(user_id, reportOrdinal);
	}

	@Override
	public List<ReportListMasterVO> selectNotSpreadReportList(String user_id) {
		ConfigMasterVO configVo = authenticationService.getConfigMstr();
		List<ReportListMasterVO> reportList = new ArrayList<ReportListMasterVO>();
		String reportOrdinal = (configVo.getREPORT_ORDINAL().equals("REG_DT"))?"REG_DT":"TEXT";
		if (configVo.getAUTH_REPORT_DETAIL_YN().equals("Y")) {
			List<ReportListMasterVO> returnReportList = new ArrayList<ReportListMasterVO>();
			/* DOGFOOT ktkang 보고서별 권한 USER 부분 추가  20200721  */
			List<ReportListMasterVO> reportListMasterVoList = this.dataSetDAO.selectNotSpreadUserAuthReportDetailList(user_id, reportOrdinal);
			if(reportListMasterVoList.size() == 0) {
				reportListMasterVoList = this.dataSetDAO.selectNotSpreadGrpAuthReportDetailList(user_id, reportOrdinal);
			}

			//폴더 상위 계층 리스트 가져오기
			for(int i=0;i<reportListMasterVoList.size();i++) {
				ReportListMasterVO reportListMasterVO = reportListMasterVoList.get(i);
				if(reportListMasterVO.getTYPE().equals("FOLDER")) {
					returnReportList.add(reportListMasterVO);
					int upperId = reportListMasterVO.getUPPERID();
					while(upperId>0) {
						ReportListMasterVO upper_reportListMasterVO = selectFldInfo(upperId);
						returnReportList.add(upper_reportListMasterVO);
						upperId = upper_reportListMasterVO.getUPPERID();
					}
				}
			}

			//폴더 중복 삭제
			List<ReportListMasterVO> resultList = new ArrayList<ReportListMasterVO>();
            for (int i = 0; i < returnReportList.size(); i++) {
            	ReportListMasterVO fld1 = returnReportList.get(i);
            	boolean keep = false;
            	for (int j = 0; j < resultList.size(); j++) {
            		ReportListMasterVO fld2 = resultList.get(j);
	                if (fld1.getID()==fld2.getID()) {
	                    keep = true;
	                }
            	}
            	if(!keep) resultList.add(returnReportList.get(i));
            }

            //폴더명은 이름순으로 정렬
            Collections.sort(resultList, new Comparator<Object>(){
            	@Override
            	public int compare(Object o1, Object o2) {
            		String vo1 = ((ReportListMasterVO)o1).getTEXT();
            		String vo2 = ((ReportListMasterVO)o2).getTEXT();
            		return vo1.compareTo(vo2);
            	}
            });

			//레포트 리스트
			for(int i=0;i<reportListMasterVoList.size();i++) {
				ReportListMasterVO reportListMasterVO = reportListMasterVoList.get(i);
				if(reportListMasterVO.getTYPE().equals("REPORT")) {
					resultList.add(reportListMasterVO);
				}
			}

			return resultList;
		}else {
			/* DOGFOOT ktkang 보고서 및 폴더 권한 체크 추가  20200717 */
			reportList = this.dataSetDAO.selectNotSpreadReportList(user_id, reportOrdinal);
			if(reportList.size() == 0) {
				reportList = this.dataSetDAO.selectNotSpreadGrpReportList(user_id, reportOrdinal);
			}

			return reportList;
		}

	}
	/* DOGFOOT ktkang 보고서 정렬 순서 다른 오류 수정 끝  20200707 */

	@Override
	public JSONObject queryDrillThruSql(User sessionUser, int cubeId, String dataSourceType, int actId, JSONObject params)
			throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {

		JSONArray dimensions = new JSONArray();
		JSONArray measures = new JSONArray();

		List<DrillThruColumnVO> drillThruColumnList = this.reportDAO.selectDrillThruColumns(cubeId, actId);

		for (DrillThruColumnVO dtc : drillThruColumnList) {

		    JSONObject o = new JSONObject();
		    o.put("uid", dtc.getRtnItemUniNm());

		    if ("Y".equalsIgnoreCase(dtc.getDimYn())) {
			dimensions.add(o);
		    }
		    else if ("Y".equalsIgnoreCase(dtc.getMeaYn())) {
			measures.add(o);
		    }
		}

		/* DOGFOOT ktkang 상세데이터 보기 수정  20200219 */
		JSONObject dataSet = this.queryCubeSql2(sessionUser, cubeId, dataSourceType, params, dimensions, measures, null,null,0, true, "AdHoc","false");

		JSONObject columnInfo;
		JSONObject meta = dataSet.getJSONObject("meta");

		if (meta != null && !meta.isEmpty()) {
		    for (DrillThruColumnVO dtc : drillThruColumnList) {

			if ("Y".equalsIgnoreCase(dtc.getDimYn())) {
			    columnInfo = meta.getJSONObject(dtc.getRtnItemUniNm().replace(dtc.getUniNm() + ".[", "").replace("]", ""));
			   // columnInfo.put("order", 0);
			}
			else if ("Y".equalsIgnoreCase(dtc.getMeaYn())) {
			    columnInfo = meta.getJSONObject(dtc.getRtnItemUniNm().replace(dtc.getUniNm() + ".[", "").replace("]", ""));
			  //  columnInfo.put("order", 0);
			}
		    }
		}

		return dataSet;
	}

	@Override
	public void cancelQuery() {
		try {
	    	if(pstmt !=null) {
	    		pstmt.cancel();
	    		pstmt.close();
	    	}
	    	if(connection !=null) {
	    		connection.close();
	    	}
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	@Override
   	public CubeMember selectCubeInfomationOne(int dataSourceId) {
		CubeMember cubeInfo = this.reportDAO.selectCubeMasterInformation(dataSourceId);
		return cubeInfo;
	}

	@Override
	public List<SubjectCubeMasterVO> selectUserAuthCubeList(String userNo) {
		// TODO Auto-generated method stub
		return dataSetDAO.selectUserAuthCubeList(userNo);
	}

	@Override
	public List<SubjectCubeMasterVO> selectGrpAuthCubeList(String userNo) {
		// TODO Auto-generated method stub
		return dataSetDAO.selectGrpAuthCubeList(userNo);
	}

	@Override
	public String getSql(ArrayList<SelectCube> aDtSel, ArrayList<Hierarchy> aDtSelHIe,
			ArrayList<SelectCubeMeasure> aDtSelMea, ArrayList<SelectCubeWhere> aDtWhere,
			ArrayList<SelectCubeOrder> aDtOrder, String dbtype, String datasourceId) {
		// TODO Auto-generated method stub

		CubeTableVO vo = new CubeTableVO();
		vo.setCubeId(Integer.parseInt(datasourceId));

		List<Object> cubeRelation = this.reportDAO.selectCubeReportTableConstraints2(vo);
		List<Object> dsViewRelation = this.reportDAO.selectViewReportTableConstraints2(vo);

		ArrayList<Relation> aDtCubeRel = new ArrayList<Relation>();
        ArrayList<Relation> aDtDsViewRel = new ArrayList<Relation>();

        QuerySettingEx sqlQenQuery = new QuerySettingEx();

		logger.debug("######### cubeRelation ######### ");
		for (int i = 0; i < cubeRelation.size(); i++) {
			/*dogfoot shlim 20210430*/
			Relation cuberel = (Relation) cubeRelation.get(i);
//			HashMap map = (HashMap) cubeRelation.get(i);
//			Relation cuberel = new Relation();
//
//			cuberel.setDS_ID(Integer.parseInt(map.get("DS_ID").toString()));
//			cuberel.setDS_VIEW_ID(Integer.parseInt(map.get("DS_VIEW_ID").toString()));
//			cuberel.setCUBE_ID(Integer.parseInt(map.get("CUBE_ID").toString()));
//			cuberel.setCONST_NM(map.get("CONST_NM").toString());
//			cuberel.setFK_TBL_NM(map.get("FK_TBL_NM").toString());
//			cuberel.setFK_COL_NM(map.get("FK_COL_NM").toString());
//			cuberel.setPK_TBL_NM(map.get("PK_TBL_NM").toString());
//			cuberel.setPK_COL_NM(map.get("PK_COL_NM").toString());
//			cuberel.setJOIN_TYPE(map.get("JOIN_TYPE").toString());
//			cuberel.setJOIN_SET_OWNER(map.get("JOIN_SET_OWNER").toString());
//			cuberel.setREL_CONST_NM(map.get("REL_CONST_NM").toString());
//			cuberel.setDIM_UNI_NM(map.get("DIM_UNI_NM").toString());
//			cuberel.setMEA_GRP_UNI_NM(map.get("MEA_GRP_UNI_NM").toString());
//			cuberel.setMODIFY_TAG("");

			aDtCubeRel.add(cuberel);
		}
		logger.debug("######### dsViewRelation ######### ");
		for (int i = 0; i < dsViewRelation.size(); i++) {
			HashMap map = (HashMap) dsViewRelation.get(i);
			Relation cuberel = new Relation();

			cuberel.setDS_ID(Integer.parseInt(map.get("DS_ID").toString()));
			cuberel.setDS_VIEW_ID(Integer.parseInt(map.get("DS_VIEW_ID").toString()));
			cuberel.setFK_TBL_NM(map.get("FK_TBL_NM").toString());
			cuberel.setFK_COL_NM(map.get("FK_COL_NM").toString());
			cuberel.setPK_TBL_NM(map.get("PK_TBL_NM").toString());
			cuberel.setPK_COL_NM(map.get("PK_COL_NM").toString());
			cuberel.setJOIN_TYPE(map.get("JOIN_TYPE").toString());
			cuberel.setJOIN_SET_OWNER(map.get("JOIN_SET_OWNER").toString());
			cuberel.setMODIFY_TAG(map.get("MODIFY_TAG").toString());
			cuberel.setCONST_NM(map.get("CONST_NM").toString());
			aDtDsViewRel.add(cuberel);
		}
		String sql2 = null;

		logger.debug("######### CubeQuerySetting ######### ");
		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
//		sql2 = sqlQenQuery.CubeQuerySetting(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, aDtOrder, "MARIA", aDtCubeRel, aDtDsViewRel, new ArrayList<SelectCubeEtc>());
		sql2 = sqlQenQuery.CubeQuerySetting(aDtSel, aDtSelHIe, aDtSelMea, aDtWhere, aDtOrder, "DB2", aDtCubeRel, aDtDsViewRel, new ArrayList<SelectCubeEtc>());
		return sql2;
	}

	@Override
    public CloseableList<JSONObject> querySqlLike(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout, String queryParam, JSONObject sqlConfig, JSONObject nullDimension, String itemType) throws Exception {
		return querySqlLike(dataSourceId, dataSourceType, sql, params, sqlTimeout, queryParam, sqlConfig, nullDimension, itemType, true);
	}
	/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
	@SuppressWarnings("unchecked")
    @Override
    public CloseableList<JSONObject> querySqlLike(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout, String queryParam, JSONObject sqlConfig, JSONObject nullDimension, String itemType, boolean useWithQuery)
//    		throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
    		throws	Exception {
    	Connection connection = null;
    	PreparedStatement pstmt = null;
        ResultSet resultSet = null;
        CloseableList<JSONObject> retResult = null;

        /* DOGFOOT ktkang 에러로 과거 소스로 돌림  20200717 */
        try {
        	// DOGFOOT hjkim db 정보 가져오게 처리 20200721
            DataSetMasterVO dataSetMaster = null;
	        if (DataSetConst.DataSetType.DS.equals(dataSourceType) || DataSetConst.DataSetType.DS_SQL.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetMaster(dataSourceId);
	        }
	        else if (DataSetConst.DataSetType.VIEW.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetViewMaster(dataSourceId);
	        }
	        else if (DataSetConst.DataSetType.CUBE.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectCubeMaster(dataSourceId);
	        }
	        String dbtype = dataSetMaster.getDatabaseType();

        	 /**
             * sql mapper 생성 및 활용해야 할 부분
             * - client에서 전달받온 parameter를 name과 type을 이용하여 sql에 value를  mapping
             */
            sql = this.sqlMapper.mapParameter(sql, params);
            logger.debug("sql(param) : " + sql);

            sql = this.sqlConvertor.convert(sql);
            logger.debug("sql(converted) : " + sql);

            /* DOGFOOT ktkang KERIS 상세현황 탭일 때 결과 값 자르기  20200123 */
            //KERIS
//            if(queryParam != null && queryParam.equals("nullData")) {
//            	sql = sql.replaceAll("RIGHT OUTER", "INNER");
//            } else if(queryParam != null && queryParam.equals("dataCut")) {
//            	 String line = System.getProperty("line.separator");
//            	 sql = "SELECT * FROM (\n"+sql+"\n) WHERE ROWNUM <= 65000";
//            	 sql = sql.replace("\n", line);
//            }

            if(useWithQuery){
	            sql = "WITH WISE_SQL_LIKE AS (\n" + sql + "\n)";
	
	            JSONArray selectList = sqlConfig.getJSONArray("Select");
	            //2020.01.30 mksong NOT JSONOBJECT 오류 수정 dogfoot
	            JSONArray groupByList = new JSONArray();
	
	            JSONArray fromList = new JSONArray();
	
	            JSONArray whereList = new JSONArray();
	
	            JSONArray orderByList = new JSONArray();
	
	
	
	            if(sqlConfig.containsKey("GroupBy")) {
	            	groupByList = sqlConfig.getJSONArray("GroupBy");
	            }
	
	
	            if(sqlConfig.containsKey("Where")) {
	            	whereList = sqlConfig.getJSONArray("Where");
	            }
	
	            if(sqlConfig.containsKey("OrderBy")) {
	            	orderByList = sqlConfig.getJSONArray("OrderBy");
	            }
	
	            if(sqlConfig.containsKey("isDiscountQuery")) {
	            	sql += "SELECT";
	            }else {
	            	sql += "SELECT ";
	            }
	
	            if(selectList.size() == 1) {
	            	//2020.02.07 mksong where 기능 추가 작업중 dogfoot
	            	if(selectList.getString(0).equals("*")) {
	            		sql += selectList.getString(0) + "\n";
	            	}else {
	            		sql += "\"" + selectList.getString(0) + "\"\n";
	            	}
	            }else {
	            	for(int i = 0; i < selectList.size(); i++) {
	                	if(i == selectList.size()-1) {
	//                		JSONObject result = this.switchSyntax(selectList.getString(i),selectList.getString(i));
	//                		if(result.getString("switched").equals("aggregate")) {
	//                			i++;
	                		// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	                		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	                		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	                			sql += selectList.getString(i) + "\n";
	                		} else {
	                			sql += "\"" + selectList.getString(i) + "\"\n";
	                		}
	//                		}
	                	}else {
	                		JSONObject result = this.switchAggregateSyntax(selectList.getString(i),selectList.getString(i+1), false);
	
	                		// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	                		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	                		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	                			String syntax = result.get("syntax").toString();
	                			result.put("syntax", syntax.replaceAll("\"", ""));
	                		}
	                		if(result.getBoolean("isChanged")) {
	                			i++;
	                			//2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
	                			if(i+1 < selectList.size()) {
	                				if(selectList.getString(i+1).equalsIgnoreCase("|as|")) {
	                        			i++;
	                        			sql += result.getString("syntax") + "\t" + "AS\t";
	                        		}else {
	                        			//2020.02.04 MKSONG ALIAS 기능 수정 DOGFOOT
	                        			sql += result.getString("syntax") + ",\t";
	                        		}
	                			}else {
	                				//2020.02.04 MKSONG ALIAS 기능 수정 DOGFOOT
	                				sql += result.getString("syntax") + "\n";
	                			}
	                		}else {
	                			//2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
	                			if(i+1 < selectList.size()) {
	                				if(selectList.getString(i+1).equalsIgnoreCase("|as|")) {
	                        			i++;
	                        			//2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
	                        			// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	                        			//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	                        			if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	                            			sql += result.getString("syntax") + "\t" + "AS\t";
	                            		} else {
	                            			sql += "\"" + result.getString("syntax") + "\"\t" + "AS\t";
	                            		}
	                        		}else {
	                           			sql += "\"" + result.getString("syntax") + "\",\t";
	                        		}
	                			}
	                		}
	                	}
	                }
	            }
	
	
	            sql += "FROM	WISE_SQL_LIKE \n";
	            //2020.02.07 mksong where 기능 추가 작업중 dogfoot
	
	            if(whereList.size() > 0) {
	            	sql += "WHERE	1=1\n";
		            if(whereList.size() == 1) {
		            	JSONArray dataList = whereList.getJSONObject(0).getJSONArray("data");
		            	/* DOGFOOT ktkang CUBRID 쿼리 오류 수정  20200701 */
		            	// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	
		            	//2020.11.12 MKSONG LIKE구문 추가 DOGFOOT
		            	if(dataList.get(0).toString().indexOf("LIKEDATA:") > -1) {
		            		sql += "AND (\n";
	            			for(int j = 0; j < dataList.size(); j++) {
	            				if(j == 0) {
	            					sql += "(";
	            				}else {
	            					sql += "OR (";
	            				}
	            				//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	            				if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
		            				sql += whereList.getJSONObject(0).getString("key")  + " LIKE '%" + dataList.get(j).toString().replaceAll("LIKEDATA:", "") + "%')\n";
	    	            		} else {
	    	            			//2020.11.27 mksong 카카오맵 like 오류 수정 dogfoot
	    	            			sql += "\"" + whereList.getJSONObject(0).getString("key")  + "\" LIKE \'%" + dataList.get(j).toString().replaceAll("LIKEDATA:", "") + "%\')\n";
	    	            		}
			                }
	            			sql += ")\n";
	        			}else {
	        				//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	        				if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	                			sql += "AND	" + whereList.getJSONObject(0).getString("key") + " IN (";
	                		} else {
	                			sql += "AND	\"" + whereList.getJSONObject(0).getString("key") + "\" IN (";
	                		}
	    	            	for(int i = 0; i < dataList.size(); i++) {
	    	            		if(i < dataList.size()-1) {
	    	            			sql += "\'" + dataList.get(i) + "\',";
	    	            		}else {
	    	            			sql += "\'" + dataList.get(i) + "\'";
	    	            		}
	    	            	}
	    	            	sql += ")\n";
	        			}
		            }else{
		            	for (int i = 0; i < whereList.size(); i++) {
		            		String whereListKey = whereList.getJSONObject(i).getString("key");
		            		JSONArray whereListData = whereList.getJSONObject(i).getJSONArray("data");
		            		/* DOGFOOT ktkang CUBRID 쿼리 오류 수정  20200701 */
			            	// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	
		            		//2020.11.12 MKSONG LIKE구문 추가 DOGFOOT
		            		if(whereListData.get(0).toString().indexOf("LIKEDATA:") > -1) {
		            			sql += "AND (\n";
		            			for(int j = 0; j < whereListData.size(); j++) {
		            				if(j == 0) {
		            					sql += "(";
		            				}else {
		            					sql += "OR (";
		            				}
		            				//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
		            				if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
			            				sql += whereListKey + " LIKE '%" + whereListData.get(j).toString().replaceAll("LIKEDATA:", "") + "%')\n";
		    	            		} else {
		    	            			//2020.11.27 mksong 카카오맵 like 오류 수정 dogfoot
		    	            			sql += "\"" + whereListKey + "\" LIKE \'%" + whereListData.get(j).toString().replaceAll("LIKEDATA:", "") + "%\')\n";
		    	            		}
	    		                }
		            			sql += ")\n";
	            			}else {
	            				//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	            				if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	    	            			sql += "AND	(" + whereListKey + " IN (";
	    	            		} else {
	    	            			sql += "AND	(\"" + whereListKey + "\" IN (";
	    	            		}
	    	            		for(int j = 0; j < whereListData.size(); j++) {
	    			            	if((whereListData.size()-1) > j) {
	    			            		sql += "\'" + whereListData.get(j) + "\',";
	    			            	}else {
	    			            		sql += "\'" + whereListData.get(j) + "\')";
	    			            	}
	    		                }
	
	    	            		sql += ")\n";
	            			}
	
	
						}
	
		            }
	
	            }
	
	          //2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
	            if(groupByList.size() != 0) {
	            	sql += "GROUP BY \t";
	                if(groupByList.size() == 1) {
		            	// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	                	//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	                	if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	            			sql += groupByList.getString(0) + "\n";
	            		} else {
	            			sql += "\"" + groupByList.getString(0) + "\"\n";
	            		}
	                }else {
	                	for(int i = 0; i < groupByList.size(); i++) {
	                    	if(i == groupByList.size()-1) {
	        	            	// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	                    		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	                    		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	                    			sql += groupByList.getString(i) + "\n";
	                    		} else {
	                    			sql += "\"" + groupByList.getString(i) + "\"\n";
	                    		}
	                    	}else {
	        	            	// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	                    		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	                    		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	                    			sql += groupByList.getString(i) + ", \t";
	                    		} else {
	                    			sql += "\"" + groupByList.getString(i) + "\", \t";
	                    		}
	                    	}
	                    }
	                }
	            }
	
	            //2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
	            if(orderByList.size() != 0) {
	            	sql += "ORDER BY \t";
	            	if(orderByList.size() == 1) {
	            		// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	            		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	            		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	            			sql += orderByList.getString(0) + "\n";
	            		} else {
	            			sql += "\"" + orderByList.getString(0) + "\"\n";
	            		}
	                }else {
	                	for(int i = 0; i < orderByList.size(); i++) {
	                		if(!(i+1 < orderByList.size())) {
	        	            	// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
	                			//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	                			if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	                    			sql += orderByList.getString(i) + "\n";
	                    		} else {
	                    			sql += "\"" + orderByList.getString(i) + "\"\n";
	                    		}
	                		}else {
	                			JSONObject result = this.switchSortDirectionSyntax(orderByList.getString(i),orderByList.getString(i+1), false);
	                    		if(result.getBoolean("isChanged")) {
	                    			i++;
	                    			if(i+1 < orderByList.size()) {
	                        			sql += result.getString("syntax") + ",\t";
	                        		}else {
	                        			sql += result.getString("syntax");
	                        		}
	                    		}
	                		}
	                    }
	                }
	            }
	
	            //ORIGIN
	//            if(join) {
	//            	sql = sql.replaceAll("RIGHT OUTER", "INNER");
	//            }
	            /* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
	            if(queryParam != null && queryParam.equals("dataCut")) {
	            	String line = System.getProperty("line.separator");
	            	if(dbtype.equals("MS-SQL")) {
	            		sql = "SELECT TOP 100 * FROM (\n"+sql+"\n)";
	            	} else if(dbtype.equals("DB2")) {
	            		sql = "\n"+sql+"\n FETCH FIRST 100 ROW ONLY";
	            	} else if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	            		sql = "\n"+sql+"\n LIMIT 100";
	            	} else {
	            		sql = "SELECT * FROM (\n"+sql+"\n) WHERE ROWNUM <= 100";
	            	}
	            	sql = sql.replace("\n", line);
	            }
	
	            if(dbtype.equals("IMPALA") || dbtype.equals("MARIA") || dbtype.equals("MYSQL")) {
	            	sql = sql.replaceAll("\"", "");
	            }
            }
            Timer timer2 = new Timer();
            
			final WebConfigMasterVO wbConfigVo = authenticationService.getWebConfigMstr();
			final org.json.JSONObject menuConf = new org.json.JSONObject(wbConfigVo.getMENU_CONFIG()).getJSONObject("Menu");
            
			// 쿼리 캐시기능 사용여부에 따른 예외처리
			Boolean bQryCashUsed = false;
			if (menuConf.has("QRY_CASH_USE")) {
				bQryCashUsed = (Boolean)menuConf.get("QRY_CASH_USE");
			}           

			if(CoreUtils.getCurrentRequest().getRequestURI().contains("/pivotSummaryMatrix.do")) {
				bQryCashUsed = false;
			}
			
			String queryResultCacheKey = null;
			final String keyDt = new SimpleDateFormat("yyyyMMdd").format(new Date());
			 if (bQryCashUsed) {
                final String argsInfo = new StringBuilder(1024).append(dataSourceId).append(':')
                        .append(dataSourceType).append(':').append(sql).append(':').append(params)
                        .append(':').append(queryParam).append(':').append(sqlConfig).append(':')
                        .toString();
                queryResultCacheKey = DigestUtils.sha256Hex(argsInfo);
            }
			 
			 if (StringUtils.isNotBlank(queryResultCacheKey)) {
				 retResult = (FileBackedJSONObjectList) queryResultCacheManager
                        .getQueryResultCache(queryResultCacheKey);

                if (retResult != null) {
                    logger.debug("Query result retrieved from in-memory cache, key: {}",
                            queryResultCacheKey);
                } else {
                    String uploadPath = "UploadFiles/cache_csv/" + keyDt + "/";
                    final String filePath = uploadPath + queryResultCacheKey + ".csv";
                    final File csvFile = new File(filePath);
                    
                    if (csvFile.exists()) {
	                    retResult = (FileBackedJSONObjectList) readCacheCsv(csvFile);
	                    final long csvFileLen = csvFile.length();
	                    queryResultCacheManager.putQueryResultCache(queryResultCacheKey, retResult, csvFileLen);
	
	                    if (retResult != null) {
	                        logger.debug(
	                                "Query result retrieved from file cache to put in in-memory cache, key: {}",
	                                queryResultCacheKey);
	                    }
                    }
                }
            }
			
			// cache csv 파일 존재 하지 않을때
			if (retResult == null) {
				logger.debug("Query result not found in neither file nor in-memory cache, key: {}",
                        queryResultCacheKey);
				
				
				retResult = new FileBackedJSONObjectList();
				connection = this.getConnection(dataSourceId, dataSourceType);
	            logger.debug("sqlike query : " + sql);

	            pstmt = connection.prepareStatement(sql);

	            if(sqlTimeout > 0) {
	            	pstmt.setQueryTimeout(sqlTimeout);
	            }
	            
	            if(pstmt != null) {
	            	try(WdcTask task = WDC.getCurrentTask().startSubtask("DataSetService.executeQuery")){
	            		resultSet = pstmt.executeQuery();
	            	}
	            } else {
	            	resultSet = null;
	            }

	            timer2.start();
	            /* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
	            boolean nullRemove = false;
	            String nullRemoveType = null;
	            List<String> nullDimensions = new ArrayList<String>();
	            /* DOGFOOT ktkang Null Data 제거 기능 오류 수정  20200909 */
	            if(nullDimension.isNullObject() == false && nullDimension.has("0")) {
	            	nullRemoveType = nullDimension.getString("0");
	            	if(!nullRemoveType.equals("noRemove")) {
	            		nullRemove = true;
	            		for (int i = 1; i < nullDimension.size(); i++) {
	            			nullDimensions.add(nullDimension.getString(String.valueOf(i)));
	            		}
	            	}
	            }
	            ResultSetMetaData md = resultSet.getMetaData();
	            int count = 0;
	            while (resultSet.next()) {
	            	JSONObject row = new JSONObject();
	            	/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
	            	boolean nullNotAllCheck = false;
	            	if(nullRemove) {
	            		boolean nullAllCheck = false;
	            		for (int i = 1; i <= md.getColumnCount(); i++) {
	            			DataField field =  new DataField(i, md, resultSet.getObject(i));
	            			
	            			/* DOGFOOT syjin 피벗그리드 빈칼럼 데이터 제거 되도록 수정 20210608 */
	            			if (field.getValue().isNull() || String.valueOf(field.getValue()).trim().isEmpty()) {
	            				nullAllCheck = true;
	            				nullNotAllCheck = true;
	            				break;
	            			}
	            		}
	            		if(nullAllCheck && nullRemoveType.equals("allNullRemove")) {
	            			continue;
	            		}
	            	}

	            	/* DOGFOOT ajkim 피벗그리드 null 처리 방법 수정 20201207 */
	                for (int i = 1; i <= md.getColumnCount(); i++) {
	                	DataField field =  new DataField(i, md, resultSet.getObject(i));
	                	if(nullRemove && nullNotAllCheck) {
	                		if(nullRemoveType.equals("colNullRemove") || nullRemoveType.equals("rowNullRemove")) {
	                			if(nullDimensions.indexOf(md.getColumnName(i)) < 0) {
	                				if(itemType.equals("PIVOT_GRID"))
	                					row.put(md.getColumnName(i),  field.getValue().isNull()? "wise_null_value" : JavaxtUtils.getValue(field));
	                				else
	                					row.put(md.getColumnName(i),  JavaxtUtils.getValue(field));
	                			}
	                		}
	                	} else {
	                		if(itemType.equals("PIVOT_GRID"))
	        					row.put(md.getColumnName(i),  field.getValue().isNull()? "wise_null_value" : JavaxtUtils.getValue(field));
	        				else
	        					row.put(md.getColumnName(i),  JavaxtUtils.getValue(field));
	                	}

//	                    DataField field =  new DataField(i, md, resultSet.getObject(i));
	//
////	                    row.put(md.getColumnLabel(i), JavaxtUtils.getValue(field));
////	                    row.put(md.getColumnLabel(i), resultSet.getString(i));
////	                    row.put(md.getColumnName(i), JavaxtUtils.getValue(field));
//	                    if (field.getValue().isNull()) {
////	                        row.put(md.getColumnName(i), null);
//	                    }
//	                    else {
//	                        row.put(md.getColumnName(i), JavaxtUtils.getValue(field));
//	                    }
	                }

	                retResult.add(row);
	                
	                if(++count%1000 == 0) {
	                	ServiceTimeoutUtils.checkServiceTimeout();
	                }
	            }
	            
	            timer2.stop();
	            
	            if (bQryCashUsed && StringUtils.isNotBlank(queryResultCacheKey)) {
                    // 캐시용 CSV 파일 생성
                    final String relPath = "cache_csv/" + keyDt + "/";
                    createCacheCsvFile(queryResultCacheKey, relPath, ResultSetMetaDataUtils.getColumnNames(md), retResult); // 헤더 재활용을 위해 ResultSetMetaData를 넘김
                    logger.debug("Query result file cached at {}, key: {}", relPath,
                            queryResultCacheKey);
                }
			}
            
            retResult.setAttribute("sql", sql);
            /* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
//            JSONObject sqlJson = new JSONObject();
//            sqlJson.put("sql", sql);
            // 2021-07-28
            // sqlJson.put("sql", AesCrypto.encrypt(CRYPTO_KEY_SIZE, CRYPTO_KEY, sql));
//            retResult.add(sqlJson);
        } catch (Exception e) {
        	e.printStackTrace();
        	throw e;
        } finally {
        	if (resultSet != null) {
        		try {
             		resultSet.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		resultSet = null;
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

        return retResult;
    }

    public CloseableList<JSONObject> sparkSqlLike(ArrayList<Integer> dsid, ArrayList<String> tblnm, String dataSourceType, String sql, JSONObject params, int sqlTimeout, String queryParam, JSONObject sqlConfig)
	throws	Exception {
    	CloseableList<JSONObject> ret = new FileBackedJSONObjectList();

		try {
		    sql = this.sqlMapper.mapParameter(sql, params);
		    logger.debug("sql(param) : " + sql);

		    sql = this.sqlConvertor.convert(sql);
		    logger.debug("sql(converted) : " + sql);

            sql = "WITH WISE_SQL_LIKE AS (\n" + sql + "\n)";

            JSONArray selectList = sqlConfig.getJSONArray("Select");
            JSONArray groupByList = new JSONArray();
            JSONArray fromList = new JSONArray();
            JSONArray whereList = new JSONArray();
            JSONArray orderByList = new JSONArray();

            if(sqlConfig.containsKey("GroupBy")) {
            	groupByList = sqlConfig.getJSONArray("GroupBy");
            }

            if(sqlConfig.containsKey("Where")) {
            	whereList = sqlConfig.getJSONArray("Where");
            }

            if(sqlConfig.containsKey("OrderBy")) {
            	orderByList = sqlConfig.getJSONArray("OrderBy");
            }

            if(sqlConfig.containsKey("isDiscountQuery")) {
            	sql += "SELECT Distinct ";
            }else {
            	sql += "SELECT ";
            }

            if(selectList.size() == 1) {
            	if(selectList.getString(0).equals("*")) {
            		sql += selectList.getString(0) + "\n";
            	}else {
            		sql += "`" + selectList.getString(0) + "`\n";
            	}
            }else {
            	for(int i = 0; i < selectList.size(); i++) {
                	if(i == selectList.size()-1) {
               			sql += "`" + selectList.getString(i) + "`\n";
                	}else {
                		JSONObject result = this.switchAggregateSyntax(selectList.getString(i),selectList.getString(i+1), true);
                		if(result.getBoolean("isChanged")) {
                			i++;
                			if(i+1 < selectList.size()) {
                				if(selectList.getString(i+1).equalsIgnoreCase("|as|")) {
                        			i++;
                        			sql += result.getString("syntax") + "\t" + "AS\t";
                        		}else {
                        			sql += result.getString("syntax") + ",\t";
                        		}
                			}else {
                				sql += result.getString("syntax") + "\n";
                			}
                		}else {
                			if(i+1 < selectList.size()) {
                				if(selectList.getString(i+1).equalsIgnoreCase("|as|")) {
                        			i++;
                           			sql += "`" + result.getString("syntax") + "`\t" + "AS\t";
                        		}else {
                           			sql += "`" + result.getString("syntax") + "`,\t";
                        		}
                			}
                		}
                	}
                }
            }

            sql += "FROM	WISE_SQL_LIKE \n";

            if(whereList.size() > 0) {
            	sql += "WHERE	1=1\n";
	            if(whereList.size() == 1) {
	            	JSONArray dataList = whereList.getJSONObject(0).getJSONArray("data");
           			sql += "AND	`" + whereList.getJSONObject(0).getString("key") + "` IN (";
	            	for(int i = 0; i < dataList.size(); i++) {
	            		if(i < dataList.size()-1) {
	            			sql += "\'" + dataList.get(i) + "\',";
	            		}else {
	            			sql += "\'" + dataList.get(i) + "\'";
	            		}
	            	}
	            	sql += ")\n";
	            }else{
	            	for (int i = 0; i < whereList.size(); i++) {
	            		String whereListKey = whereList.getJSONObject(i).getString("key");
	            		JSONArray whereListData = whereList.getJSONObject(i).getJSONArray("data");
            			sql += "AND	(" + whereListKey + " IN (";
	            		for(int j = 0; j < whereListData.size(); j++) {
			            	if((whereListData.size()-1) > j) {
			            		sql += "\'" + whereListData.get(j) + "\',";
			            	}else {
			            		sql += "\'" + whereListData.get(j) + "\')";
			            	}
		                }
		            	sql += ")\n";
					}
	            }
            }

            if(groupByList.size() != 0) {
            	sql += "GROUP BY \t";
                if(groupByList.size() == 1) {
           			sql += "`" + groupByList.getString(0) + "`\n";
                }else {
                	for(int i = 0; i < groupByList.size(); i++) {
                    	if(i == groupByList.size()-1) {
                   			sql += "`" + groupByList.getString(i) + "`\n";
                    	}else {
                   			sql += "`" + groupByList.getString(i) + "`, \t";
                    	}
                    }
                }
            }

            if(orderByList.size() != 0) {
            	sql += "ORDER BY \t";
            	if(orderByList.size() == 1) {
           			sql += "`" + orderByList.getString(0) + "`\n";
                }else {
                	for(int i = 0; i < orderByList.size(); i++) {
                		if(!(i+1 < orderByList.size())) {
                   			sql += "`" + orderByList.getString(i) + "`\n";
                		}else {
                			JSONObject result = this.switchSortDirectionSyntax(orderByList.getString(i),orderByList.getString(i+1), true);
                    		if(result.getBoolean("isChanged")) {
                    			i++;
                    			if(i+1 < orderByList.size()) {
                        			sql += result.getString("syntax") + ",\t";
                        		}else {
                        			sql += result.getString("syntax");
                        		}
                    		}
                		}
                    }
                }
            }

		    if(queryParam != null && queryParam.equals("dataCut")) {
		    	String line = System.getProperty("line.separator");
	    		sql = "\n"+sql+"\n LIMIT 100";
		    	sql = sql.replace("\n", line);
		    }

        	Dataset<org.apache.spark.sql.Row> dfRes = sparkExec(dsid, tblnm, sql);

//        	Timer timer1 = new Timer();
//    		timer1.start();
    		List<String> jsonStrList = dfRes.toJSON().collectAsList();
//    		timer1.stop();
//    		System.out.println("DataFrame casting time : " + timer1.getInterval());

//    		Timer timer2 = new Timer();
//    		timer2.start();
    		for (String str:jsonStrList) {
    			ret.add(JSONObject.fromObject(JSONSerializer.toJSON(str)));
    		}
//    		timer2.stop();
//    		System.out.println("json List Loop : " + timer2.getInterval() + " list Size : " + list.size());

			JSONObject sqlJson = new JSONObject();
		    sqlJson.put("sql", sql);
		    ret.add(sqlJson);

		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}

		return ret;
	}

	public CloseableList<JSONObject> sparkJson(JSONArray jsonData, String sql, JSONObject params, String queryParam, JSONObject sqlConfig)  throws	Exception {
		CloseableList<JSONObject> ret = new FileBackedJSONObjectList();

		try {
			/*
		    sql = this.sqlMapper.mapParameter(sql, params);
		    logger.debug("sql(param) : " + sql);

		    sql = this.sqlConvertor.convert(sql);
		    logger.debug("sql(converted) : " + sql);
		    */
			sql = "select * from df0";

            sql = "WITH WISE_SQL_LIKE AS (\n" + sql + "\n)";

            JSONArray selectList = sqlConfig.getJSONArray("Select");
            JSONArray groupByList = new JSONArray();
            JSONArray fromList = new JSONArray();
            JSONArray whereList = new JSONArray();
            JSONArray orderByList = new JSONArray();

            if(sqlConfig.containsKey("GroupBy")) {
            	groupByList = sqlConfig.getJSONArray("GroupBy");
            }

            if(sqlConfig.containsKey("Where")) {
            	whereList = sqlConfig.getJSONArray("Where");
            }

            if(sqlConfig.containsKey("OrderBy")) {
            	orderByList = sqlConfig.getJSONArray("OrderBy");
            }

            if(sqlConfig.containsKey("isDiscountQuery")) {
            	sql += "SELECT Distinct ";
            }else {
            	sql += "SELECT ";
            }

            if(selectList.size() == 1) {
            	if(selectList.getString(0).equals("*")) {
            		sql += selectList.getString(0) + "\n";
            	}else {
            		sql += "`" + selectList.getString(0) + "`\n";
            	}
            }else {
            	for(int i = 0; i < selectList.size(); i++) {
                	if(i == selectList.size()-1) {
               			sql += "`" + selectList.getString(i) + "`\n";
                	}else {
                		JSONObject result = this.switchAggregateSyntax(selectList.getString(i),selectList.getString(i+1), true);
                		if(result.getBoolean("isChanged")) {
                			i++;
                			if(i+1 < selectList.size()) {
                				if(selectList.getString(i+1).equalsIgnoreCase("|as|")) {
                        			i++;
                        			sql += result.getString("syntax") + "\t" + "AS\t";
                        		}else {
                        			sql += result.getString("syntax") + ",\t";
                        		}
                			}else {
                				sql += result.getString("syntax") + "\n";
                			}
                		}else {
                			if(i+1 < selectList.size()) {
                				if(selectList.getString(i+1).equalsIgnoreCase("|as|")) {
                        			i++;
                           			sql += "`" + result.getString("syntax") + "`\t" + "AS\t";
                        		}else {
                           			sql += "`" + result.getString("syntax") + "`,\t";
                        		}
                			}
                		}
                	}
                }
            }

            sql += "FROM	WISE_SQL_LIKE \n";

            if(whereList.size() > 0) {
            	sql += "WHERE	1=1\n";
	            if(whereList.size() == 1) {
	            	JSONArray dataList = whereList.getJSONObject(0).getJSONArray("data");
           			sql += "AND	`" + whereList.getJSONObject(0).getString("key") + "` IN (";
	            	for(int i = 0; i < dataList.size(); i++) {
	            		if(i < dataList.size()-1) {
	            			sql += "\'" + dataList.get(i) + "\',";
	            		}else {
	            			sql += "\'" + dataList.get(i) + "\'";
	            		}
	            	}
	            	sql += ")\n";
	            }else{
	            	for (int i = 0; i < whereList.size(); i++) {
	            		String whereListKey = whereList.getJSONObject(i).getString("key");
	            		JSONArray whereListData = whereList.getJSONObject(i).getJSONArray("data");
            			sql += "AND	(" + whereListKey + " IN (";
	            		for(int j = 0; j < whereListData.size(); j++) {
			            	if((whereListData.size()-1) > j) {
			            		sql += "\'" + whereListData.get(j) + "\',";
			            	}else {
			            		sql += "\'" + whereListData.get(j) + "\')";
			            	}
		                }
		            	sql += ")\n";
					}
	            }
            }

            if(groupByList.size() != 0) {
            	sql += "GROUP BY \t";
                if(groupByList.size() == 1) {
           			sql += "`" + groupByList.getString(0) + "`\n";
                }else {
                	for(int i = 0; i < groupByList.size(); i++) {
                    	if(i == groupByList.size()-1) {
                   			sql += "`" + groupByList.getString(i) + "`\n";
                    	}else {
                   			sql += "`" + groupByList.getString(i) + "`, \t";
                    	}
                    }
                }
            }

            if(orderByList.size() != 0) {
            	sql += "ORDER BY \t";
            	if(orderByList.size() == 1) {
           			sql += "`" + orderByList.getString(0) + "`\n";
                }else {
                	for(int i = 0; i < orderByList.size(); i++) {
                		if(!(i+1 < orderByList.size())) {
                   			sql += "`" + orderByList.getString(i) + "`\n";
                		}else {
                			JSONObject result = this.switchSortDirectionSyntax(orderByList.getString(i),orderByList.getString(i+1), true);
                    		if(result.getBoolean("isChanged")) {
                    			i++;
                    			if(i+1 < orderByList.size()) {
                        			sql += result.getString("syntax") + ",\t";
                        		}else {
                        			sql += result.getString("syntax");
                        		}
                    		}
                		}
                    }
                }
            }

            /*
		    if(queryParam != null && queryParam.equals("dataCut")) {
		    	String line = System.getProperty("line.separator");
	    		sql = "\n"+sql+"\n LIMIT 100";
		    	sql = sql.replace("\n", line);
		    }
		    */

            //System.out.println(jsonData.toString());

            ArrayList<String> jList = new ArrayList<String>();
            for(int i=0;i<jsonData.size();i++) {
            	jList.add(jsonData.getString(i));
            }

        	String os = System.getProperty("os.name").toLowerCase();
        	if(os.indexOf("win")>-1) {
        		System.setProperty("hadoop.home.dir", Configurator.getInstance().getApplicationContextRealLocation()+"WEB-INF\\hadoop");
        	}
			/* DOGFOOT ktkang 스케줄링 spark 부분 에러 수정  20201008 */
        	SparkSession spark = this.sparkLoad.sparkSession();
        	SparkContext sparkContext = spark.sparkContext();
//        	if(sparkContext==null || sparkContext.isStopped()) {
//        		SparkConf conf = new SparkConf().set("spark.driver.allowMultipleContexts", "true").setAppName("WiseIntelligenceJson").setMaster("local");
//        		sparkContext = new SparkContext(conf);
//        	}
//
//			sparkContext.setLogLevel("ERROR");
			JavaSparkContext javaSparkContext = new JavaSparkContext(sparkContext);
//            //SparkSession spark = this.sparkLoad.sparkSession();
			SQLContext sqlContext = new SQLContext(spark);
			JavaRDD<String> javaRDD = javaSparkContext.parallelize(jList);
			Dataset<org.apache.spark.sql.Row> df = sqlContext.read().json(javaRDD);
			df.createOrReplaceTempView("df0");
			//df.show();

			//spark의 컬럼명이 한글을 인식할려면 ` 특수문자가 붙어야 한다
			Pattern pattern1 = Pattern.compile("\\.[a-zA-Zㄱ-ㅎㅏ-ㅣ가-힣0-9_]*");
			Matcher matcher1 = pattern1.matcher(sql);
			while (matcher1.find()) {
				String str = matcher1.group(0);
			    sql = sql.replaceFirst("\\."+str.substring(1), "\\.`"+str.substring(1)+"`");
			}
			Pattern pattern2 = Pattern.compile("[aA][sS] [a-zA-Zㄱ-ㅎㅏ-ㅣ가-힣0-9_]*");
			Matcher matcher2 = pattern2.matcher(sql);
			while (matcher2.find()) {
				String str = matcher2.group(0);
				if(!"".equals(str.substring(3))) sql = sql.replaceFirst("[aA][sS] "+str.substring(3), "AS `"+str.substring(3)+"`");
			}

			Dataset<org.apache.spark.sql.Row> dfRes = sqlContext.sql(sql);
			//dfRes.show();

			for(String str:dfRes.toJSON().collectAsList()) {
				ret.add(JSONObject.fromObject(JSONSerializer.toJSON(str)));
			}

		    JSONObject sqlJson = new JSONObject();
		    sqlJson.put("sql", sql);
		    ret.add(sqlJson);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} finally {
		}

		return ret;
	}

    public JSONObject switchAggregateSyntax(String currentSyntax, String nextSyntax, boolean multiDb) throws Exception {
    	JSONObject ret = new JSONObject();
    	String [] aggregateList = {"|sum|","|min|","|max|","|count|","|countdistinct|","|avg|"};
    	boolean isChanged = false;

    	for (int i = 0; i < aggregateList.length; i++) {
    		if(aggregateList[i].equalsIgnoreCase(currentSyntax)) {
    			isChanged = true;
    			currentSyntax = currentSyntax.replaceAll("\\d|\\|", "");
    			/*dogfoot 고유 카운트 설정 오류 수정 shlim 20210421*/
    			if(currentSyntax.equals("countdistinct")) {
    				currentSyntax = "COUNT";
    				if(multiDb) {
        				currentSyntax += "( DISTINCT `" + nextSyntax + "`)";
        			} else {
        				currentSyntax += "( DISTINCT \"" + nextSyntax + "\")";
        			}
    			}else {
    				if(multiDb) {
        				currentSyntax += "(`" + nextSyntax + "`)";
        			} else {
        				currentSyntax += "(\"" + nextSyntax + "\")";
        			}
    			}
    			//2020.07.17 mksong with절 사용하는 쿼리 오류 보완
//    			currentSyntax += "(WISE_SQL_LIKE.\"" + nextSyntax + "\")";
    			
    		}
    	}

		ret.put("syntax", currentSyntax);
    	ret.put("isChanged", isChanged);
    	return ret;
    }

    public JSONObject switchSortDirectionSyntax(String currentSyntax, String nextSyntax, boolean multiDb) throws Exception {
    	JSONObject ret = new JSONObject();
    	//2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
    	String [] sortDirectionList = {"|asc|","|desc|"};
    	boolean isChanged = false;

    	for (int i = 0; i < sortDirectionList.length; i++) {
    		if(sortDirectionList[i].equalsIgnoreCase(nextSyntax)) {
    			isChanged = true;
    			nextSyntax = nextSyntax.replaceAll("\\d|\\|", "");
    			nextSyntax = nextSyntax.toUpperCase();
    			if(multiDb) {
    				currentSyntax = "`" + currentSyntax + "`\t" + nextSyntax;
    			} else {
    				currentSyntax = "\"" + currentSyntax + "\"\t" + nextSyntax;
    			}
    		}
    	}

    	ret.put("syntax", currentSyntax);
    	ret.put("isChanged", isChanged);

    	return ret;
    }

    @Override
	public CloseableList<JSONObject> queryTableSql(int datasrc_id, String datasrc_type, String sql, JSONObject params, int sqlTimeout,
			boolean join, String sqlType) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
		// TODO Auto-generated method stub
		Connection connection = null;
		PreparedStatement pstmt = null;
        ResultSet resultSet = null;

        CloseableList<JSONObject> ret = new FileBackedJSONObjectList();

        try {
        	if(join) {
        		DataSetMasterVO dataSetInfo = this.getDataSourceInfo(datasrc_id, datasrc_type);
        		sql = this.sqlConvertor.convertTopN(sql, dataSetInfo.getDatabaseType(), 1);
        	}
            /**
             * sql mapper 생성 및 활용해야 할 부분
             * - client에서 전달받온 parameter를 name과 type을 이용하여 sql에 value를  mapping
             */
            /* DOGFOOT ktkang 데이터 집합 기본값 USE_SQL 로 되어있을 때 오류 수정  20200701 */
        	if(sqlType != null && sqlType.equals("dataset")) {
        		/*dogfoot shlim 20210414*/
        		sql = this.sqlMapper.mapParameter(sql, params, sqlType,null);
        	} else {
        		sql = this.sqlMapper.mapParameter(sql, params);
        	}
            logger.debug("sql(param) : " + sql);

            sql = this.sqlConvertor.convert(sql);
            logger.debug("sql(converted) : " + sql);

            connection = this.getConnection(datasrc_id, datasrc_type);
            pstmt = connection.prepareStatement(sql);
            
            logger.debug("sql(finalSQL) : " + sql);
            
            Timer timer1 = new Timer();
            timer1.start();

            if(sqlTimeout > 0) {
            	pstmt.setQueryTimeout(sqlTimeout);
            }
            if(pstmt != null) {
            	resultSet = pstmt.executeQuery();
            } else {
            	resultSet = null;
            }
            
            timer1.stop();

            Timer timer2 = new Timer();
            timer2.start();

            ResultSetMetaData md = resultSet.getMetaData();
            JSONObject row = new JSONObject();
            for(int i=1;i<=md.getColumnCount();i++) {
            	//컬럼헤더에 빈값이면 오류 표시로
                if(md.getColumnLabel(i).equals("")) throw new SQLException();

            	switch (md.getColumnType(i)) {
            		//2020.09.15 MKSONG 마리아DB FLOAT 타입 오류 수정 DOGFOOT
            		case Types.BIGINT:
            		case Types.DECIMAL:
            		case Types.DOUBLE:
            		case Types.FLOAT:
            		case Types.INTEGER:
            		case Types.TINYINT:
            		case Types.SMALLINT:
            		case Types.NUMERIC:
            		case Types.REAL:
            			//2020.09.15 MKSONG 마리아DB 컬럼 ALIAS 오류 수정 DOGFOOT
            			row.put(md.getColumnLabel(i), "decimal");
            			break;
        			default:
        				//2020.09.15 MKSONG 마리아DB 컬럼 ALIAS 오류 수정 DOGFOOT
        				row.put(md.getColumnLabel(i), "varchar");
            	}
            }
            ret.add(row);
            timer2.stop();

            logger.debug("queried count : " + ret.size());
            logger.debug("sql quering time : " + timer1.getInterval());
            logger.debug("result loop time : " + timer2.getInterval());
        }  catch (Throwable e) {
        	logger.error("failed to queryTableSql.", e);
        	throw e;
        } finally {
        	if (pstmt != null) {
        		try {
        			pstmt.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		pstmt = null;
             	}
        	}
        	if (resultSet != null) {
        		try {
             		resultSet.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		resultSet = null;
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

        return ret;
	}

	public CloseableList<JSONObject> querySparkSql(ArrayList<Integer> dsid, ArrayList<String> tblnm, String datasrc_type, String sql, JSONObject params, int sqlTimeout,
			boolean join, String sqlType) throws NotFoundDatabaseConnectorException, EmptyDataSetInformationException, NotFoundDataSetTypeException, UndefinedDataTypeForNullValueException, SQLException {
		CloseableList<JSONObject> ret = new FileBackedJSONObjectList();

        try {
        	if(sqlType != null && sqlType.equals("dataset")) {
        		/*dogfoot shlim 20210414*/
        		sql = this.sqlMapper.mapParameter(sql, params, sqlType,null);
        	} else {
        		sql = this.sqlMapper.mapParameter(sql, params);
        	}
            logger.debug("sql(param) : " + sql);

            sql = this.sqlConvertor.convert(sql);
            logger.debug("sql(converted) : " + sql);

            if(join) {
            	sql = sql.replaceAll("RIGHT OUTER", "INNER");
            }

            Dataset<org.apache.spark.sql.Row> dfRes = sparkExec(dsid, tblnm, sql);

            JSONObject row = new JSONObject();
			for(StructField st:dfRes.schema().fields()) {
				String columnName = st.name();
				String columnType = st.dataType().toString();
				if(columnType.indexOf("Decimal")>-1 || columnType.indexOf("Long")>-1) {
					row.put(columnName, "decimal");
				} else {
					row.put(columnName, "varchar");
				}
			}
            ret.add(row);

            logger.debug("queried count : " + ret.size());
        } catch (Exception e) {
        	e.printStackTrace();
        	throw e;
    	}

        return ret;
	}

	@Override
	public SubjectMasterVO getDatasourceInfoById(int id) {
		return dataSetDAO.getDatasourceInfoById(id);
	}

	@Override
	public SubjectCubeMasterVO getCubeDatasourceInfoById(int id) {
		return dataSetDAO.getCubeDatasourceInfoById(id);
	}

	@Override
	public CloseableList<JSONObject> getTableList(int dataSourceId, String dataSourceType, String requestType, String searchWord) {
		DataSetMasterVO dataSetInfo = this.getDataSourceInfo(dataSourceId,dataSourceType);
		SqlForEachMartDbType sqlFor = new SqlForEachMartDbType();
		String sql = sqlFor.SqlForEachDbType(
			dataSetInfo.getDatabaseType(),
			"TABLE",
			dataSetInfo.getDatabaseOwner(),
			dataSetInfo.getDatabaseName(),
			"",
			searchWord
		);
		CloseableList<JSONObject> result = new FileBackedJSONObjectList();
		try {
			result = this.querySql(dataSourceId, dataSourceType, sql, new JSONObject(), 0, null);
		} catch (NotFoundDatabaseConnectorException | EmptyDataSetInformationException | NotFoundDataSetTypeException
				| UndefinedDataTypeForNullValueException | SQLException e) {
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println("Unknown exception occurred.");
			e.printStackTrace();
		}

		if(dataSetInfo.getDatabaseType().equals("IMPALA")) {
			for (int i = 0; i < result.size(); i++) {
				if (result.get(i) instanceof JSONObject) {
					JSONObject dataItem = result.get(i);
					String caption = dataItem.getString("name");
					dataItem.put("TBL_NM", caption);
					dataItem.put("TBL_CAPTION", "");
					dataItem.put("text", caption);
					dataItem.put("parent", "");
					dataItem.put("id", caption);
					dataItem.put("isDirectory", true);
					dataItem.put("hasItems", true);
					dataItem.put("TYPE", "TABLE");
				}
			}
		} else {
			for (Iterator<JSONObject> it = result.iterator(); it.hasNext(); ) {
				JSONObject dataItem = it.next();

				//Object obj = dataItem.get("TBL_CAPTION");
				String caption = dataItem.getString("TBL_CAPTION");
				if (caption == null || caption.length() == 0) {
					caption = dataItem.getString("TBL_NM");
				}

				dataItem.put("text", caption);
				dataItem.put("parent", "");
				dataItem.put("id", dataItem.getString("TBL_NM"));
				dataItem.put("isDirectory", true);
				dataItem.put("hasItems", true);
				dataItem.put("TYPE", "TABLE");
			}
		}
		return result;
	}

	@Override
	public CloseableList<JSONObject> getColumnList(int dataSourceId, String dataSourceType, String requestType, String tableName) {
		DataSetMasterVO dataSetInfo = this.getDataSourceInfo(dataSourceId,dataSourceType);
		SqlForEachMartDbType sqlFor = new SqlForEachMartDbType();
		String sql = sqlFor.SqlForEachDbType(
			dataSetInfo.getDatabaseType(),
			"COLUMN",
			dataSetInfo.getDatabaseOwner(),
			dataSetInfo.getDatabaseName(),
			tableName,
			null
		);
		CloseableList<JSONObject> result = new FileBackedJSONObjectList();
		try {
			result = this.querySql(dataSourceId, dataSourceType, sql, new JSONObject(), 0, null);
		} catch (NotFoundDatabaseConnectorException | EmptyDataSetInformationException | NotFoundDataSetTypeException
				| UndefinedDataTypeForNullValueException | SQLException e) {
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println("Unknown exception occurred.");
			e.printStackTrace();
		}


		if(dataSetInfo.getDatabaseType().equals("IMPALA")) {
			for (int i = 0; i < result.size(); i++) {
				if (result.get(i) instanceof JSONObject) {
					JSONObject dataItem = result.get(i);

					String name = dataItem.getString("name");
					String type = dataItem.getString("type");
					String comment = dataItem.getString("comment");
					dataItem.put("TBL_NM", tableName);
					dataItem.put("TBL_CAPTION", "");
					dataItem.put("COL_NM", name);
					dataItem.put("COL_CAPTION", comment);
					dataItem.put("DATA_TYPE", type);
					dataItem.put("LENGTH", "0");
					dataItem.put("COL_ID", "");
					dataItem.put("PK_YN", "N");

					String caption = comment;
					if (caption == null || caption.length() == 0) {
						caption = name;
					}

					dataItem.put("text", caption);
					dataItem.put("parent", tableName);
					dataItem.put("id", tableName + "-" + caption);
					dataItem.put("isDirectory", false);
					dataItem.put("hasItems", false);
					dataItem.put("TYPE", "COLUMN");
					dataItem.put("dataset_src", dataSourceId);
				}
			}
		} else {
			for (Iterator<JSONObject> it = result.iterator(); it.hasNext(); ) {
				JSONObject dataItem = it.next();
				String table = "".equals(tableName) ? "" : dataItem.getString("TBL_NM");
				String caption = dataItem.getString("COL_CAPTION");
				if (caption == null || caption.length() == 0) {
					caption = dataItem.getString("COL_NM");
				}

				dataItem.put("text", caption);
				dataItem.put("parent", table);
				dataItem.put("id", table + "-" + caption);
				dataItem.put("isDirectory", false);
				dataItem.put("hasItems", false);
				dataItem.put("TYPE", "COLUMN");
				dataItem.put("dataset_src", dataSourceId);
			}
		}
		return result;
	}

	@Override
	public CloseableList<JSONObject> getCubeTableColumnList(int cubeId) {
		CloseableList<JSONObject> result = new FileBackedJSONObjectList();
		CubeTableVO param = new CubeTableVO(cubeId);

		List<CubeTableVO> measures = this.dataSetDAO.selectCubeReportMeasureTableList(cubeId);
        List<CubeTableVO> dimensions = this.dataSetDAO.selectCubeReportDimensionTableList(cubeId);
        List<CubeTableColumnVO> cubeTableMeaColumns = this.dataSetDAO.selectCubeReportMeasureTableColumnList(param);
        List<CubeTableColumnVO> cubeTableDimColumns = this.dataSetDAO.selectCubeReportDimensionTableColumnList(param);

        for (CubeTableVO cubeTable : measures) {
        	JSONObject measureTable = new JSONObject();
        	measureTable.put("id", cubeTable.getUniqueName());
        	measureTable.put("text", cubeTable.getLogicalName());
        	measureTable.put("TBL_NM", cubeTable.getLogicalName());
        	measureTable.put("TBL_CAPTION", cubeTable.getLogicalName());
        	measureTable.put("parent", "");
        	measureTable.put("isDirectory", true);
        	measureTable.put("hasItems", true);
        	measureTable.put("TYPE", "TABLE");
        	result.add(measureTable);
        }

        for (CubeTableVO cubeTable : dimensions) {

        	JSONObject dimensionTable = new JSONObject();
        	dimensionTable.put("id", cubeTable.getUniqueName());
        	dimensionTable.put("text", cubeTable.getLogicalName());
        	dimensionTable.put("TBL_NM", cubeTable.getLogicalName());
        	dimensionTable.put("TBL_CAPTION", cubeTable.getLogicalName());
        	dimensionTable.put("parent", "");
        	dimensionTable.put("isDirectory", true);
        	dimensionTable.put("hasItems", true);
        	dimensionTable.put("TYPE", "TABLE");
        	result.add(dimensionTable);
        }

        HashSet<String> meaColFolders = new HashSet<String>();
        for (CubeTableColumnVO cubeTableColumn : cubeTableMeaColumns) {
        	if (cubeTableColumn.getDataType() != null) {
        		String folderName = cubeTableColumn.getFolder();
        		String parentId = cubeTableColumn.getTableName();
        		if (folderName != null && folderName.length() > 0) {
        			if (!meaColFolders.contains(folderName)) {
        				meaColFolders.add(folderName);
        				JSONObject measureFolder = new JSONObject();
            			measureFolder.put("id", cubeTableColumn.getTableName() + "." + folderName);
            			measureFolder.put("text", folderName);
            			measureFolder.put("parent", cubeTableColumn.getTableName());
            			measureFolder.put("isDirectory", true);
            			measureFolder.put("hasItems", true);
            			measureFolder.put("TYPE", "FOLDER");
            			result.add(measureFolder);
        			}
        			parentId += "." + folderName;
        		}
            	JSONObject measureColumn = new JSONObject();
            	measureColumn.put("id", cubeTableColumn.getUniqueName());
            	measureColumn.put("text", cubeTableColumn.getCaptionName());
            	measureColumn.put("TBL_NM", cubeTableColumn.getLogicalTableName());
            	measureColumn.put("COL_NM", cubeTableColumn.getLogicalColumnName());
            	measureColumn.put("DATA_TYPE", cubeTableColumn.getDataType());
            	measureColumn.put("COL_CAPTION", cubeTableColumn.getCaptionName());
            	measureColumn.put("parent", parentId);
            	measureColumn.put("isDirectory", false);
            	measureColumn.put("hasItems", false);
            	measureColumn.put("TYPE", "COLUMN");
            	result.add(measureColumn);
        	}
        }

        HashSet<String> dimColFolders = new HashSet<String>();
        for (CubeTableColumnVO cubeTableColumn : cubeTableDimColumns) {
        	if (cubeTableColumn.getDataType() != null) {
        		String folderName = cubeTableColumn.getFolder();
        		String parentId = cubeTableColumn.getTableName();
        		if (folderName != null && folderName.length() > 0) {
        			if (!dimColFolders.contains(folderName)) {
        				dimColFolders.add(folderName);
	        			JSONObject dimensionFolder = new JSONObject();
	        			dimensionFolder.put("id", cubeTableColumn.getTableName() + "." + folderName);
	        			dimensionFolder.put("text", folderName);
	        			dimensionFolder.put("parent", cubeTableColumn.getTableName());
	        			dimensionFolder.put("isDirectory", true);
	        			dimensionFolder.put("hasItems", true);
	        			dimensionFolder.put("TYPE", "FOLDER");
	        			result.add(dimensionFolder);
        			}
        			parentId += "." + folderName;
        		}
            	JSONObject dimensionColumn = new JSONObject();
            	dimensionColumn.put("id", cubeTableColumn.getUniqueName());
            	dimensionColumn.put("text", cubeTableColumn.getCaptionName());
            	dimensionColumn.put("TBL_NM", cubeTableColumn.getPhysicalTableName());
            	dimensionColumn.put("COL_NM", cubeTableColumn.getPhysicalColumnName());
            	dimensionColumn.put("DATA_TYPE", cubeTableColumn.getDataType());
            	dimensionColumn.put("COL_CAPTION", cubeTableColumn.getCaptionName());
            	dimensionColumn.put("parent", parentId);
            	dimensionColumn.put("isDirectory", false);
            	dimensionColumn.put("hasItems", false);
            	dimensionColumn.put("TYPE", "COLUMN");
            	result.add(dimensionColumn);
        	}
        }

		return result;
	}

	@Override
	public List<TableRelationVO> selectCubeRelationList(CubeTableVO cubeTableVO) {
		return reportDAO.selectCubeRelationList(cubeTableVO);
	}
	
	@Override
	public String selectGoyongUserSosok(String iscd) {
		return reportDAO.selectGoyongUserSosok(iscd);
	}

	public Dataset<org.apache.spark.sql.Row> sparkExec(ArrayList<Integer> dsid, ArrayList<String> tblnm, String sql) {
		SparkSession spark = this.sparkLoad.sparkSession();

		logger.debug("이기종 before sql="+sql);
		
		//WISE_TBL_LIST 생성
		if(!spark.catalog().tableExists("WISE_TBL_LIST")) {
			StructType schema = new StructType(new StructField[] {
					new StructField("dbName", DataTypes.StringType, false, Metadata.empty()),
					new StructField("tblName", DataTypes.StringType, false, Metadata.empty()),
					new StructField("sparkTblName", DataTypes.StringType, false, Metadata.empty())
			});
			Dataset<org.apache.spark.sql.Row> wise_tbl_list = spark.read().schema(schema)
					.csv(spark.emptyDataset(Encoders.STRING()));
			wise_tbl_list.createOrReplaceTempView("WISE_TBL_LIST");
			spark.catalog().listTables().show();
			spark.catalog().cacheTable("wise_tbl_list");
		}
		
		int dsCnt = dsid.parallelStream().collect(Collectors.toList()).size();
		
		for(int j=0;j<dsCnt;j++) {
			
//			DataSetMasterVO dsVO = this.dataSetDAO.selectDataSetMaster(dsid.get(j));
//			String ip = dsVO.getDatabaseIp();
//			String port = dsVO.getDatabasePort();
//			String dbNm = dsVO.getDatabaseName();
//			String dbtype = dsVO.getDatabaseType();
//			String url = "";
//			String user = dsVO.getDatabaseUser();
//			String passwd = dsVO.getDatabasePassword();
//			String driverClass = "";
//			String sparkTblName = "";
//			boolean isExist = false;
//			
//			//sparkTblName 생성 및 WISE_TBL_LIST에 정보 등록
//			Dataset<org.apache.spark.sql.Row> wise_tbl_list2 = spark.sql("SELECT sparkTblName FROM wise_tbl_list WHERE dbName = '"+dbNm+"' AND tblName = '"+tblnm.get(j)+"'");
//			if(wise_tbl_list2.count() > 0) {
////				System.out.println(wise_tbl_list2.first().get(0).toString());
//				sparkTblName = wise_tbl_list2.first().get(0).toString();
//			}else {
//				int tblNum = 1;
//				if(spark.sql("SELECT * FROM wise_tbl_list").count() != 0)
//					tblNum = Integer.parseInt(spark.sql("SELECT sparkTblName FROM wise_tbl_list ORDER BY tblName DESC limit 1").first().get(0).toString().replaceAll("[^0-9]", "")) + 1;
//				sparkTblName = "wise_spark_table"+(tblNum);
//				wise_tbl_list2.show();
//				System.out.println("INSERT INTO wise_tbl_list VALUES ('"+dbNm+"', '"+tblnm.get(j)+"', '"+sparkTblName+"')");
////				spark.sql("INSERT INTO wise_tbl_list VALUES ('"+dbNm+"', '"+tblnm.get(j)+"', '"+sparkTblName+"')");
//				spark.sql("create or replace temporary view wise_tbl_list as select * from wise_tbl_list union select '"+dbNm+"' as dbName, '"+tblnm.get(j)+"' as tblName, '"+sparkTblName+"' as sparkTblName");
//				 spark.sql("SELECT sparkTblName FROM wise_tbl_list WHERE dbName = '"+dbNm+"' AND tblName = '"+tblnm.get(j)+"'").show();
//			}
//			
//			if(!spark.catalog().tableExists(sparkTblName)) {
//				if(dbtype.equals("MS-SQL")) {
//					driverClass = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
//					url = "jdbc:sqlserver://" + ip + ":" + port + ";DatabaseName=" + dbNm;
//				}
//				else if(dbtype.equals("DB2BLU")) {
//					driverClass = "com.ibm.db2.jcc.DB2Driver";
//					url = "jdbc:db2://" + ip + ":" + port + "/" + dbNm;
//				}
//				else if(dbtype.equals("ORACLE")) {
//					driverClass = "oracle.jdbc.driver.OracleDriver";
//					url = "jdbc:oracle:thin:@" + ip + ":" + port + ":" + dbNm;
//				}
//				else if(dbtype.equals("TIBERO")) {
//					driverClass = "com.tmax.tibero.jdbc.TbDriver";
//					url = "jdbc:tibero:thin:@" + ip + ":" + port + ":" + dbNm;
//				}
//				else if(dbtype.equals("ALTIBASE")) {
//					driverClass = "Altibase.jdbc.driver.AltibaseDriver";
//					url = "jdbc:Altibase://" + ip + ":" + port + "/" + dbNm;
//				}
//				else if(dbtype.equals("CUBRID")) {
//					driverClass = "cubrid.jdbc.driver.CUBRIDDriver";
//					url = "jdbc:cubrid:" + ip + ":" + port + ":" + dbNm + ":dba::";
//				}
//				else if(dbtype.equals("IMPALA")) {
//					driverClass = "com.cloudera.impala.jdbc41.Driver";
//					url = "jdbc:impala://" + ip + ":" + port + "/" + dbNm;
//				}
//				else if(dbtype.equals("MYSQL")) {
//					driverClass = "com.mysql.jdbc.Driver";
//					url = "jdbc:mysql://" + ip + ":" + port + "/" + dbNm;
//				}
//				else if(dbtype.equals("NETEZZA")) {
//					driverClass = "org.netezza.Driver";
//					url = "jdbc:netezza://" + ip + ":" + port + "/" + dbNm;
//				}
//				else if(dbtype.equals("MARIA")) {
//					driverClass = "org.mariadb.jdbc.Driver";
//					//maria는 데이터가 이상하게 나오는 경우가 있어서 url을 mysql로 함
//					//url = "jdbc:mariadb://" + ip + ":" + port + "/" + dbNm;
//					url = "jdbc:mysql://" + ip + ":" + port + "/" + dbNm;
//				}
//
//
//
//				/*dogfoot spark 파일 업로드 테스트 shlim 20210226*/
//
//				/*dogfoot spark 메모리 테이블 존재 여부 체크 shlim 20210218*/
//				/*boolean tabelCheck = spark.catalog().tableExists("`"+tblnm.get(j)+"`");
//
//				//없을때 추가
//				if(!tabelCheck) {
//					//테스트용 강제 하드코딩
//					if(tblnm.get(j).equals("F_자동차_작업일지")) {
//						/*스파크 파일 불러오기 테스트
//						 * option("header", true) : 데이터셋 저장시 헤더정보 포함 여부
//						 * */
//				/*
//						Dataset<org.apache.spark.sql.Row> df = spark.read().option("header", true).csv("../Develop/wise.rnd.ds.1/WebContent/UploadFiles/newReport_그리드 1.csv");
//
//						df.createOrReplaceTempView("`F_자동차_작업일지`");
//						df.persist(StorageLevel.MEMORY_AND_DISK_2());
//					}else {
//						Dataset<org.apache.spark.sql.Row> df = spark.read()
//						  .format("jdbc")
//						  .option("url", url)
//						  .option("driver", driverClass)
//						  .option("dbtable", tblnm.get(j))
//						  .option("user", user)
//						  .option("password", passwd)
//						  .load();
//						df.createOrReplaceTempView("`"+tblnm.get(j)+"`");
//						df.persist(StorageLevel.MEMORY_AND_DISK_2());
//					}
//
//				}
//				sql = sql.replaceAll(tblnm.get(j), "`"+tblnm.get(j)+"`");*/
//
//				//df.show();
//
//				//			Dataset<org.apache.spark.sql.Row> df = spark.read()
//				//			  .format("jdbc")
//				//			  .option("url", url)
//				//			  .option("driver", driverClass)
//				//			  .option("query", " SELECT      T_WISE_5176_76.대장번호 AS 대장번호\r\n" +
//				//			  		"FROM        T_WISE_5176_76\r\n" +
//				//			  		"GROUP BY    T_WISE_5176_76.대장번호")
//				//			  .option("user", user)
//				//			  .option("password", passwd)
//				//			  .load();
//				//	df.createOrReplaceTempView("df"+j);
//				//
//				//	Dataset<org.apache.spark.sql.Row> df2 = spark.read()
//				//			  .format("jdbc")
//				//			  .option("url", url)
//				//			  .option("driver", driverClass)
//				//			  .option("query", " SELECT      T_WISE_5176_76.대장번호 AS 대장번호, T_WISE_5176_76.주소코드 AS 주소코드\r\n" +
//				//			  		"FROM        T_WISE_5176_76\r\n" +
//				//			  		"GROUP BY    T_WISE_5176_76.대장번호")
//				//			  .option("user", user)
//				//			  .option("password", passwd)
//				//			  .load();
//				//	df2.createOrReplaceTempView("df2"+j);
//				//
//				//	Dataset<org.apache.spark.sql.Row> dfJoined = df.join(df2, "대장번호").select("주소코드");
//				//	dfJoined.createOrReplaceTempView("dfJoined"+j);
//				//
//				//	Timer timer1 = new Timer();
//				//	timer1.start();
//				//	List<String> json = dfJoined.toJSON().collectAsList();
//				//	List<JSONObject> list = new ArrayList<JSONObject>();
//				//	timer1.stop();
//				//	System.out.println("df1 Casting Time : " + timer1.getInterval());
//				//
//				//	for (String str:json) {
//				//		list.add(JSONObject.fromObject(JSONSerializer.toJSON(str)));
//				//	}
//				//
//				//	System.out.println("df1 list Size : " + list.size());
//				Dataset<org.apache.spark.sql.Row> df = spark.read()
//						  .format("jdbc")
//						  .option("url", url)
//						  .option("driver", driverClass)
//						  .option("dbtable", tblnm.get(j))
//						  .option("user", user)
//						  .option("password", passwd)
//						  .load();
//						df.createOrReplaceTempView(sparkTblName);
//						spark.catalog().cacheTable(sparkTblName);
//						spark.sql("select * from " + sparkTblName).show();
//			}
			

			//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
			String sparkTblName = sparkUploadTable(dsid.get(j), tblnm.get(j));
			sql = sql.replaceAll(tblnm.get(j), sparkTblName);
		}
//		System.out.println(spark.catalog().listTables().count());
//		spark.catalog().listTables().show();
		
//		spark.catalog().listTables().foreach( tab -> {
//            System.out.println("tab.database :" + tab.database());
//            System.out.println("tab.name :" + tab.name());
//            System.out.println("tab.tableType :" + tab.tableType());
//        });
		//spark의 컬럼명이 한글을 인식할려면 ` 특수문자가 붙어야 한다 중요
		//.한글
		Pattern pattern1 = Pattern.compile("\\.[a-zA-Zㄱ-ㅎㅏ-ㅣ가-힣0-9_]*");
		Matcher matcher1 = pattern1.matcher(sql);
		while (matcher1.find()) {
			String str = matcher1.group(0);
		    sql = sql.replaceFirst("\\."+str.substring(1), "\\.`"+str.substring(1)+"`");
		}
//		//(한글.
//		Pattern pattern4 = Pattern.compile("\\([a-zA-Zㄱ-ㅎㅏ-ㅣ가-힣0-9_]*\\.");
//		Matcher matcher4 = pattern4.matcher(sql);
//		while (matcher4.find()) {
//			String str = matcher4.group(0);
//			
//		    sql = sql.replaceFirst("\\(" + str.substring(1,  str.length() - 1) + "\\.", "\\(`" + str.substring(1, str.length() - 1)+"`\\.");
//		}
//		//(공백)한글.
//		Pattern pattern5 = Pattern.compile("\\s[a-zA-Zㄱ-ㅎㅏ-ㅣ가-힣0-9_]*\\.");
//		Matcher matcher5 = pattern5.matcher(sql);
//		while (matcher5.find()) {
//			String str = matcher5.group(0);
//		    sql = sql.replaceFirst(str.substring(0, str.length() - 1) + "\\.", " `" + str.substring(1, str.length() - 1)+"`\\.");
//		}
//		
		//AS 한글
		Pattern pattern2 = Pattern.compile("[aA][sS] [a-zA-Zㄱ-ㅎㅏ-ㅣ가-힣0-9_]*");
		Matcher matcher2 = pattern2.matcher(sql);
		while (matcher2.find()) {
			String str = matcher2.group(0);
			if(!"".equals(str.substring(3))) sql = sql.replaceFirst("[aA][sS] "+str.substring(3), "AS `"+str.substring(3)+"`");
		}
		
//		//(공백)한글(공백)
//		Pattern pattern3 = Pattern.compile("\\s[a-zA-Zㄱ-ㅎㅏ-ㅣ가-힣0-9_]+\\s");
//		Matcher matcher3 = pattern3.matcher(sql);
//		while (matcher3.find()) {
//			String str = matcher3.group(0);
//			if(!str.substring(1, str.length() - 1).matches(".*[ㄱ-ㅎㅏ-ㅣ가-힣]+.*")) continue;
//		    sql = sql.replaceFirst(str, " `" + str.substring(1, str.length() - 1)+"` ");
//		}
		System.out.println("이기종 after sql="+sql);
		logger.debug("이기종 after sql="+sql);

		SQLContext sqlContext = new SQLContext(spark);
		//sqlContext.setConf("spark.driver.allowMultipleContexts","true");

		// yyb 2021-02-17 병렬처리를 위한 파티션 갯수 설정 core수로 맞출것
		// repartiton, coalesce는 파티션 재설정시 shuffling이 일어나므로 반드시 sql 실행전에 설정해줘야 함
		String partialCnt = Configurator.getInstance().getConfig("wise.spark.sql.shuffle.partitions");
		sqlContext.setConf("spark.sql.shuffle.partitions", partialCnt);
		//sqlContext.setConf("spark.sql.shuffle.partitions", "7");

		MemoryMXBean memoryMXBean = ManagementFactory.getMemoryMXBean();
		System.out.println(String.format("Initial memory: %.2f GB", 
		  (double)memoryMXBean.getHeapMemoryUsage().getInit() /1073741824));
		System.out.println(String.format("Used heap memory: %.2f GB", 
		  (double)memoryMXBean.getHeapMemoryUsage().getUsed() /1073741824));
		System.out.println(String.format("Max heap memory: %.2f GB", 
		  (double)memoryMXBean.getHeapMemoryUsage().getMax() /1073741824));
		System.out.println(String.format("Committed memory: %.2f GB", 
		  (double)memoryMXBean.getHeapMemoryUsage().getCommitted() /1073741824));

		System.out.println(sql);
		Dataset<org.apache.spark.sql.Row> dfRes = sqlContext.sql(sql);
		//dfRes.show();
		return dfRes;
	}
	
	//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
	public String sparkUploadTable(int dsid, String tblnm) {
		
		SparkSession spark = this.sparkLoad.sparkSession();
		
		DataSetMasterVO dsVO = this.dataSetDAO.selectDataSetMaster(dsid);
		String ip = dsVO.getDatabaseIp();
		String port = dsVO.getDatabasePort();
		String dbNm = dsVO.getDatabaseName();
		String dbtype = dsVO.getDatabaseType();
		String url = "";
		String user = dsVO.getDatabaseUser();
		String passwd = dsVO.getDatabasePassword();
		String driverClass = "";
		String sparkTblName = "";
		boolean isExist = false;
		
		//sparkTblName 생성 및 WISE_TBL_LIST에 정보 등록
		Dataset<org.apache.spark.sql.Row> wise_tbl_list2 = spark.sql("SELECT sparkTblName FROM wise_tbl_list WHERE dbName = '"+dbNm+"' AND tblName = '"+tblnm+"'");
		if(wise_tbl_list2.count() > 0) {
//			System.out.println(wise_tbl_list2.first().get(0).toString());
			sparkTblName = wise_tbl_list2.first().get(0).toString();
		}else {
			int tblNum = 1;
			if(spark.sql("SELECT * FROM wise_tbl_list").count() != 0)
				tblNum = Integer.parseInt(spark.sql("SELECT sparkTblName FROM wise_tbl_list ORDER BY sparkTblName DESC limit 1").first().get(0).toString().replaceAll("[^0-9]", "")) + 1;
			sparkTblName = "wise_spark_table"+(tblNum);
			wise_tbl_list2.show();
			System.out.println("INSERT INTO wise_tbl_list VALUES ('"+dbNm+"', '"+tblnm+"', '"+sparkTblName+"')");
//			spark.sql("INSERT INTO wise_tbl_list VALUES ('"+dbNm+"', '"+tblnm.get(j)+"', '"+sparkTblName+"')");
			spark.sql("create or replace temporary view wise_tbl_list as select * from wise_tbl_list union select '"+dbNm+"' as dbName, '"+tblnm+"' as tblName, '"+sparkTblName+"' as sparkTblName");
			 spark.sql("SELECT sparkTblName FROM wise_tbl_list WHERE dbName = '"+dbNm+"' AND tblName = '"+tblnm+"'").show();
		}
		
		if(!spark.catalog().tableExists(sparkTblName)) {
			if(dbtype.equals("MS-SQL")) {
				driverClass = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
				url = "jdbc:sqlserver://" + ip + ":" + port + ";DatabaseName=" + dbNm;
			}
			else if(dbtype.equals("DB2BLU")) {
				driverClass = "com.ibm.db2.jcc.DB2Driver";
				url = "jdbc:db2://" + ip + ":" + port + "/" + dbNm;
			}
			else if(dbtype.equals("ORACLE")) {
				driverClass = "oracle.jdbc.driver.OracleDriver";
				url = "jdbc:oracle:thin:@" + ip + ":" + port + ":" + dbNm;
			}
			else if(dbtype.equals("TIBERO")) {
				driverClass = "com.tmax.tibero.jdbc.TbDriver";
				url = "jdbc:tibero:thin:@" + ip + ":" + port + ":" + dbNm;
			}
			else if(dbtype.equals("ALTIBASE")) {
				driverClass = "Altibase.jdbc.driver.AltibaseDriver";
				url = "jdbc:Altibase://" + ip + ":" + port + "/" + dbNm;
			}
			else if(dbtype.equals("CUBRID")) {
				driverClass = "cubrid.jdbc.driver.CUBRIDDriver";
				url = "jdbc:cubrid:" + ip + ":" + port + ":" + dbNm + ":dba::";
			}
			else if(dbtype.equals("IMPALA")) {
				driverClass = "com.cloudera.impala.jdbc41.Driver";
				url = "jdbc:impala://" + ip + ":" + port + "/" + dbNm;
			}
			else if(dbtype.equals("MYSQL")) {
				driverClass = "com.mysql.jdbc.Driver";
				url = "jdbc:mysql://" + ip + ":" + port + "/" + dbNm;
			}
			else if(dbtype.equals("NETEZZA")) {
				driverClass = "org.netezza.Driver";
				url = "jdbc:netezza://" + ip + ":" + port + "/" + dbNm;
			}
			else if(dbtype.equals("MARIA")) {
				driverClass = "org.mariadb.jdbc.Driver";
				//maria는 데이터가 이상하게 나오는 경우가 있어서 url을 mysql로 함
				//url = "jdbc:mariadb://" + ip + ":" + port + "/" + dbNm;
				url = "jdbc:mysql://" + ip + ":" + port + "/" + dbNm;
			}

			Dataset<org.apache.spark.sql.Row> df = spark.read()
					  .format("jdbc")
					  .option("url", url)
					  .option("driver", driverClass)
					  .option("dbtable", tblnm)
					  .option("user", user)
					  .option("password", passwd)
					  .load();
					df.createOrReplaceTempView(sparkTblName);
					spark.catalog().cacheTable(sparkTblName);
					spark.sql("select * from " + sparkTblName).show();
		}
		
		return sparkTblName;
	}

	/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
	@Override
    public CloseableList<JSONObject> querySqlLikePaging(int dataSourceId, String dataSourceType, String sql, JSONObject params, int sqlTimeout, JSONObject sqlConfig, int pagingSize, int pagingStart)
    		throws	Exception {
    	Connection connection = null;
    	pstmt = null;
        ResultSet resultSet = null;

        CloseableList<JSONObject> ret = new FileBackedJSONObjectList();
        try {
            DataSetMasterVO dataSetMaster = null;
	        if (DataSetConst.DataSetType.DS.equals(dataSourceType) || DataSetConst.DataSetType.DS_SQL.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetMaster(dataSourceId);
	        }
	        else if (DataSetConst.DataSetType.VIEW.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectDataSetViewMaster(dataSourceId);
	        }
	        else if (DataSetConst.DataSetType.CUBE.equals(dataSourceType)) {
	            dataSetMaster = this.dataSetDAO.selectCubeMaster(dataSourceId);
	        }
	        String dbtype = dataSetMaster.getDatabaseType();

            sql = this.sqlMapper.mapParameter(sql, params);
            logger.debug("sql(param) : " + sql);

            sql = this.sqlConvertor.convert(sql);
            logger.debug("sql(converted) : " + sql);

            String countSql = "SELECT COUNT(*) FROM (\n"+sql+"\n) A";

            sql = "WITH WISE_SQL_LIKE AS (\n" + sql + "\n)";

            JSONArray selectList = sqlConfig.getJSONArray("Select");

            JSONArray groupByList = new JSONArray();

            JSONArray fromList = new JSONArray();

            JSONArray whereList = new JSONArray();

            JSONArray orderByList = new JSONArray();



            if(sqlConfig.containsKey("GroupBy")) {
            	groupByList = sqlConfig.getJSONArray("GroupBy");
            }


            if(sqlConfig.containsKey("Where")) {
            	whereList = sqlConfig.getJSONArray("Where");
            }

            if(sqlConfig.containsKey("OrderBy")) {
            	orderByList = sqlConfig.getJSONArray("OrderBy");
            }

            if(sqlConfig.containsKey("isDiscountQuery")) {
            	sql += "SELECT Distinct ";
            }else {
            	sql += "SELECT ";
            }

            if(selectList.size() == 1) {
            	if(selectList.getString(0).equals("*")) {
            		sql += selectList.getString(0) + "\n";
            	}else {
            		sql += "\"" + selectList.getString(0) + "\"\n";
            	}
            }else {
            	for(int i = 0; i < selectList.size(); i++) {
                	if(i == selectList.size()-1) {
                		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
                		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
                			sql += selectList.getString(i) + "\n";
                		} else {
                			sql += "\"" + selectList.getString(i) + "\"\n";
                		}
//                		}
                	}else {
                		JSONObject result = this.switchAggregateSyntax(selectList.getString(i),selectList.getString(i+1), false);

                		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
                		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
                			String syntax = result.get("syntax").toString();
                			result.put("syntax", syntax.replaceAll("\"", ""));
                		}
                		if(result.getBoolean("isChanged")) {
                			i++;
                			if(i+1 < selectList.size()) {
                				if(selectList.getString(i+1).equalsIgnoreCase("|as|")) {
                        			i++;
                        			sql += result.getString("syntax") + "\t" + "AS\t";
                        		}else {
                        			sql += result.getString("syntax") + ",\t";
                        		}
                			}else {
                				sql += result.getString("syntax") + "\n";
                			}
                		}else {
                			if(i+1 < selectList.size()) {
                				if(selectList.getString(i+1).equalsIgnoreCase("|as|")) {
                        			i++;
                        			//2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
                        			// DOGFOOT hjkim IMPALA는 WITH절 밖에 따옴표 생략되게 처리 20200721
                        			//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
                        			if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
                            			sql += result.getString("syntax") + "\t" + "AS\t";
                            		} else {
                            			sql += "\"" + result.getString("syntax") + "\"\t" + "AS\t";
                            		}
                        		}else {
                           			sql += "\"" + result.getString("syntax") + "\",\t";
                        		}
                			}
                		}
                	}
                }
            }


            sql += "FROM	WISE_SQL_LIKE \n";

            if(whereList.size() > 0) {
            	sql += "WHERE	1=1\n";
	            if(whereList.size() == 1) {
	            	JSONArray dataList = whereList.getJSONObject(0).getJSONArray("data");
	            	//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	            	if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
            			sql += "AND	" + whereList.getJSONObject(0).getString("key") + " IN (";
            		} else {
            			sql += "AND	\"" + whereList.getJSONObject(0).getString("key") + "\" IN (";
            		}
	            	for(int i = 0; i < dataList.size(); i++) {
	            		if(i < dataList.size()-1) {
	            			sql += "\'" + dataList.get(i) + "\',";
	            		}else {
	            			sql += "\'" + dataList.get(i) + "\'";
	            		}
	            	}
	            	sql += ")\n";
	            }else{
	            	for (int i = 0; i < whereList.size(); i++) {
	            		String whereListKey = whereList.getJSONObject(i).getString("key");
	            		JSONArray whereListData = whereList.getJSONObject(i).getJSONArray("data");
	            		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
	            		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
	            			sql += "AND	(" + whereListKey + " IN (";
	            		} else {
	            			sql += "AND	(\"" + whereListKey + "\" IN (";
	            		}
	            		for(int j = 0; j < whereListData.size(); j++) {
			            	if((whereListData.size()-1) > j) {
			            		sql += "\'" + whereListData.get(j) + "\',";
			            	}else {
			            		sql += "\'" + whereListData.get(j) + "\')";
			            	}
		                }
		            	sql += ")\n";

					}

	            }

            }

            if(groupByList.size() != 0) {
            	sql += "GROUP BY \t";
                if(groupByList.size() == 1) {
                	//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
                	if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
            			sql += groupByList.getString(0) + "\n";
            		} else {
            			sql += "\"" + groupByList.getString(0) + "\"\n";
            		}
                }else {
                	for(int i = 0; i < groupByList.size(); i++) {
                    	if(i == groupByList.size()-1) {
                    		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
                    		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
                    			sql += groupByList.getString(i) + "\n";
                    		} else {
                    			sql += "\"" + groupByList.getString(i) + "\"\n";
                    		}
                    	}else {
                    		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
                    		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
                    			sql += groupByList.getString(i) + ", \t";
                    		} else {
                    			sql += "\"" + groupByList.getString(i) + "\", \t";
                    		}
                    	}
                    }
                }
            }

            if(orderByList.size() != 0) {
            	sql += "ORDER BY \t";
            	if(orderByList.size() == 1) {
            		//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
            		if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
            			sql += orderByList.getString(0) + "\n";
            		} else {
            			sql += "\"" + orderByList.getString(0) + "\"\n";
            		}
                }else {
                	for(int i = 0; i < orderByList.size(); i++) {
                		if(!(i+1 < orderByList.size())) {
                			//2020.12.07 MKSONG MARIADB 오류  DOGFOOT
                			if(dbtype.equals("IMPALA") || dbtype.equals("MYSQL") || dbtype.equals("MARIA")) {
                    			sql += orderByList.getString(i) + "\n";
                    		} else {
                    			sql += "\"" + orderByList.getString(i) + "\"\n";
                    		}
                		}else {
                			JSONObject result = this.switchSortDirectionSyntax(orderByList.getString(i),orderByList.getString(i+1), false);
                    		if(result.getBoolean("isChanged")) {
                    			i++;
                    			if(i+1 < orderByList.size()) {
                        			sql += result.getString("syntax") + ",\t";
                        		}else {
                        			sql += result.getString("syntax");
                        		}
                    		}
                		}
                    }
                }
            }

            if(dbtype.equals("IMPALA") || dbtype.equals("MARIA") || dbtype.equals("MYSQL")) {
            	sql = sql.replaceAll("\"", "");
            }

            connection = this.getConnection(dataSourceId, dataSourceType);
            logger.debug("sqlike query : " + sql);

            ResultSet countRs = null;
            PreparedStatement pstmt2 = connection.prepareStatement(countSql);
            countRs = pstmt2.executeQuery();
            ResultSetMetaData rsmd = null;

            rsmd = countRs.getMetaData();
            JSONObject totalCount = new JSONObject();
            /*dogfoot 데이터 그리드 페이징 totalcount 테이블전체-> 그리드 쿼리에 대한 count 로 변경  shlim*/
//    		while (countRs.next()) {
//    			for (int i = 1; i <= rsmd.getColumnCount(); i++) {
//    				totalCount.put("totalCount", countRs.getString(i));
//    			}
//    		}
    		pstmt2.close();
    		countRs.close();

            pstmt = connection.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
            if(sqlTimeout > 0) {
            	pstmt.setQueryTimeout(sqlTimeout);
            }
            if(pstmt != null) {
            	pstmt.setFetchSize(500);
                massRS = pstmt.executeQuery();
                massRS.setFetchSize(100);
            } else {
            	massRS = null;
            }

            /*dogfoot 데이터 그리드 페이징 totalcount 테이블전체-> 그리드 쿼리에 대한 count 로 변경  shlim*/
            massRS.last();
            int rowcount = massRS.getRow();
            massRS.beforeFirst();
            totalCount.put("totalCount", rowcount);

            rsmd = massRS.getMetaData();
            /* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 오류 수정  20200921 */
            for(int i = pagingStart + 1;i < (pagingStart+pagingSize + 1);i++) {
            	if(massRS.absolute(i)) {
            		JSONObject tempObj = new JSONObject();
            		for(int colLength=1;colLength<=rsmd.getColumnCount();colLength++) {
            			tempObj.put(rsmd.getColumnName(colLength), massRS.getString(colLength));
            		}
            		ret.add(tempObj);
            	}
            }

            Timer timer1 = new Timer();
            timer1.start();


            timer1.stop();

            Timer timer2 = new Timer();
            timer2.start();
            timer2.stop();

            Timer timer3 = new Timer();
            timer3.start();
            JSONObject sqlJson = new JSONObject();
            sqlJson.put("sql", sql);
            ret.add(sqlJson);
            ret.add(totalCount);
            timer3.stop();

            logger.debug("queried count : " + ret.size());
            logger.debug("sql quering time : " + timer1.getInterval());
            logger.debug("result loop time : " + timer2.getInterval());
            logger.debug("convert result to json time: " + timer3.getInterval());
        } catch (SQLException e) {
        	e.printStackTrace();
        	throw e;
        } finally {
        	if (resultSet != null) {
        		try {
             		resultSet.close();
             	} catch (SQLException e) {
             		e.printStackTrace();
             		resultSet = null;
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

        return ret;
    }

	// Logical Table Name붙여 Unique Name 생성
	private String getUniqNm(String logicalTblNm, String uniqueNm) {
		String[] arrUnique = uniqueNm.split("\\.", 2);
		String retVal = "";
		if (arrUnique.length > 1) {
			retVal = logicalTblNm + ".";
			for (int i = 1; i < arrUnique.length; i++) {
				if (i < arrUnique.length - 1) {
					retVal += arrUnique[i] + ".";
				}
				else {
					retVal += arrUnique[i];
				}
			}
		}
		else {
			retVal = logicalTblNm;
		}
		return retVal;
	}
	
	private CloseableList<JSONObject> readCacheCsv(File cacheCsv) throws Exception {
		CloseableList<JSONObject> result = new FileBackedJSONObjectList();
		
		CSVParser csvParser = null;
		FileInputStream fis = null;
		InputStreamReader isr = null;
		BufferedReader br = null;
		
		try {
			if (cacheCsv.exists()) {
				fis = new FileInputStream(cacheCsv);
				isr = new InputStreamReader(fis, "UTF-8");
				br = new BufferedReader(isr);
				
				/* DOGFOOT ktkang 고용정보원10 캐시파일 , 에러 수정 */
				csvParser = new CSVParser(br, CSVFormat.EXCEL.withDelimiter('|').withHeader());		// CSVParser를 반드시 닫아줘야 한다.
				List<String> headers = csvParser.getHeaderNames();
				final int headerCnt = headers.size();
				Iterable<CSVRecord> records = csvParser;
				for (CSVRecord record : records) {
			    	// result 처리
			    	JSONObject row = new JSONObject();
			    	for (int i=0; i<headerCnt; i++) {
			    		String key = headers.get(i);
			    		String field = "";
			    		
			    		//CSV null 확인(사용자정의 데이터)
			    		if(record.isSet(i)) { 
			    			field = record.get(i);
			    		}
			    		
			    		// 숫자표현등에 있어 예외가 발생하여 처리함
			    		if (WINumberUtils.isNumber(field)) {
			    			BigDecimal b = new BigDecimal(field);
				    		if (field.contains(".")) {
				    			row.put(key, b.doubleValue());
							}
							else {
								row.put(key, b.longValue());
							}
			    		}
			    		else {
			    			row.put(key, field);
			    		}
			        }
			    	result.add(row);
			    }
				return result;
			}
			else {
				return null;
			}
		}
		
		finally {
			IOUtils.closeQuietly(csvParser, br, isr, fis);
		}
	}
	
	private void createCacheCsvFile(final String queryKey, final String relPath, final String[] headers, final List<JSONObject> result) throws Exception {
		try {
			cacheFileWritingTaskExecutorService.execute(new Runnable() {
				@Override
				public void run() {
					try {
						keyedFileLockService.writeCsvData(queryKey, relPath, headers, result);		// Lock 후에 Csv파일 생성
					} catch (Exception e) {
						logger.error("Failed to save CSV cache file.", e);
					}
				}
			});
		}
		catch (Exception e) {
			logger.error("Failed to submit a task to save CSV cache file.", e);
		}
	}
	
	@Override
	public CloseableList<JSONObject> executeSqlLike(final String sqlLikeOptionValue, boolean useWithQuery, HttpServletRequest request)
            throws Exception {
        final JSONObject sqlLikeOption = JSONObject.fromObject(sqlLikeOptionValue);

 		/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
 		long beforeTime = System.currentTimeMillis(); //코드 실행 전
 		System.out.println("-------------------------------");
		System.out.println("시작시간 : "+beforeTime);
		System.out.println("-------------------------------");
        User sessionUser = this.authenticationService.getSessionUser(request);
        
        JSONObject sqlConfig = sqlLikeOption.getJSONObject("sqlConfig");
        String sql_query = new String(Base64.decode(sqlLikeOption.getString("sql_query")));
        String dataSourceNm = sqlLikeOption.getString("ds_nm");
        String dataSourceIdStr = sqlLikeOption.getString("dsid");
        boolean multiDbQuery = (dataSourceIdStr.indexOf(",")>-1);
        if(multiDbQuery) {
        	String[] multiDsId = dataSourceIdStr.split(",");
        	dataSourceIdStr = multiDsId[0];
        }
        int dataSourceId = Integer.parseInt(dataSourceIdStr);
        String dataSourceType = sqlLikeOption.getString("dstype");
        String schedulePath = sqlLikeOption.has("schedulePath")? sqlLikeOption.getString("schedulePath") : "1001";
        String inMemory = sqlLikeOption.has("inMemory")? sqlLikeOption.getString("inMemory"): "1001";
        
        Timer timer = new Timer();
        
        int sqlTimeout = Integer.parseInt(sqlLikeOption.getString("sqlTimeout"));
        JSONObject ret = new JSONObject();
        String status = "50";
        JSONObject params = sqlLikeOption.getJSONObject("params");
        String join2 = sqlLikeOption.has("join")? sqlLikeOption.getString("join"): "1001";
        String fullQuery = sqlLikeOption.getString("fullQuery");
        /* DOGFOOT ktkang SQL 로그 추가  20200721 */
        String userId = sqlLikeOption.getString("userId");
        String reportType = sqlLikeOption.getString("reportType");
		/* DOGFOOT ajkim 피벗그리드 null 처리 방법 수정 20201207 */
        String itemType = sqlLikeOption.getString("itemType");
        /* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
        JSONObject nullDimension = sqlLikeOption.getJSONObject("nullDimension");;
        /* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
        String oldSchedule = sqlLikeOption.getString("oldSchedule");
        
        boolean join = false;
        
        /* DOGFOOT ktkang 모니터링 프로세스에 아무것도 안뜨는 오류 수정  20200922 */
        String sql = sql_query;
        String pidString = sqlLikeOption.has("pid")? sqlLikeOption.getString("pid"): "";
		String reportTypeForWeb = "";
		ReportLogMasterVO LogVo = new ReportLogMasterVO();
		String ip = "";
		// 2021-07-09 yyb 조회시 불필요하게 데이터원본 조회하지 않게 수정
		//int dataSourceID = this.dataSetServiceImpl.getDSIDforLog(dataSourceId, dataSourceType);
		int dataSourceID = Integer.parseInt(dataSourceIdStr);
		boolean logUse = Configurator.getInstance().getConfigBooleanValue("wise.ds.logUse", false);
		// logUse = false;
		if (logUse) {
			final HttpSession session = request.getSession(false);
			ip = session != null ? (String) request.getSession(false).getAttribute("IP_ADDRESS") : null;
			if(ip==null) ip = "127.0.0.1";
			if(sessionUser == null) {
				User sessionUser2 = new User();
				sessionUser2.setGRP_ID(1000);
				sessionUser2.setName("관리자");
				sessionUser2.setId("admin");
				sessionUser2.setNo(1001);
				sessionUser = sessionUser2;
			}
			logger.debug("remoteADDR : " + ip);
			if (pidString.equals("")) {
				LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), 0, "", reportTypeForWeb,
						sessionUser.getUSER_ID(), sessionUser.getUSER_NM(), sessionUser.getUSER_NO(), sessionUser.getGRP_ID(), "", ip, "",
						/* DOGFOOT mksong BASE64 오류 수정  20200116 */
						new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceID, timer.getInterval(), "WB");
			} else {
				int pid = Integer.parseInt(sqlLikeOption.getString("pid"));
				LogVo.setReportQueryLog(Timer.formatTime(timer.getStartTime()), pid, "", reportTypeForWeb,
						sessionUser.getUSER_ID(), sessionUser.getUSER_NM(), sessionUser.getUSER_NO(), sessionUser.getGRP_ID(), "", ip, "",
						/* DOGFOOT mksong BASE64 오류 수정  20200116 */
						new String(java.util.Base64.getEncoder().encode(sql.getBytes())), dataSourceID, timer.getInterval(), "WB");
			}

			logger.debug("query log ----" + LogVo.toString());
			this.reportService.enrollReportQueryLog(logUse, LogVo);
		}
		
        timer.start();
        /* DOGFOOT ktkang KERIS 상세현황 탭일 때 결과 값 자르기  20200123 */
        String queryParam = null;
        if(fullQuery.equals("true") && dataSourceNm.contains("상세현황")) {
        } else if(dataSourceNm.contains("상세현황")) {
        	queryParam = "dataCut";
        }
        
        status = "60";
        //2020.09.11 mksong 타이머 위치 오류 수정 dogfoot
        
    	Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
        Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());
        
        logger.debug("sqlLike query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
        logger.debug("sqlLike query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
        logger.debug("sqlLike query elapse time: " + timer.getInterval());
        CloseableList<JSONObject> result = new FileBackedJSONObjectList();
        JSONArray data = new JSONArray();
        
        //mssql에서는 with절안에 order by를 쓸수 없어서 제거해야 함
//        if(sql_query.toUpperCase().indexOf("ORDER BY") > 0) {
//        	sql_query = sql_query.substring(0, sql_query.toUpperCase().indexOf("ORDER BY"));
//        }
        
        
        if(!schedulePath.equals("1001") && !schedulePath.equals("")) {
            File folder = WebFileUtils.getWebFolder(request, true, "DataFiles");
    		/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
    		File file = null;
    		if(oldSchedule.equals("Y")) {
    			file = new File(schedulePath);
    		} else {
    			file = new File(folder, schedulePath);
    		}

    		try (InputStream is = new FileInputStream(file)) {
        		String jsonText = IOUtils.toString(is, "UTF-8");
        		JSONObject dataJson = (JSONObject) JSONSerializer.toJSON(jsonText);
                JSONArray jArr = (JSONArray) dataJson.get(dataSourceNm);
                result = (CloseableList<JSONObject>) this.sparkJson(jArr, sql_query, params, queryParam, sqlConfig);
    		}
        } else {
        	/*dogfoot spark 인메모리 작업 shlim 20210205*/
            if(multiDbQuery || inMemory.equals("true")) {
            	JSONArray tbllist = SecureUtils.getJSONArrayParameter(request, "tbllist");
            	
            	if(tbllist.size() > 0 || inMemory.equals("true")) {
            		ArrayList<Integer> dsid = new ArrayList<Integer>();
    		        ArrayList<String> tblnm = new ArrayList<String>();
    		        ArrayList<String> fileUrl = new ArrayList<String>();
    		        for(int i=0;i<tbllist.size();i++) {
    		        	JSONObject jobj = (JSONObject) tbllist.get(i);
    		        	if(jobj.getString("dsid").indexOf("\\.") > -1) {
    		        		dsid.add(-1);
        		        	tblnm.add((String)jobj.get("tblnm"));
        		        	fileUrl.add((String)jobj.get("dsid"));
    		        	}else {
    		        		dsid.add((int)jobj.get("dsid"));
        		        	tblnm.add((String)jobj.get("tblnm"));
        		        	fileUrl.add(jobj.has("fileUrl")? (String)jobj.get("fileUrl") : "noneFile");
    		        	}
    		        }                     	
                	
    		        //20210328 AJKIM 파일 조인 기능 추가 dogfoot
    		        result = (CloseableList<JSONObject>) this.sparkSqlLike(dsid, tblnm, dataSourceType, sql_query, params, sqlTimeout, queryParam, sqlConfig);
            	}else {
            		result = (CloseableList<JSONObject>) this.querySqlLike(dataSourceId, dataSourceType, sql_query, params, sqlTimeout, queryParam, sqlConfig, nullDimension, itemType, useWithQuery);
            	}
    	        
            } else { 
           		/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
            	/* DOGFOOT ajkim 피벗그리드 null 처리 방법 수정 20201207 */
            	result = (CloseableList<JSONObject>) this.querySqlLike(dataSourceId, dataSourceType, sql_query, params, sqlTimeout, queryParam, sqlConfig, nullDimension, itemType, useWithQuery);
            }
        }
        
        //2020.09.11 mksong 타이머 위치 오류 수정 dogfoot
        timer.stop();

        // 고운산 - 조회 루틴 변경  20210913
        ret.put("sql", result.getAttribute("sql"));
        //       	result.remove(result.size()-1);
        ret.put("data", result);

        /* DOGFOOT ktkang 모니터링 프로세스에 아무것도 안뜨는 오류 수정  20200922 */
        if (logUse) {
			//20210908 AJKIM 로그 보고서 타입 추가 dogfoot
			if (reportType.equals("AdHoc")) {
				reportTypeForWeb = "AdHoc";
			} else if(reportType.equals("Spread") || reportType.equals("Excel")){
				reportTypeForWeb = "Spread";
			} else if(reportType.equals("DSViewer")){
				reportTypeForWeb = "DSViewer";
			} else if(reportType.equals("StaticAnalysis") || reportType.equals("StaticAnal")) {
				reportTypeForWeb = "StaticAnalysis";
			} else {
				reportTypeForWeb = "DashAny";
			}

			String keyTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS").format(new Date(timer.getStartTime()));
			Timestamp queryEndTimestamp = Timer.formatTime(timer.getFinishTime());
			
			ReportLogMasterVO vo = new ReportLogMasterVO();
			vo.setLOG_SEQ(keyTime);
			vo.setED_DT(queryEndTimestamp);
			vo.setSTATUS_CD(status);
			
			if (logUse) {
				this.reportService.updateReportLogDetail(logUse, vo);
			}
		}
		
		/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/        
		long afterTime = System.currentTimeMillis(); // 코드 실행 후
		long secDiffTime = (afterTime - beforeTime); 
		System.out.println("-------------------------------");
		System.out.println("종료시간 : "+afterTime);
		System.out.println("시간차이(ms) : "+secDiffTime);
		System.out.println("-------------------------------");
		ret.put("Queries_Time", secDiffTime);
		
		return result;
    }

}
