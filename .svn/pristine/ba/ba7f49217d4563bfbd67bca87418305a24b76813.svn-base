package com.wise.ds.repository.dataset;  
  
import java.util.HashMap;  
import java.util.Map;  
  
import javax.annotation.Resource;  
  
import org.apache.commons.dbcp.BasicDataSource;  
import org.springframework.stereotype.Service;  
  
import com.wise.context.config.Configurator;  
import com.wise.ds.repository.DataSetMasterVO;  
import com.wise.ds.repository.dao.DataSetDAO;  
import com.wise.ds.repository.dataset.jdbc.CommonDataBaseConnector;  
import com.wise.ds.repository.dataset.jdbc.DataBaseConnector;  
  
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
  
@Service("dataSourceFactory")  
public class DataSourceFactory {  
  
    @Resource(name = "dataSetDAO")  
    private DataSetDAO dataSetDAO;  
  
    private Map<Integer, BasicDataSource> dataSources = new HashMap<Integer, BasicDataSource>();  
    private Map<Integer, String> dataSourceTypes = new HashMap<Integer, String>();  
  
    public String getDataSourceType(int dataSourceId) {  
     return this.dataSourceTypes.get(dataSourceId);  
    }  
  
    public void removeDataSource(int dataSourceId) {  
    	this.dataSources.remove(Integer.valueOf(dataSourceId));  
    	this.dataSourceTypes.remove(Integer.valueOf(dataSourceId));  
    }  
  
    public synchronized BasicDataSource getDataSource(int dataSourceId) {  
        return this.dataSources.get(dataSourceId);  
    }  
  
    public synchronized BasicDataSource getDataSource(int dataSourceId, String dataSourceType)  
      throws NotFoundDataSetTypeException, EmptyDataSetInformationException, NotFoundDatabaseConnectorException {  
        BasicDataSource dataSource = this.dataSources.get(dataSourceId);  
//        System.out.println("BasicDataSource getDataSource >>>> "+dataSource.getUsername()+dataSource.getPassword());  
  
        if (dataSource == null) {  
            DataSetMasterVO dataSetMaster;  
  
            this.dataSourceTypes.put(dataSourceId, dataSourceType);  
  
            /* querying database information by dataset type */  
            if (DataSetConst.DataSetType.DS.equals(dataSourceType) || DataSetConst.DataSetType.DS_SQL.equals(dataSourceType) || DataSetConst.DataSetType.TBL.equals(dataSourceType)) {  
                dataSetMaster = this.dataSetDAO.selectDataSetMaster(dataSourceId);  
            }  
            else if (DataSetConst.DataSetType.VIEW.equals(dataSourceType)) {  
                dataSetMaster = this.dataSetDAO.selectDataSetViewMaster(dataSourceId);  
            }  
            else if (DataSetConst.DataSetType.CUBE.equals(dataSourceType)) {  
                dataSetMaster = this.dataSetDAO.selectCubeMaster(dataSourceId);  
            }  
            else {  
                throw new NotFoundDataSetTypeException();  
            }  
  
            if (dataSetMaster == null) {  
                throw new EmptyDataSetInformationException();  
            }  
  
            /* connect to database using database information queried above */  
            DataBaseConnector connector = null;  
            String dbmsType = dataSetMaster.getDatabaseType().toUpperCase();  
            dataSetMaster.setDatabaseType(dbmsType);  
  
            String jdbcUrl = Configurator.getInstance().getConfig("wise.ds.repository.mart.connector." + dbmsType + ".jdbc");  
  
            if (!"".equals(jdbcUrl)) {  
            	connector = new CommonDataBaseConnector(jdbcUrl);  
            }  
            else {  
            	String connectorClass = Configurator.getInstance().getConfig("wise.ds.repository.mart.connector." + dbmsType + ".class");  

            	try {  
            		@SuppressWarnings("rawtypes")  
            		Class clazz = Class.forName(connectorClass);  
            		connector = (DataBaseConnector) clazz.newInstance();  
            	} catch (ClassNotFoundException e) {  
            		e.printStackTrace();  
            		connector = null;  
            	} catch (IllegalAccessException e) {  
            		e.printStackTrace();  
            		connector = null;  
            	} catch (InstantiationException e) {  
            		e.printStackTrace();  
            		connector = null;  
            	}  
            }  

            if (connector == null) {  
                throw new NotFoundDatabaseConnectorException(dbmsType);  
            }  
  
            /* initilizing connector */  
            connector.setDataSetMasterVO(dataSetMaster);  
            connector.init();  
  
            /* set factory created datasource */  
            BasicDataSource connectionPool = connector.connectDatabase();  
            this.dataSources.put(dataSourceId, connectionPool);  
  
            /* return requested database */  
            dataSource = this.dataSources.get(dataSourceId);  
        }  
        return dataSource;  
    }  
  
 public DataSetMasterVO getDSInformation(int dataSourceId, String dataSourceType) {  
  // TODO Auto-generated method stub  
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
  return dataSetMaster;  
 }  
  
 public String selectSCHForSkip(String schId, String dataSourceIdStr) {  
  // TODO Auto-generated method stub  
  
  return this.dataSetDAO.selectSCHForSkip(schId, dataSourceIdStr);  
 }  
  
}