package com.wise.ds.repository.dataset.jdbc;

import org.apache.commons.dbcp.BasicDataSource;

import com.wise.context.config.Configurator;
import com.wise.ds.repository.DataSetMasterVO;

abstract class AbstractDataBaseConnector implements DataBaseConnector {
    protected String driver;
    protected String url;
    protected String user;
    protected String password;
    protected String type;
    protected DataSetMasterVO dataSetMaster;
    
    @Override
    public void setDataSetMasterVO(DataSetMasterVO dataSetMaster) {
        this.dataSetMaster = dataSetMaster;
        
        this.type = this.dataSetMaster.getDatabaseType();
        this.driver = Configurator.getInstance().getConfig("wise.ds.repository.mart.connector." + this.type + ".driver");
    }

    @Override
    public BasicDataSource connectDatabase() {
        BasicDataSource connectionPool = new BasicDataSource();

        connectionPool.setDriverClassName(this.getDriver());
        connectionPool.setUrl(this.getUrl());
        connectionPool.setUsername(this.getUser());
        connectionPool.setPassword(this.getPassword());

        int initialSize = Configurator.getInstance().getConfigIntValue("wise.ds.repository.mart.connection.pool.initialSize", 0);
        int maxActive = Configurator.getInstance().getConfigIntValue("wise.ds.repository.mart.connection.pool.max.active", 8);
        int maxWait = Configurator.getInstance().getConfigIntValue("wise.ds.repository.mart.connection.pool.max.wait", 0);
        boolean poolingStatements = Configurator.getInstance().getConfigBooleanValue("wise.ds.repository.mart.connection.pool.preparedstatement", false);
        
        int minIdle = Configurator.getInstance().getConfigIntValue("wise.ds.repository.mart.connection.pool.min.idle", 0);
        int maxIdle = Configurator.getInstance().getConfigIntValue("wise.ds.repository.mart.connection.pool.max.idle", 8);
        
        boolean testOnBorrow = Configurator.getInstance().getConfigBooleanValue("wise.ds.repository.mart.connection.pool.testOnBorrow");
        boolean testWhileIdle = Configurator.getInstance().getConfigBooleanValue("wise.ds.repository.mart.connection.pool.testWhileIdle");
        
        String validationQuery = Configurator.getInstance().getConfig("wise.ds.repository.mart.connection.pool." + this.type + ".validationQuery");
        
        if (initialSize > 8) connectionPool.setInitialSize(initialSize);
        if (maxActive > 8) connectionPool.setMaxActive(maxActive);
        if (maxIdle > 0) connectionPool.setMaxIdle(maxIdle);
        if (minIdle > 0) connectionPool.setMinIdle(minIdle);
        if (maxWait > 0) connectionPool.setMaxWait(maxWait);
        
        connectionPool.setTestWhileIdle(testWhileIdle);
        if (!"".equals(validationQuery)) connectionPool.setValidationQuery(validationQuery);

        return connectionPool;
    }

}
