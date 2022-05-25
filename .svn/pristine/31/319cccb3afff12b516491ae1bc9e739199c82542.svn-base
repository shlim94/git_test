package com.wise.ds.repository.dataset.jdbc;

import org.apache.commons.dbcp.BasicDataSource;

import com.wise.ds.repository.DataSetMasterVO;

public interface DataBaseConnector {
    public String getDriver();

    public void setUrl(String url);

    public String getUrl();

    public void setUser(String user);

    public String getUser();

    public void setPassword(String password);

    public String getPassword();
    
    public void setDataSetMasterVO(DataSetMasterVO dataSetMasterVO);
    
    public void init();
    
    public BasicDataSource connectDatabase();
}
