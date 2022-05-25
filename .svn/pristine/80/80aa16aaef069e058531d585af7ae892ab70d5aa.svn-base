package com.wise.ds.repository.dataset.jdbc;


public class CommonDataBaseConnector extends AbstractDataBaseConnector {

    private String jdbcUrl;
    
    public CommonDataBaseConnector(String jdbcUrl) {
        this.jdbcUrl = jdbcUrl;
    }
    
    @Override
    public void init() {
        this.url = this.jdbcUrl;
        this.url = this.url.replaceAll("\\{\\{DOMAIN\\}\\}", this.dataSetMaster.getDatabaseIp());
        this.url = this.url.replaceAll("\\{\\{PORT\\}\\}", this.dataSetMaster.getDatabasePort());
        this.url = this.url.replaceAll("\\{\\{DATABASE\\}\\}", this.dataSetMaster.getDatabaseName());
        
        this.user = this.dataSetMaster.getDatabaseUser();
        this.password = this.dataSetMaster.getDatabasePassword();
    }

    @Override
    public String getDriver() {
        return this.driver;
    }

    @Override
    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public String getUrl() {
        return this.url;
    }

    @Override
    public void setUser(String user) {
        this.user = user;
    }

    @Override
    public String getUser() {
        return this.user;
    }

    @Override
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String toString() {
        return "SqlServerConnectionInformation [driver=" + driver + ", url=" + url + ", user=" + user + ", password=" + password + "]";
    }

}
