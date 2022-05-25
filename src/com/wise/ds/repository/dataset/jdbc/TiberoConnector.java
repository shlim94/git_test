package com.wise.ds.repository.dataset.jdbc;


public class TiberoConnector extends AbstractDataBaseConnector {
    
    /*public TiberoConnector(DataSetMasterVO dataSetMaster) {
        this();
        
        this.type = dataSetMaster.getDatabaseType();
        
        String developUrl = Configurator.getInstance().getConfig("wise.ds.dev.datasource.connector.tibero.url");
        if ("".equals(developUrl)) {
            this.url = "jdbc:tibero:thin:@" + dataSetMaster.getDatabaseIp() + ":" + dataSetMaster.getDatabasePort();
            this.url += ":" + dataSetMaster.getDatabaseName();
        } else {
            this.url = developUrl;
        }
        
        this.user = dataSetMaster.getDatabaseUser();
        this.password = dataSetMaster.getDatabasePassword();
    }*/
    
    @Override
    public void init() {
        this.url = "jdbc:tibero:thin:@" + dataSetMaster.getDatabaseIp() + ":" + dataSetMaster.getDatabasePort();
        this.url += ":" + dataSetMaster.getDatabaseName();
        this.user = dataSetMaster.getDatabaseUser();
        this.password = dataSetMaster.getDatabasePassword();
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
        return "OracleConnectionInformation [driver=" + driver + ", url=" + url + ", user=" + user + ", password=" + password + "]";
    }

}
