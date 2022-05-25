package com.wise.ds.repository.dataset.jdbc;


public class IMPALAConnector extends AbstractDataBaseConnector {

    @Override
    public void init() {
        this.url = "jdbc:impala://" + this.dataSetMaster.getDatabaseIp() + ":" + this.dataSetMaster.getDatabasePort();
        this.url += "/" + this.dataSetMaster.getDatabaseName();
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
        return "IMPALAConnectionInformation [driver=" + driver + ", url=" + url + ", user=" + user + ", password=" + password + "]";
    }

}
