package com.wise.ds.repository;

public class DataSetMasterVO {
    private int id;
    private String name;

    private String databaseName;
    private String databaseIp;
    private String databasePort;
    private String databaseType;
    private String databaseOwner;
    private String databaseConnectString;

    private String databaseUser;
    private String databasePassword;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDatabaseName() {
        return databaseName;
    }

    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
    }

    public String getDatabaseIp() {
        return databaseIp;
    }

    public void setDatabaseIp(String databaseIp) {
        this.databaseIp = databaseIp;
    }

    public String getDatabasePort() {
        return databasePort;
    }

    public void setDatabasePort(String databasePort) {
        this.databasePort = databasePort;
    }

    public String getDatabaseType() {
        return databaseType;
    }

    public void setDatabaseType(String databaseType) {
        this.databaseType = databaseType;
    }

    public String getDatabaseOwner() {
        return databaseOwner;
    }

    public void setDatabaseOwner(String databaseOwner) {
        this.databaseOwner = databaseOwner;
    }

    public String getDatabaseConnectString() {
        return databaseConnectString;
    }

    public void setDatabaseConnectString(String databaseConnectString) {
        this.databaseConnectString = databaseConnectString;
    }

    public String getDatabaseUser() {
        return databaseUser;
    }

    public void setDatabaseUser(String databaseUser) {
        this.databaseUser = databaseUser;
    }

    public String getDatabasePassword() {
        return databasePassword;
    }

    public void setDatabasePassword(String databasePassword) {
        this.databasePassword = databasePassword;
    }

    @Override
    public String toString() {
        return "DataSetMasterVO [id=" + id + ", name=" + name + ", databaseName=" + databaseName + ", databaseIp=" + databaseIp + ", databasePort="
                + databasePort + ", databaseType=" + databaseType + ", databaseOwner=" + databaseOwner + ", databaseConnectString="
                + databaseConnectString + ", databaseUser=" + databaseUser + ", databasePassword=" + databasePassword + "]";
    }

}
