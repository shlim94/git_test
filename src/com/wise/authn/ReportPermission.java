package com.wise.authn;

import java.io.Serializable;

public class ReportPermission implements Serializable {
    private static final long serialVersionUID = 253728383416349101L;
    
    private int id; // user_no, group_id
    private int folderId;
    private String viewYn;
    private String publishYn;
    private String dataItemYn;
    private String exportYn;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getFolderId() {
        return folderId;
    }

    public void setFolderId(int folderId) {
        this.folderId = folderId;
    }

    public String getViewYn() {
        return viewYn;
    }

    public void setViewYn(String viewYn) {
        this.viewYn = viewYn;
    }

    public String getPublishYn() {
        return publishYn;
    }

    public void setPublishYn(String publishYn) {
        this.publishYn = publishYn;
    }

    public String getDataItemYn() {
        return dataItemYn;
    }

    public void setDataItemYn(String dataItemYn) {
        this.dataItemYn = dataItemYn;
    }
    
    public String getExportYn() {
        return exportYn;
    }

    public void setExportYn(String exportYn) {
        this.exportYn = exportYn;
    }

    @Override
    public String toString() {
        return "UserAuthentication [id=" + id + ", folderId=" + folderId + ", viewYn=" + viewYn + ", publishYn=" + publishYn + ", dataItemYn="
                + dataItemYn + "]";
    }
}
