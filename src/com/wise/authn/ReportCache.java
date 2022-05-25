package com.wise.authn;


public class ReportCache {
    private int id;
    private int folderId;
    private String folderType;
    private int regUserNo;

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

    public String getFolderType() {
        return folderType;
    }

    public void setFolderType(String folderType) {
        this.folderType = folderType;
    }

    public int getRegUserNo() {
        return regUserNo;
    }

    public void setRegUserNo(int regUserNo) {
        this.regUserNo = regUserNo;
    }

    @Override
    public String toString() {
        return "ReportCache [id=" + id + ", folderId=" + folderId + ", folderType=" + folderType + ", regUserNo=" + regUserNo + "]";
    }

}
