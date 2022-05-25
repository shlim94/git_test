package com.wise.ds.repository;

public class AuthReportVO {
	private String grpid;
	private Integer userNo;
	private String report_id;
	private String fld_id;
	private String auth_show;
	private String auth_publish;
	private String auth_dataitem;
	private String auth_export;
	
	public String getGrpid() {
		return grpid;
	}
	public void setGrpid(String grpid) {
		this.grpid = grpid;
	}
	public Integer getUserNo() {
		return userNo;
	}
	public void setUserNo(Integer userNo) {
		this.userNo = userNo;
	}
	public String getReport_id() {
		return report_id;
	}
	public void setReport_id(String report_id) {
		this.report_id = report_id;
	}
	public String getAuth_show() {
		return auth_show;
	}
	public void setAuth_show(String auth_show) {
		this.auth_show = auth_show;
	}
	public String getAuth_publish() {
		return auth_publish;
	}
	public void setAuth_publish(String auth_publish) {
		this.auth_publish = auth_publish;
	}
	public String getAuth_dataitem() {
		return auth_dataitem;
	}
	public void setAuth_dataitem(String auth_dataitem) {
		this.auth_dataitem = auth_dataitem;
	}
	public String getAuth_export() {
		return auth_export;
	}
	public void setAuth_export(String auth_export) {
		this.auth_export = auth_export;
	}
	public String getFld_id() {
		return fld_id;
	}
	public void setFld_id(String fld_id) {
		this.fld_id = fld_id;
	}
	@Override
	public String toString() {
		return "AuthReportVO [grpid=" + grpid + ", report_id=" + report_id + ", fld_id=" + fld_id + ", auth_show="
				+ auth_show + ", auth_publish=" + auth_publish + "]";
	}
	
	
}
