package com.wise.ds.repository;

public class TableRelationVO {
	private String CONST_NM;
	private String FK_TBL_NM;
	private String FK_COL_NM;
	private String PK_TBL_NM;
	private String PK_COL_NM;
	private String JOIN_TYPE;
	
	public String getCONST_NM() {
		return CONST_NM;
	}
	public void setCONST_NM(String cONST_NM) {
		CONST_NM = cONST_NM;
	}
	public String getFK_TBL_NM() {
		return FK_TBL_NM;
	}
	public void setFK_TBL_NM(String fK_TBL_NM) {
		FK_TBL_NM = fK_TBL_NM;
	}
	public String getFK_COL_NM() {
		return FK_COL_NM;
	}
	public void setFK_COL_NM(String fK_COL_NM) {
		FK_COL_NM = fK_COL_NM;
	}
	public String getPK_TBL_NM() {
		return PK_TBL_NM;
	}
	public void setPK_TBL_NM(String pK_TBL_NM) {
		PK_TBL_NM = pK_TBL_NM;
	}
	public String getPK_COL_NM() {
		return PK_COL_NM;
	}
	public void setPK_COL_NM(String pK_COL_NM) {
		PK_COL_NM = pK_COL_NM;
	}
	public String getJOIN_TYPE() {
		return JOIN_TYPE;
	}
	public void setJOIN_TYPE(String jOIN_TYPE) {
		JOIN_TYPE = jOIN_TYPE;
	}
}
