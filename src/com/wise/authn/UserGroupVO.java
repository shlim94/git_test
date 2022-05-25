package com.wise.authn;

import java.sql.Timestamp;
import java.util.List;

public class UserGroupVO {
	private String USER_NO;
	private String USER_ID;
	private String USER_NM;
	private String USER_PW;
	private String USER_EMAIL1;
	private String USER_EMAIL2;
	private String USER_HP_NO;
	private String USER_TEL_NO;
	private String USER_RUN_MODE;
	private String USER_REL_CD;
	private String USER_DESC;
	private int GRP_ID;
	private String GRP_NM;
	private String GRP_DESC;
	private String GRP_RUN_MODE;
	private String GRP_REL_CD;
	private Timestamp PW_CHANGE_DT;
	private String selectedUser;
	private String newPw;
	private int selectedGroup;
	private List<Integer> selectedUsers; 
	private int authCount;
	private int startNum;
	private int endNum;
	
	public String getUSER_NO() {
		return USER_NO;
	}
	public void setUSER_NO(String uSER_NO) {
		USER_NO = uSER_NO;
	}
	public String getUSER_ID() {
		return USER_ID;
	}
	public void setUSER_ID(String uSER_ID) {
		USER_ID = uSER_ID;
	}
	public String getUSER_NM() {
		return USER_NM;
	}
	public void setUSER_NM(String uSER_NM) {
		USER_NM = uSER_NM;
	}
	public String getUSER_PW() {
		return USER_PW;
	}
	public void setUSER_PW(String uSER_PW) {
		USER_PW = uSER_PW;
	}
	public String getUSER_EMAIL1() {
		return USER_EMAIL1;
	}
	public void setUSER_EMAIL1(String uSER_EMAIL1) {
		USER_EMAIL1 = uSER_EMAIL1;
	}
	public String getUSER_EMAIL2() {
		return USER_EMAIL2;
	}
	public void setUSER_EMAIL2(String uSER_EMAIL2) {
		USER_EMAIL2 = uSER_EMAIL2;
	}
	public String getUSER_HP_NO() {
		return USER_HP_NO;
	}
	public void setUSER_HP_NO(String uSER_HP_NO) {
		USER_HP_NO = uSER_HP_NO;
	}
	public String getUSER_TEL_NO() {
		return USER_TEL_NO;
	}
	public void setUSER_TEL_NO(String uSER_TEL_NO) {
		USER_TEL_NO = uSER_TEL_NO;
	}
	public String getUSER_RUN_MODE() {
		return USER_RUN_MODE;
	}
	public void setUSER_RUN_MODE(String uSER_RUN_MODE) {
		USER_RUN_MODE = uSER_RUN_MODE;
	}
	public String getUSER_REL_CD() {
		return USER_REL_CD;
	}
	public void setUSER_REL_CD(String uSER_REL_CD) {
		USER_REL_CD = uSER_REL_CD;
	}
	public String getUSER_DESC() {
		return USER_DESC;
	}
	public void setUSER_DESC(String uSER_DESC) {
		USER_DESC = uSER_DESC;
	}
	public int getGRP_ID() {
		return GRP_ID;
	}
	public void setGRP_ID(int gRP_ID) {
		GRP_ID = gRP_ID;
	}
	public String getGRP_NM() {
		return GRP_NM;
	}
	public void setGRP_NM(String gRP_NM) {
		GRP_NM = gRP_NM;
	}
	public String getGRP_DESC() {
		return GRP_DESC;
	}
	public void setGRP_DESC(String gRP_DESC) {
		GRP_DESC = gRP_DESC;
	}
	public String getGRP_RUN_MODE() {
		return GRP_RUN_MODE;
	}
	public void setGRP_RUN_MODE(String gRP_RUN_MODE) {
		GRP_RUN_MODE = gRP_RUN_MODE;
	}
	public String getGRP_REL_CD() {
		return GRP_REL_CD;
	}
	public void setGRP_REL_CD(String gRP_REL_CD) {
		GRP_REL_CD = gRP_REL_CD;
	}
	public Timestamp getPW_CHANGE_DT() {
		return PW_CHANGE_DT;
	}
	public void setPW_CHANGE_DT(Timestamp currentTime) {
		PW_CHANGE_DT = currentTime;
	}
	public String getSelectedUser() {
		return selectedUser;
	}
	public void setSelectedUser(String selectedUser) {
		this.selectedUser = selectedUser;
	}
	public String getNewPw() {
		return newPw;
	}
	public void setNewPw(String newPw) {
		this.newPw = newPw;
	}
	public int getSelectedGroup() {
		return selectedGroup;
	}
	public void setSelectedGroup(int selectedGroup) {
		this.selectedGroup = selectedGroup;
	}
	public List<Integer> getSelectedUsers() {
		return selectedUsers;
	}
	public void setSelectedUsers(List<Integer> selectedUsers) {
		this.selectedUsers = selectedUsers;
	}
	public int getAuthCount() {
		return authCount;
	}
	public void setAuthCount(int authCount) {
		this.authCount = authCount;
	}
	
	public int getStartNum() {
		return startNum;
	}
	public void setStartNum(int startNum) {
		this.startNum = startNum;
	}
	public int getEndNum() {
		return endNum;
	}
	public void setEndNum(int endNum) {
		this.endNum = endNum;
	}
}
