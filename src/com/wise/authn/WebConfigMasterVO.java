package com.wise.authn;

public class WebConfigMasterVO {
	private String DASHBOARD_LAYOUT;
	private String LOGIN_IMAGE;
	private String LOGO;
	private String MENU_CONFIG;
	private String FONT_CONFIG;
	private String SPREAD_JS_LICENSE;
	private String PIVOT_ALIGN_CENTER;
	private String GRID_AUTO_ALIGN;
	private int REPORT_LOG_CLEAN_HOUR;
	private int EXCEL_DOWNLOAD_SERVER_COUNT;
	/* DOGFOOT syjin LAYOUT_CONFIG 추가  20200814 */
	private String LAYOUT_CONFIG;
	/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
	private String GRID_DATA_PAGING;
	/* DOGFOOT syjin KAKAO_MAP_API_KEY 추가  20200819 */
	private String KAKAO_MAP_API_KEY;
	/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
	private String DOWNLOAD_FILTER_YN;
	private String PIVOT_DRILL_UPDOWN;
	/* DOGFOOT ktkang 보고서 바로 조회 기능 옵션 추가  20201015 */
	private String REPORT_DIRECT_VIEW;
	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
	private String OLD_SCHEDULE_YN;
	public WebConfigMasterVO() {};
	
	public WebConfigMasterVO(String dASHBOARD_LAYOUT, String lOGIN_IMAGE, String lOGO, String mENU_CONFIG, String fONT_CONFIG, String sPREAD_JS_LICENSE, String rEPORT_LOG_CLEAN_HOUR, String eXCEL_DOWNLOAD_SERVER_COUNT, String pIVOT_ALIGN_CENTER, String gRID_AUTO_ALIGN, String lAYOUT_CONFIG, String gRID_DATA_PAGING, String kAKAO_MAP_API_KEY, String dOWNLOAD_FILTER_YN, String pIVOT_DRILL_UPDOWN, String rEPORT_DIRECT_VIEW, String oLD_SCHEDULE_YN) {
		DASHBOARD_LAYOUT = dASHBOARD_LAYOUT;
		LOGIN_IMAGE = lOGIN_IMAGE;
		LOGO = lOGO;
		MENU_CONFIG = mENU_CONFIG;
		FONT_CONFIG = fONT_CONFIG;
		PIVOT_ALIGN_CENTER = pIVOT_ALIGN_CENTER;
		GRID_AUTO_ALIGN = gRID_AUTO_ALIGN;
		SPREAD_JS_LICENSE = sPREAD_JS_LICENSE;
		REPORT_LOG_CLEAN_HOUR = Integer.parseInt(rEPORT_LOG_CLEAN_HOUR);
		EXCEL_DOWNLOAD_SERVER_COUNT = Integer.parseInt(eXCEL_DOWNLOAD_SERVER_COUNT);
		/* DOGFOOT syjin LAYOUT_CONFIG 추가  20200814 */
		LAYOUT_CONFIG = lAYOUT_CONFIG;
		GRID_DATA_PAGING = gRID_DATA_PAGING;
		/* DOGFOOT syjin KAKAO_MAP_API_KEY 추가  20200819 */
		KAKAO_MAP_API_KEY = kAKAO_MAP_API_KEY;
		DOWNLOAD_FILTER_YN = dOWNLOAD_FILTER_YN;
		PIVOT_DRILL_UPDOWN = pIVOT_DRILL_UPDOWN;
		REPORT_DIRECT_VIEW = rEPORT_DIRECT_VIEW;
		OLD_SCHEDULE_YN = oLD_SCHEDULE_YN;
	}

	public String getDASHBOARD_LAYOUT() {
		return DASHBOARD_LAYOUT;
	}

	public void setDASHBOARD_LAYOUT(String dASHBOARD_LAYOUT) {
		DASHBOARD_LAYOUT = dASHBOARD_LAYOUT;
	}

	public String getLOGIN_IMAGE() {
		return LOGIN_IMAGE;
	}

	public void setLOGIN_IMAGE(String lOGIN_IMAGE) {
		LOGIN_IMAGE = lOGIN_IMAGE;
	}

	public String getLOGO() {
		return LOGO;
	}

	public void setLOGO(String lOGO) {
		LOGO = lOGO;
	}

	public String getMENU_CONFIG() {
		return MENU_CONFIG;
	}

	public void setMENU_CONFIG(String mENU_CONFIG) {
		MENU_CONFIG = mENU_CONFIG;
	}

	public String getFONT_CONFIG() {
		return FONT_CONFIG;
	}

	public void setFONT_CONFIG(String fONT_CONFIG) {
		FONT_CONFIG = fONT_CONFIG;
	}

	public String getSPREAD_JS_LICENSE() {
		return SPREAD_JS_LICENSE;
	}

	public void setSPREAD_JS_LICENSE(String sPREAD_JS_LICENSE) {
		SPREAD_JS_LICENSE = sPREAD_JS_LICENSE;
	}
	
	public int getREPORT_LOG_CLEAN_HOUR() {
		return REPORT_LOG_CLEAN_HOUR;
	}

	public void setREPORT_LOG_CLEAN_HOUR(int rEPORT_LOG_CLEAN_HOUR) {
		REPORT_LOG_CLEAN_HOUR = rEPORT_LOG_CLEAN_HOUR;
	}

	public int getEXCEL_DOWNLOAD_SERVER_COUNT() {
		return EXCEL_DOWNLOAD_SERVER_COUNT;
	}

	public void setEXCEL_DOWNLOAD_SERVER_COUNT(int eXCEL_DOWNLOAD_SERVER_COUNT) {
		EXCEL_DOWNLOAD_SERVER_COUNT = eXCEL_DOWNLOAD_SERVER_COUNT;
	}	
	
	public String getPIVOT_ALIGN_CENTER() {
		return PIVOT_ALIGN_CENTER;
	}

	public void setPIVOT_ALIGN_CENTER(String pIVOT_ALIGN_CENTER) {
		PIVOT_ALIGN_CENTER = pIVOT_ALIGN_CENTER;
	}

	public String getGRID_AUTO_ALIGN() {
		return GRID_AUTO_ALIGN;
	}

	public void setGRID_AUTO_ALIGN(String gRID_AUTO_ALIGN) {
		GRID_AUTO_ALIGN = gRID_AUTO_ALIGN;
	}
	
	/* DOGFOOT syjin LAYOUT_CONFIG 추가  20200814 */
	public String getLAYOUT_CONFIG() {
		return LAYOUT_CONFIG;
	}

	public void setLAYOUT_CONFIG(String lAYOUT_CONFIG) {
		LAYOUT_CONFIG = lAYOUT_CONFIG;
	}
	
	/* DOGFOOT syjin KAKAO_MAP_API_KEY 추가  20200819 */
	public String getKAKAO_MAP_API_KEY() {
		return KAKAO_MAP_API_KEY;
	}

	public void setKAKAO_MAP_API_KEY(String kAKAO_MAP_API_KEY) {
		KAKAO_MAP_API_KEY = kAKAO_MAP_API_KEY;
	}	
	
	/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
	public String getGRID_DATA_PAGING() {
		return GRID_DATA_PAGING;
	}

	public void setGRID_DATA_PAGING(String gRID_DATA_PAGING) {
		GRID_DATA_PAGING = gRID_DATA_PAGING;
	}	
	
	/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
	public String getDOWNLOAD_FILTER_YN() {
		return DOWNLOAD_FILTER_YN;
	}

	public void setDOWNLOAD_FILTER_YN(String dOWNLOAD_FILTER_YN) {
		DOWNLOAD_FILTER_YN = dOWNLOAD_FILTER_YN;
	}
	
	public String getPIVOT_DRILL_UPDOWN() {
		return PIVOT_DRILL_UPDOWN;
	}

	public void setPIVOT_DRILL_UPDOWN(String pIVOT_DRILL_UPDOWN) {
		PIVOT_DRILL_UPDOWN = pIVOT_DRILL_UPDOWN;
	}
	
	/* DOGFOOT ktkang 보고서 바로 조회 기능 옵션 추가  20201015 */
	public String getREPORT_DIRECT_VIEW() {
		return REPORT_DIRECT_VIEW;
	}

	public void setREPORT_DIRECT_VIEW(String rEPORT_DIRECT_VIEW) {
		REPORT_DIRECT_VIEW = rEPORT_DIRECT_VIEW;
	}
	
	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
	public String getOLD_SCHEDULE_YN() {
		return OLD_SCHEDULE_YN;
	}

	public void setOLD_SCHEDULE_YN(String oLD_SCHEDULE_YN) {
		OLD_SCHEDULE_YN = oLD_SCHEDULE_YN;
	}
}
