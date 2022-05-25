package com.wise.common.file.download;

public class Colors {

	private String bgColor = "D1E5FE";
	private String lineColor = "A4BED4";
	private String headerTextColor = "000000";
	private String scaleOneColor = "FFFFFF";
	private String scaleTwoColor = "E3EFFF";
	private String gridTextColor = "000000";
	private String watermarkTextColor = "8b8b8b";

	
	public void setColorProfile(String profile) {
		if ((profile.equalsIgnoreCase("color"))||profile.equalsIgnoreCase("full_color")) {
			bgColor = "D1E5FE";
			lineColor = "A4BED4";
			headerTextColor = "000000";
			scaleOneColor = "FFFFFF";
			scaleTwoColor = "E3EFFF";
			gridTextColor = "000000";
			watermarkTextColor = "8b8b8b";
		} else {
			if (profile.equalsIgnoreCase("gray")) {
				bgColor = "E3E3E3";
				lineColor = "B8B8B8";
				headerTextColor = "000000";
				scaleOneColor = "FFFFFF";
				scaleTwoColor = "EDEDED";
				gridTextColor = "000000";
				watermarkTextColor = "8b8b8b";
			} else {
				bgColor = "FFFFFF";
				lineColor = "000000";
				headerTextColor = "000000";
				scaleOneColor = "FFFFFF";
				scaleTwoColor = "FFFFFF";
				gridTextColor = "000000";
				watermarkTextColor = "000000";
			}
		}
	}
	
	public String getBgColor() {
		return bgColor;
	}
	
	public String getLineColor() {
		return lineColor;
	}
	
	public String getHeaderTextColor() {
		return headerTextColor;
	}
	
	public String getScaleOneColor() {
		return scaleOneColor;
	}
	
	public String getScaleTwoColor() {
		return scaleTwoColor;
	}
	
	public String getGridTextColor() {
		return gridTextColor;
	}
	
	public String getWatermarkTextColor() {
		return watermarkTextColor;
	}
	
}
