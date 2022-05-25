package com.wise.ds.repository;

import java.io.UnsupportedEncodingException;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.json.XML;

import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;

import net.sf.json.JSONObject;

public class ReportSubLinkVO {
	private String arg_id;
	private String target_nm;
	private String target_id;
	private String target_item;
	private String link_type;
	private int link_report_ordinal;
	private String link_xml;
	private String link_xml2;
	private String link_xml_base64;
	private String link_xml_data;
	private String target_type;
	private JSONObject linkJson;
	private JSONObject linkJson2;
	private int seq;

	
	public String getArg_id() {
		return arg_id;
	}
	
	public void setArg_id(String arg_id) {
		this.arg_id = arg_id;
	}
	
	public String getTarget_nm() {
		return target_nm;
	}
	
	public void setTarget_nm(String target_nm) {
		this.target_nm = target_nm;
	}
	
	public String getTarget_id() {
		return target_id;
	}
	
	public void setTarget_id(String target_id) {
		this.target_id = target_id;
	}
	
	public String getTarget_item() {
		return target_item;
	}
	
	public void setTarget_item(String target_item) {
		this.target_item = target_item;
	}
	
	public String getLink_type() {
		return link_type;
	}
	
	public void setLink_type(String link_type) {
		this.link_type = link_type;
	}
	
	public String getLink_xml_data() {
		return link_xml_data;
	}
	
	public void setLink_xml_data(String link_xml_data) throws UnsupportedEncodingException  {
		this.link_xml_data = CoreUtils.ifNull(link_xml_data);
		if ("".equals(this.link_xml_data)) {
			this.link_xml2 = "";
			this.linkJson2 = new JSONObject();
		}
		else {
			String encoding = Configurator.getInstance().getConfig("encoding");
			this.link_xml2 = new String(Base64.decode(this.link_xml_data.getBytes()), encoding);

			if ("".equals(CoreUtils.ifNull(this.link_xml2))) {
				this.linkJson2 = new JSONObject();
			} else {
				org.json.JSONObject CHART_XML = XML.toJSONObject(this.link_xml2);
				this.linkJson2 = JSONObject.fromObject(CHART_XML.toString());
			}
		}
	}
	
	public String getLink_xml() {
		return link_xml;
	}
	
	public void setLink_xml(String link_xml) {
		this.link_xml = link_xml;
	}
	
	public String getLink_xml2() {
		return link_xml2;
	}
	
	public void setLink_xml2(String link_xml2) {
		this.link_xml2 = link_xml2;
	}
	
	public String getLink_xml_base64() {
		return link_xml_base64;
	}
	
	public void setLink_xml_base64(String link_xml_base64) throws UnsupportedEncodingException {
		this.link_xml_base64 = CoreUtils.ifNull(link_xml_base64);
		if ("".equals(this.link_xml_base64)) {
			this.link_xml = "";
			this.linkJson = new JSONObject();
		}
		else {
			String encoding = Configurator.getInstance().getConfig("encoding");
			this.link_xml = new String(Base64.decode(this.link_xml_base64.getBytes()), encoding);

			if ("".equals(CoreUtils.ifNull(this.link_xml))) {
				this.linkJson = new JSONObject();
			} else {
				org.json.JSONObject CHART_XML = XML.toJSONObject(this.link_xml);
				this.linkJson = JSONObject.fromObject(CHART_XML.toString());
			}
		}
	}
	
	public JSONObject getLinkJson() {
		return linkJson;
	}
	public void setLinkJson(JSONObject linkJson) {
		this.linkJson = linkJson;
	}
	
	public JSONObject getLinkJson2() {
		return linkJson2;
	}
	public void setLinkJson2(JSONObject linkJson2) {
		this.linkJson2 = linkJson2;
	}
	
	public String getTarget_type() {
		return target_type;
	}
	public void setTarget_type(String target_type) {
		this.target_type = target_type;
	}
	
	public int getLink_report_ordinal() {
		return link_report_ordinal;
	}
	public void setLink_report_ordinal(int link_report_ordinal) {
		this.link_report_ordinal = link_report_ordinal;
	}
	
	public int getSEQ() {
		return seq;
	}
	public void setSEQ(int sEQ) {
		this.seq = sEQ;
	}
	
	@Override
	public String toString() {
		return "ReportSubLinkVO [arg_id=" + arg_id + ", target_id=" + target_id + ", target_item=" + target_item
				+ ", link_type=" + link_type + ", link_xml=" + link_xml + ", link_xml_base64=" + link_xml_base64
				+ ", link_xml_data=" + link_xml_data + "]";
	}
	
	
}
