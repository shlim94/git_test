package com.wise.ds.repository;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;

import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;

public class GrpAuthDataSetVO {
	private int USER_NO;
	private int GRP_ID;
	private int FLD_ID;
	private String dataAuthnXmlBase64;
    private String dataAuthnXml;
    private JSONObject dataAuthnJson;
	
	public int getUSER_NO() {
		return USER_NO;
	}
	public void setUSER_NO(int uSER_NO) {
		USER_NO = uSER_NO;
	}
	public int getGRP_ID() {
		return GRP_ID;
	}
	public void setGRP_ID(int gRP_ID) {
		GRP_ID = gRP_ID;
	}
	public int getFLD_ID() {
		return FLD_ID;
	}
	public void setFLD_ID(int fLD_ID) {
		FLD_ID = fLD_ID;
	}
	
	public String getDataAuthnXmlBase64() {
        return dataAuthnXmlBase64;
    }

    public void setDataAuthnXmlBase64(String dataAuthnXmlBase64) throws UnsupportedEncodingException {
        this.dataAuthnXmlBase64 = CoreUtils.ifNull(dataAuthnXmlBase64);

        if ("".equals(this.dataAuthnXmlBase64)) {
            this.dataAuthnXml = "";
            this.dataAuthnJson = new JSONObject();
        } else {
            String encoding = Configurator.getInstance().getConfig("encoding");
            this.dataAuthnXml = new String(Base64.decode(this.dataAuthnXmlBase64.getBytes()), encoding);
            
            if ("".equals(CoreUtils.ifNull(this.dataAuthnXml))) {
                this.dataAuthnJson = new JSONObject();
            } else {
                org.json.JSONObject CHART_XML = org.json.XML.toJSONObject(this.dataAuthnXml);
                
                this.dataAuthnJson = CHART_XML;
            }
        }
    }

    public String getDataAuthnXml() {
        return dataAuthnXml;
    }

    public JSONObject getDataAuthnJson() {
        return dataAuthnJson;
    }
}
