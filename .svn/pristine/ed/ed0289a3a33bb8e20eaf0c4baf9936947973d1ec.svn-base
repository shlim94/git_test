package com.wise.ds.repository;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.util.encoders.Base64;

//import com.wise.authn.DataAuthentication;
import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;

import org.json.JSONObject;

public class UserAuthDataSetVO {
	private int userNo;
	private int fldId;
    private int userGroupId; // user group id
    private String dataAuthnXmlBase64;
    private String dataAuthnXml;
    private JSONObject dataAuthnJson;
    
    public int getUserNo() {
        return userNo;
    }

    public void setUserNo(int userNo) {
        this.userNo = userNo;
    }

    public int getFldId() {
		return fldId;
	}

	public void setFldId(int fldId) {
		this.fldId = fldId;
	}

	public int getUserGroupId() {
        return userGroupId;
    }

    public void setUserGroupId(int userGroupId) {
        this.userGroupId = userGroupId;
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
    
//    public List<DataAuthentication> getAuthnMember(int dsViewId) {
//        List<DataAuthentication> members = new ArrayList<DataAuthentication>();
//        
//        JSONObject NewDataSet = this.dataAuthnJson.getJSONObject("NewDataSet");
//        Object Auth_Mem = NewDataSet.get("Auth_Mem");
//        
//        if (Auth_Mem != null) {
//            JSONArray temp;
//            if (Auth_Mem instanceof org.json.JSONObject) {
//                temp = new JSONArray();
//                temp.add(Auth_Mem);
//            }
//            else {
//                temp = (JSONArray) Auth_Mem;
//            }
//            
//            for (Object member : temp.toArray()) {
//                DataAuthentication da = new DataAuthentication((JSONObject) member);
//                if (dsViewId == da.getDsViewId()) {
//                    members.add(da);
//                }
//            }
//        }
//        
//        return members;
//    }
}
